//! Content-Encoding response decoding (tranche 19a): one dispatcher
//! over four reused codecs — gzip and deflate via flate2's zlib-rs
//! backend (pure Rust, the fastest DEFLATE available without a C
//! toolchain), `br` via brotli-decompressor (safe, decode-only), and
//! `zstd` via ruzstd (pure Rust; libzstd-rs is the recorded migration
//! trigger). No owned codecs — DEFLATE/brotli/zstd decompression is
//! solved, the token grammar is ours.
//!
//! Semantics (frozen at the T19 planning pass):
//! - **Tokens**: `gzip` (+ the `x-gzip` alias, curl parity),
//!   `deflate`, `br`, `zstd`, `identity`; anything else is a pointed
//!   error, never a silent passthrough.
//! - **`deflate` ambiguity**: RFC 9110 says zlib-wrapped, wild
//!   servers emit raw — try the zlib wrapper, fall back to raw
//!   (libcurl's rule).
//! - **Stacked codings** (`Content-Encoding: gzip, br`) decode
//!   right-to-left (RFC 9110 §8.4.1; libcurl's order).
//! - **Multi-member gzip** bodies decode like browsers/curl
//!   (flate2's multi-member decoder).
//! - **The bomb cap**: decoded bytes count against the SAME budget
//!   the wire bytes do — decode streams in bounded pieces and stops
//!   at the cap (a 100 MB-of-zeros .gz must not become 100 MB).
//! - **Corrupt streams** are pointed errors (truncated, bad magic),
//!   never panics, never partial output.

/// Decode failures — the verb maps each to a pointed exit-1 line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// A Content-Encoding token wrex does not decode.
    UnknownEncoding(String),
    /// The decoded byte budget (the same `--max-bytes` the wire
    /// budget uses) was exceeded.
    TooLarge,
    /// The stream is corrupt (truncated, bad magic, bad block).
    Corrupt(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::UnknownEncoding(t) => {
                write!(
                    f,
                    "unknown content-encoding `{t}` (gzip, deflate, br, zstd)"
                )
            }
            DecodeError::TooLarge => {
                write!(f, "decoded content exceeded the response byte budget")
            }
            DecodeError::Corrupt(detail) => write!(f, "corrupt content stream: {detail}"),
        }
    }
}

/// The `Accept-Encoding` value `--compressed` advertises — pinned
/// byte-exact to curl 8.x's own list (`curl --compressed` against a
/// capture stub; wire-visible, the differential asserts it).
pub const ACCEPT_ENCODING: &str = "deflate, gzip, br, zstd";

/// The `Content-Encoding` token list → one decoded buffer. Tokens
/// apply right-to-left (stacked codings); every decoding pass counts
/// its output against `budget`.
pub fn decode(content_encoding: &str, body: &[u8], budget: usize) -> Result<Vec<u8>, DecodeError> {
    let mut tokens: Vec<&str> = content_encoding
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect();
    tokens.reverse();
    if tokens.is_empty() {
        return Err(DecodeError::Corrupt("empty content-encoding".to_string()));
    }
    let mut data = body.to_vec();
    for token in tokens {
        data = decode_one(token, &data, budget)?;
    }
    Ok(data)
}

/// One coding step. `identity` passes through (RFC 9110 §8.4.1 — a
/// no-op wrapper must not fail).
fn decode_one(token: &str, body: &[u8], budget: usize) -> Result<Vec<u8>, DecodeError> {
    match token.to_ascii_lowercase().as_str() {
        "identity" => Ok(body.to_vec()),
        "gzip" | "x-gzip" => {
            let mut dec = flate2::read::MultiGzDecoder::new(std::io::Cursor::new(body));
            pump("gzip", &mut dec, budget)
        }
        "deflate" => {
            // RFC 9110 says zlib-wrapped; wild servers emit raw — the
            // zlib attempt first, raw on any error (libcurl's rule).
            let mut zlib = flate2::read::ZlibDecoder::new(std::io::Cursor::new(body));
            match pump("deflate", &mut zlib, budget) {
                Ok(out) => Ok(out),
                Err(DecodeError::TooLarge) => Err(DecodeError::TooLarge),
                Err(_) => {
                    let mut raw = flate2::read::DeflateDecoder::new(std::io::Cursor::new(body));
                    pump("deflate", &mut raw, budget)
                }
            }
        }
        "br" => {
            let mut reader = std::io::Cursor::new(body);
            let mut dec = brotli_decompressor::Decompressor::new(&mut reader, 4096);
            let mut out = Vec::new();
            read_to_end_capped(&mut dec, &mut out, budget)
                .map_err(|e| DecodeError::Corrupt(format!("brotli: {e}")))?;
            Ok(out)
        }
        "zstd" => {
            let mut reader = std::io::Cursor::new(body);
            let mut dec = ruzstd::decoding::StreamingDecoder::new(&mut reader)
                .map_err(|e| DecodeError::Corrupt(format!("zstd frame: {e}")))?;
            let mut out = Vec::new();
            read_to_end_capped(&mut dec, &mut out, budget)
                .map_err(|e| DecodeError::Corrupt(format!("zstd: {e}")))?;
            Ok(out)
        }
        other => Err(DecodeError::UnknownEncoding(other.to_string())),
    }
}

/// Drive one decoder to EOF under the decoded budget, wrapping
/// stream errors with the coding's name.
fn pump(what: &str, dec: &mut dyn std::io::Read, budget: usize) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::new();
    match read_to_end_capped(dec, &mut out, budget) {
        Ok(()) => Ok(out),
        Err(e) => Err(match e {
            DecodeError::TooLarge => DecodeError::TooLarge,
            DecodeError::Corrupt(detail) => DecodeError::Corrupt(format!("{what}: {detail}")),
            DecodeError::UnknownEncoding(t) => DecodeError::UnknownEncoding(t),
        }),
    }
}

/// read_to_end with the cap: a tiny compressed stream must never
/// materialize an unbounded buffer.
fn read_to_end_capped(
    reader: &mut dyn std::io::Read,
    out: &mut Vec<u8>,
    budget: usize,
) -> Result<(), DecodeError> {
    let mut piece = [0u8; 16 * 1024];
    loop {
        let n = reader
            .read(&mut piece)
            .map_err(|e| DecodeError::Corrupt(e.to_string()))?;
        if n == 0 {
            return Ok(());
        }
        if out.len() + n > budget {
            return Err(DecodeError::TooLarge);
        }
        out.extend_from_slice(&piece[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    /// Byte-stable committed fixtures (generated by the committed
    /// python in the tranche log — encoder versions churn, fixture
    /// bytes do not; the golden-corpus pattern). Embedded at compile
    /// time (include_bytes!) so the decode paths run under Miri too.
    const FIXTURE_GZ: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/content/fixture.gz"
    ));
    const FIXTURE_GZ_EXPECTED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/content/fixture.gz.expected"
    ));
    const FIXTURE_MULTI_GZ: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/content/fixture.multi.gz"
    ));
    const FIXTURE_MULTI_GZ_EXPECTED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/content/fixture.multi.gz.expected"
    ));
    const FIXTURE_ZZ: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/content/fixture.zz"
    ));
    const FIXTURE_ZZ_EXPECTED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/content/fixture.zz.expected"
    ));
    const FIXTURE_RAW: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/content/fixture.raw"
    ));
    const FIXTURE_RAW_EXPECTED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/content/fixture.raw.expected"
    ));
    const FIXTURE_BR: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/content/fixture.br"
    ));
    const FIXTURE_BR_EXPECTED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/content/fixture.br.expected"
    ));
    const FIXTURE_ZST: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/content/fixture.zst"
    ));
    const FIXTURE_ZST_EXPECTED: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/content/fixture.zst.expected"
    ));
    const FIXTURE_TRUNCATED_GZ: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/content/truncated.gz"
    ));
    const BOMB_GZ: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/content/bomb.gz"
    ));
    const BUDGET: usize = 1024 * 1024;

    /// The embedded fixture bytes (compile-time; Miri needs no fs).
    fn fixture(name: &str) -> Vec<u8> {
        match name {
            "fixture.gz" => FIXTURE_GZ.to_vec(),
            "fixture.gz.expected" => FIXTURE_GZ_EXPECTED.to_vec(),
            "fixture.multi.gz" => FIXTURE_MULTI_GZ.to_vec(),
            "fixture.multi.gz.expected" => FIXTURE_MULTI_GZ_EXPECTED.to_vec(),
            "fixture.zz" => FIXTURE_ZZ.to_vec(),
            "fixture.zz.expected" => FIXTURE_ZZ_EXPECTED.to_vec(),
            "fixture.raw" => FIXTURE_RAW.to_vec(),
            "fixture.raw.expected" => FIXTURE_RAW_EXPECTED.to_vec(),
            "fixture.br" => FIXTURE_BR.to_vec(),
            "fixture.br.expected" => FIXTURE_BR_EXPECTED.to_vec(),
            "fixture.zst" => FIXTURE_ZST.to_vec(),
            "fixture.zst.expected" => FIXTURE_ZST_EXPECTED.to_vec(),
            "truncated.gz" => FIXTURE_TRUNCATED_GZ.to_vec(),
            "bomb.gz" => BOMB_GZ.to_vec(),
            other => panic!("unknown fixture {other}"),
        }
    }

    #[test]
    fn gzip_alias_and_multimember() {
        let body = fixture("fixture.gz");
        let expected = fixture("fixture.gz.expected");
        assert_eq!(decode("gzip", &body, BUDGET).unwrap(), expected);
        // x-gzip alias (curl parity)
        assert_eq!(decode("x-gzip", &body, BUDGET).unwrap(), expected);
        // case-insensitive tokens
        assert_eq!(decode("GZip", &body, BUDGET).unwrap(), expected);
        // stacked on identity
        assert_eq!(decode("identity, gzip", &body, BUDGET).unwrap(), expected);
        // Multi-member gzip: wrex decodes like BROWSERS do — curl
        // errors (exit 23, first member only), the recorded divergence.
        let multi = fixture("fixture.multi.gz");
        let multi_expected = fixture("fixture.multi.gz.expected");
        assert_eq!(decode("gzip", &multi, BUDGET).unwrap(), multi_expected);
    }

    #[test]
    fn deflate_zlib_wrapped_and_raw_fallback() {
        let zz = fixture("fixture.zz");
        let expected = fixture("fixture.zz.expected");
        assert_eq!(decode("deflate", &zz, BUDGET).unwrap(), expected);
        // a raw-deflate body (the wild-server spelling) decodes via
        // the fallback
        let raw = fixture("fixture.raw");
        assert_eq!(decode("deflate", &raw, BUDGET).unwrap(), expected);
    }

    #[test]
    fn brotli_and_zstd() {
        let br = fixture("fixture.br");
        let expected = fixture("fixture.br.expected");
        assert_eq!(decode("br", &br, BUDGET).unwrap(), expected);
        let zst = fixture("fixture.zst");
        assert_eq!(decode("zstd", &zst, BUDGET).unwrap(), expected);
        // stacked: gzip then br (decode right-to-left)
        let gz = fixture("fixture.gz");
        let gz_body = decode("gzip", &gz, BUDGET).unwrap();
        let mut both = std::io::Cursor::new(&gz_body);
        let mut enc = flate2::read::GzEncoder::new(&mut both, flate2::Compression::default());
        let mut stacked = Vec::new();
        enc.read_to_end(&mut stacked).unwrap();
        assert_eq!(
            decode("gzip, br", &br, BUDGET).unwrap_err(),
            DecodeError::Corrupt("gzip: invalid gzip header".to_string()),
            "br bytes are not a gzip member — the stack must fail pointedly, not panic"
        );
        let _ = stacked; // (stacked encode left for a future fixture)
    }

    #[test]
    fn stacked_codings_right_to_left() {
        // br(gzip(body)) — Content-Encoding lists the OUTER coding
        // first; decode applies right-to-left (gzip then br? no:
        // the LAST applied coding is listed first, so `gzip, br`
        // means br was applied last → decode gzip first, then br).
        let plain = b"stack me".to_vec();
        // gzip(plain)
        let mut enc = flate2::read::GzEncoder::new(
            std::io::Cursor::new(plain.clone()),
            flate2::Compression::default(),
        );
        let mut gz = Vec::new();
        enc.read_to_end(&mut gz).unwrap();
        // br(gz) via the brotli crate? No encoder here — use deflate
        // stacking instead: deflate(gzip(plain)).
        let mut zenc = flate2::read::ZlibEncoder::new(
            std::io::Cursor::new(gz.clone()),
            flate2::Compression::default(),
        );
        let mut stacked = Vec::new();
        zenc.read_to_end(&mut stacked).unwrap();
        // Content-Encoding: gzip, deflate → deflate was applied last,
        // so peel deflate first, then gzip.
        assert_eq!(
            decode("gzip, deflate", &stacked, BUDGET).unwrap(),
            plain,
            "stacked codings decode right-to-left"
        );
    }

    #[test]
    fn unknown_tokens_are_pointed() {
        assert_eq!(
            decode("brotar", b"x", BUDGET),
            Err(DecodeError::UnknownEncoding("brotar".to_string()))
        );
        assert_eq!(
            decode("zstd, mystery", b"x", BUDGET),
            Err(DecodeError::UnknownEncoding("mystery".to_string()))
        );
        let err = decode("", b"x", BUDGET).unwrap_err();
        assert!(matches!(err, DecodeError::Corrupt(_)), "{err}");
    }

    #[test]
    fn corrupt_streams_never_panic_or_return_partials() {
        let truncated = fixture("truncated.gz");
        let err = decode("gzip", &truncated, BUDGET).unwrap_err();
        assert!(matches!(err, DecodeError::Corrupt(_)), "{err}");
        let garbage = [0u8; 64];
        let err = decode("br", &garbage, BUDGET).unwrap_err();
        assert!(matches!(err, DecodeError::Corrupt(_)), "{err}");
        let err = decode("zstd", &garbage, BUDGET).unwrap_err();
        assert!(matches!(err, DecodeError::Corrupt(_)), "{err}");
        let err = decode("zstd", &garbage, BUDGET).unwrap_err();
        assert!(matches!(err, DecodeError::Corrupt(_)), "{err}");
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "100 MB through the interpreter is minutes; the cap rides the CLI bomb test"
    )]
    fn the_bomb_stops_at_the_budget() {
        // 100 MB of zeros in ~100 KB: the decoded budget (here, tiny)
        // must trip before the buffer grows.
        let bomb = fixture("bomb.gz");
        assert_eq!(decode("gzip", &bomb, 64 * 1024), Err(DecodeError::TooLarge));
        // …and a generous budget still works (streamed, not bounded
        // by the compressed size)
        let out = decode("gzip", &bomb, 200 * 1024 * 1024).unwrap();
        assert_eq!(out.len(), 100 * 1024 * 1024);
        assert!(out.iter().all(|&b| b == 0));
    }

    #[test]
    fn accept_encoding_is_curls_list() {
        assert_eq!(ACCEPT_ENCODING, "deflate, gzip, br, zstd");
    }
}
