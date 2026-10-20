//! Chunked-body framing (RFC 9112 §7.1): a standalone, pure chunk
//! header decoder — the Kani harness proves it panic-free for all
//! bounded inputs.

/// Maximum chunk-header line length (size + extensions); headers longer
/// than this are malformed rather than "need more".
const MAX_HEADER_LINE: usize = 70;

/// One parsed chunk header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChunkHeader {
    /// No complete header yet; the buffer is within its length cap.
    NeedMore,
    /// A data chunk: `size` octets follow; `len` is the header line's
    /// own wire length (including CRLF).
    Chunk { size: u64, len: usize },
    /// The last chunk (`0[;ext]`); `len` includes its CRLF. The trailer
    /// section follows.
    Last { len: usize },
    /// Malformed chunk header.
    Invalid,
}

/// Parse one chunk header from the front of `buf`.
///
/// Grammar: `1*HEXDIG [ ";" chunk-ext ] CRLF` (case-insensitive hex).
pub(crate) fn parse_chunk_header(buf: &[u8]) -> ChunkHeader {
    let Some(crlf) = find_crlf(buf) else {
        if buf.len() > MAX_HEADER_LINE {
            return ChunkHeader::Invalid;
        }
        return ChunkHeader::NeedMore;
    };
    let line = &buf[..crlf];
    // Strip chunk extensions.
    let size_part = match line.iter().position(|&b| b == b';') {
        Some(semi) => &line[..semi],
        None => line,
    };
    if size_part.is_empty() || size_part.len() > 16 {
        return ChunkHeader::Invalid;
    }
    let mut size: u64 = 0;
    for &b in size_part {
        let digit = match b {
            b'0'..=b'9' => u64::from(b - b'0'),
            b'a'..=b'f' => u64::from(b - b'a' + 10),
            b'A'..=b'F' => u64::from(b - b'A' + 10),
            _ => return ChunkHeader::Invalid,
        };
        let (shifted, overflow) = size.overflowing_mul(16);
        if overflow {
            return ChunkHeader::Invalid;
        }
        let (summed, overflow) = shifted.overflowing_add(digit);
        if overflow {
            return ChunkHeader::Invalid;
        }
        size = summed;
    }
    let len = crlf + 2;
    if size == 0 {
        ChunkHeader::Last { len }
    } else {
        ChunkHeader::Chunk { size, len }
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_sizes() {
        assert_eq!(
            parse_chunk_header(b"5\r\nhello"),
            ChunkHeader::Chunk { size: 5, len: 3 }
        );
        assert_eq!(
            parse_chunk_header(b"1A\r\n"),
            ChunkHeader::Chunk { size: 26, len: 4 }
        );
        assert_eq!(parse_chunk_header(b"0\r\n"), ChunkHeader::Last { len: 3 });
        assert_eq!(
            parse_chunk_header(b"0;ext=1\r\n"),
            ChunkHeader::Last { len: 9 }
        );
        assert_eq!(
            parse_chunk_header(b"f;name=v\r\nxx"),
            ChunkHeader::Chunk { size: 15, len: 10 }
        );
    }

    #[test]
    fn partial_and_invalid() {
        assert_eq!(parse_chunk_header(b"12"), ChunkHeader::NeedMore);
        assert_eq!(parse_chunk_header(b""), ChunkHeader::NeedMore);
        // overlong header line without CRLF → Invalid, not NeedMore
        assert_eq!(parse_chunk_header(&[b'1'; 80]), ChunkHeader::Invalid);
        assert_eq!(parse_chunk_header(b"xy\r\n"), ChunkHeader::Invalid);
        assert_eq!(parse_chunk_header(b"\r\n"), ChunkHeader::Invalid); // empty size
        // 17+ hex digits
        assert_eq!(
            parse_chunk_header(b"11111111111111111\r\n"),
            ChunkHeader::Invalid
        );
        // u64 overflow (16 digits, all F is fine; force via 16 F's is
        // exactly u64::MAX — valid)
        assert_eq!(
            parse_chunk_header(b"FFFFFFFFFFFFFFFF\r\n"),
            ChunkHeader::Chunk {
                size: u64::MAX,
                len: 18
            }
        );
    }
}

#[cfg(kani)]
mod verification {
    //! Kani proof: the chunk header decoder must never panic and must
    //! never claim more input than it consumed, for ALL 10-byte inputs.
    //! 10 bytes reach every branch this harness can see (CRLF at any
    //! position, hex sizes, extensions, NeedMore, empty-size and
    //! bad-digit rejection). The overlong-header rejection branch
    //! (no CRLF within 70 bytes) is unreachable at this scale and is
    //! covered by the unit test — it is a trivial length check.
    //! Symbolic bytes scale exponentially, so the bound stays at the
    //! proven-cheap scale: a 24-byte variant of this harness needed
    //! 20+GB of solver state.

    #[kani::proof]
    // Sequential loops, each ≤ 10 iterations in a 10-byte buffer:
    // the symbolic init loop (10), find_crlf (≤9), the hex fold (≤8).
    #[kani::unwind(12)]
    fn parse_chunk_header_panic_free() {
        const N: usize = 10;
        let mut buf = [0u8; N];
        for b in buf.iter_mut() {
            *b = kani::any();
        }
        let out = super::parse_chunk_header(&buf);
        if let super::ChunkHeader::Chunk { len, .. } | super::ChunkHeader::Last { len } = out {
            assert!(len <= N);
            assert!(len >= 2);
        }
        if let super::ChunkHeader::Chunk { size, .. } = out {
            // Data chunks are nonzero; the fold cannot overflow (16
            // hex digits max with checked arithmetic).
            assert!(size > 0);
        }
    }
}
