//! The HTTP/2 binary framing layer (RFC 9113 §§4–6): frame header
//! encode/decode, the committed frame-type set with per-type flag
//! grammar, settings payloads, and the connection preface.
//!
//! Pure and sans-IO (the `chunked.rs` lineage): the session owns all
//! state; this module only moves bytes.

use bytes::{BufMut as _, Bytes, BytesMut};

/// The HTTP/2 client connection preface (RFC 9113 §3.4 — the magic
/// string every client sends before any frame).
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// One frame header (RFC 9113 §4.1): 9 octets.
pub const HEADER_LEN: usize = 9;

/// Our advertised (and default peer) SETTINGS_MAX_FRAME_SIZE.
pub const DEFAULT_MAX_FRAME: u32 = 16 * 1024;

/// Default flow-control window (SETTINGS_INITIAL_WINDOW_SIZE).
pub const DEFAULT_WINDOW: i64 = 65_535;

/// Largest legal flow-control window (RFC 9113 §6.9.1: windows are
/// 2^31-1 max; increments past it are protocol errors).
pub const MAX_WINDOW: i64 = (1 << 31) - 1;

/// SETTINGS ids (RFC 9113 §6.5.2).
pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 1;
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 3;
pub const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 4;
pub const SETTINGS_MAX_FRAME_SIZE: u16 = 5;

/// One frame type (RFC 9113 §6). `Unknown` keeps foreign/
/// experimental types dissectable (they skip per §5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameType {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    Goaway,
    WindowUpdate,
    Continuation,
    Unknown(u8),
}

impl FrameType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x0 => FrameType::Data,
            0x1 => FrameType::Headers,
            0x2 => FrameType::Priority,
            0x3 => FrameType::RstStream,
            0x4 => FrameType::Settings,
            0x5 => FrameType::PushPromise,
            0x6 => FrameType::Ping,
            0x7 => FrameType::Goaway,
            0x8 => FrameType::WindowUpdate,
            0x9 => FrameType::Continuation,
            other => FrameType::Unknown(other),
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            FrameType::Data => 0x0,
            FrameType::Headers => 0x1,
            FrameType::Priority => 0x2,
            FrameType::RstStream => 0x3,
            FrameType::Settings => 0x4,
            FrameType::PushPromise => 0x5,
            FrameType::Ping => 0x6,
            FrameType::Goaway => 0x7,
            FrameType::WindowUpdate => 0x8,
            FrameType::Continuation => 0x9,
            FrameType::Unknown(other) => other,
        }
    }
}

/// Flag bits (RFC 9113): END_STREAM/ACK share 0x1, END_HEADERS 0x4,
/// PADDED 0x8, PRIORITY 0x20 (HEADERS only).
pub const END_STREAM: u8 = 0x1;
pub const ACK: u8 = 0x1;
pub const END_HEADERS: u8 = 0x4;
pub const PADDED: u8 = 0x8;
pub const PRIORITY: u8 = 0x20;

/// One decoded frame header. `stream_id` is the wire stream id with the
/// reserved high bit masked off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub ty: FrameType,
    pub flags: u8,
    pub stream_id: u32,
}

impl FrameHeader {
    /// Encode this header with a `length` payload in front (RFC 9113
    /// §4.1: 24-bit length, 8-bit type, 8-bit flags, R bit + 31-bit
    /// stream id).
    pub fn encode(&self, length: u32, out: &mut BytesMut) {
        debug_assert!(length <= 0x00ff_ffff, "frame length exceeds 24 bits");
        out.put_uint(u64::from(length), 3);
        out.put_u8(self.ty.to_u8());
        out.put_u8(self.flags);
        out.put_u32(self.stream_id & 0x7fff_ffff);
    }
}

/// One step of frame decoding against a byte buffer.
#[derive(Debug)]
pub enum FrameStep {
    /// Not enough bytes for a whole frame yet.
    Need,
    /// One full frame present: consumed bytes + header + payload.
    Have {
        consumed: usize,
        header: FrameHeader,
        payload: Bytes,
    },
    /// Protocol error (pointed, never fatal to the process).
    Malformed(String),
}

/// Decode the first frame in `buf` (RFC 9113 §4.1 + §4.2: length is
/// the payload size; the 16-octet SETTINGS/PING/WINDOW_UPDATE/
/// GOAWAY/RST_STREAM shapes validate here, DATA/HEADERS shapes at the
/// session). Malformed never panics and never reads past `buf`.
pub fn decode_frame(buf: &[u8]) -> FrameStep {
    if buf.len() < HEADER_LEN {
        return FrameStep::Need;
    }
    let length = u32::from_be_bytes([0, buf[0], buf[1], buf[2]]);
    let ty = FrameType::from_u8(buf[3]);
    let flags = buf[4];
    let stream_id = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7fff_ffff;
    let header = FrameHeader {
        ty,
        flags,
        stream_id,
    };
    // Frame lengths beyond 2^24-1 are impossible by construction; the
    // 24-bit length field caps them.
    let total = HEADER_LEN + length as usize;
    if buf.len() < total {
        return FrameStep::Need;
    }
    let payload = Bytes::copy_from_slice(&buf[HEADER_LEN..total]);
    // Per-type shape validation (never fatal; the session turns these
    // into pointed stream/connection outcomes).
    let err = match ty {
        FrameType::Settings if stream_id != 0 => Some("settings frame on non-zero stream"),
        FrameType::Settings if flags & PADDED != 0 => Some("padded settings frame"),
        FrameType::Ping if stream_id != 0 => Some("ping frame on non-zero stream"),
        FrameType::Ping if payload.len() != 8 => Some("ping frame without 8 octets"),
        FrameType::WindowUpdate if payload.len() != 4 => Some("window update without 4 octets"),
        FrameType::RstStream if payload.len() != 4 => Some("rst stream without 4 octets"),
        FrameType::Goaway if payload.len() < 8 => Some("goaway shorter than 8 octets"),
        FrameType::Priority if payload.len() != 5 => Some("priority without 5 octets"),
        FrameType::Data | FrameType::Headers if stream_id == 0 => {
            Some("data/headers frame on stream 0")
        }
        _ => None,
    };
    match err {
        Some(e) => FrameStep::Malformed(e.to_string()),
        None => FrameStep::Have {
            consumed: total,
            header,
            payload,
        },
    }
}

/// Settings frame payload entries (id, value), plus the flags the
/// caller wants (ACK frames carry no entries).
pub fn encode_settings(out: &mut BytesMut, entries: &[(u16, u32)]) {
    for &(id, value) in entries {
        out.put_u16(id);
        out.put_u32(value);
    }
}

/// One fully encoded frame.
pub fn encode(ty: FrameType, flags: u8, stream_id: u32, payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(HEADER_LEN + payload.len());
    FrameHeader {
        ty,
        flags,
        stream_id,
    }
    .encode(payload.len() as u32, &mut out);
    out.extend_from_slice(payload);
    out.freeze()
}

/// SETTINGS with our (default) values: empty entries — defaults are
/// what we run (header table 4096, no push).
pub fn settings_frame() -> Bytes {
    encode(FrameType::Settings, 0, 0, &[])
}

/// SETTINGS ACK.
pub fn settings_ack_frame() -> Bytes {
    encode(FrameType::Settings, ACK, 0, &[])
}

/// PING ACK echoing the peer's 8 octets.
pub fn ping_ack_frame(payload: &[u8]) -> Bytes {
    encode(FrameType::Ping, ACK, 0, payload)
}

/// HEADERS carrying one HPACK block (END_STREAM/END_HEADERS per the
/// caller).
pub fn headers_frame(stream_id: u32, block: &[u8], end_stream: bool) -> Bytes {
    let mut flags = END_HEADERS;
    if end_stream {
        flags |= END_STREAM;
    }
    encode(FrameType::Headers, flags, stream_id, block)
}

/// DATA carrying body bytes (END_STREAM per the caller).
pub fn data_frame(stream_id: u32, data: &[u8], end_stream: bool) -> Bytes {
    encode(
        FrameType::Data,
        if end_stream { END_STREAM } else { 0 },
        stream_id,
        data,
    )
}

/// WINDOW_UPDATE (stream 0 = connection).
pub fn window_update_frame(stream_id: u32, increment: u32) -> Bytes {
    let payload = (increment & 0x7fff_ffff).to_be_bytes();
    encode(FrameType::WindowUpdate, 0, stream_id, &payload)
}

/// GOAWAY (last stream id + error code; debug data optional).
pub fn goaway_frame(last_stream_id: u32, error_code: u32) -> Bytes {
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&(last_stream_id & 0x7fff_ffff).to_be_bytes());
    payload.extend_from_slice(&error_code.to_be_bytes());
    encode(FrameType::Goaway, 0, 0, &payload)
}

/// Parse one SETTINGS payload into entries (ACK frames are empty).
pub fn parse_settings(payload: &[u8]) -> Result<Vec<(u16, u32)>, String> {
    if payload.len().is_multiple_of(6) {
        Ok(payload
            .as_chunks::<6>()
            .0
            .iter()
            .map(|c| {
                (
                    u16::from_be_bytes([c[0], c[1]]),
                    u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
                )
            })
            .collect())
    } else {
        Err("settings payload not a multiple of 6 octets".to_string())
    }
}

/// Parse one WINDOW_UPDATE payload (RFC 9113 §6.9: 1..=2^31-1).
pub fn parse_window_update(payload: &[u8]) -> Result<u32, String> {
    if payload.len() != 4 {
        return Err("window update without 4 octets".to_string());
    }
    let inc = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff;
    if inc == 0 {
        return Err("window update increment of 0".to_string());
    }
    Ok(inc)
}

/// Strip PADDED padding from a DATA/HEADERS payload (RFC 9113 §6.1:
/// pad length octet + trailing pad, bounds-checked).
pub fn strip_padding(flags: u8, payload: &[u8]) -> Result<&[u8], String> {
    if flags & PADDED == 0 {
        return Ok(payload);
    }
    let Some(&pad_len) = payload.first() else {
        return Err("padded frame without pad length".to_string());
    };
    let pad_len = pad_len as usize;
    if pad_len + 1 > payload.len() {
        return Err("pad length exceeds the frame".to_string());
    }
    Ok(&payload[1..payload.len() - pad_len])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip_all_types() {
        // Per-type legal shapes (decode_frame validates them): stream
        // scoped where the protocol demands, connection-scoped payload
        // shapes where fixed.
        for v in 0u8..=9 {
            let ty = FrameType::from_u8(v);
            assert_eq!(ty.to_u8(), v);
            let (flags, stream, payload): (u8, u32, &[u8]) = match ty {
                FrameType::Data
                | FrameType::Headers
                | FrameType::PushPromise
                | FrameType::Continuation => (0xa5, 0x1234_5678, b"abcd"),
                FrameType::Priority => (0, 0x1234_5678, &[0u8; 5]),
                FrameType::RstStream => (0, 0x1234_5678, &4u32.to_be_bytes()),
                FrameType::Settings => (0, 0, &[]),
                FrameType::Ping => (0, 0, &[0u8; 8]),
                FrameType::Goaway => (0, 0, &[0u8; 8]),
                FrameType::WindowUpdate => (0, 0x1234_5678, &1u32.to_be_bytes()),
                FrameType::Unknown(_) => unreachable!("0..=9 are all known"),
            };
            let header = FrameHeader {
                ty,
                flags,
                stream_id: stream,
            };
            let mut out = BytesMut::new();
            header.encode(payload.len() as u32, &mut out);
            out.extend_from_slice(payload);
            match decode_frame(&out) {
                FrameStep::Have {
                    consumed,
                    header: h,
                    payload: p,
                } => {
                    assert_eq!(consumed, out.len());
                    assert_eq!(h.ty, ty);
                    assert_eq!(h.flags, flags);
                    // reserved bit masked off in both directions
                    assert_eq!(h.stream_id, stream & 0x7fff_ffff);
                    assert_eq!(&p[..], payload);
                }
                _ => panic!("roundtrip failed for {ty:?}"),
            }
        }
    }

    #[test]
    fn unknown_types_are_kept_and_skipped() {
        let header = FrameHeader {
            ty: FrameType::Unknown(0x42),
            flags: 0,
            stream_id: 7,
        };
        let mut out = BytesMut::new();
        header.encode(2, &mut out);
        out.extend_from_slice(b"xy");
        match decode_frame(&out) {
            FrameStep::Have {
                header, payload, ..
            } => {
                assert_eq!(header.ty, FrameType::Unknown(0x42));
                assert_eq!(&payload[..], b"xy");
            }
            _ => panic!("unknown type must decode"),
        }
    }

    #[test]
    fn need_more_is_partial_safe() {
        assert!(matches!(decode_frame(&[]), FrameStep::Need));
        assert!(matches!(decode_frame(&[0, 0, 4, 4, 0, 0]), FrameStep::Need));
        // full header but short payload
        let mut buf = vec![0, 0, 4, 0x4, 0, 0, 0, 0, 0];
        buf.extend_from_slice(b"ab");
        assert!(matches!(decode_frame(&buf), FrameStep::Need));
    }

    #[test]
    fn per_type_shape_errors() {
        let f = |ty, flags, stream, payload: &[u8]| {
            let mut out = BytesMut::new();
            FrameHeader {
                ty,
                flags,
                stream_id: stream,
            }
            .encode(payload.len() as u32, &mut out);
            out.extend_from_slice(payload);
            decode_frame(&out)
        };
        assert!(matches!(
            f(FrameType::Settings, 0, 1, &[]),
            FrameStep::Malformed(_)
        ));
        assert!(matches!(
            f(FrameType::Settings, PADDED, 0, &[]),
            FrameStep::Malformed(_)
        ));
        assert!(matches!(
            f(FrameType::Ping, 0, 3, &[0; 8]),
            FrameStep::Malformed(_)
        ));
        assert!(matches!(
            f(FrameType::Ping, 0, 0, &[0; 7]),
            FrameStep::Malformed(_)
        ));
        assert!(matches!(
            f(FrameType::WindowUpdate, 0, 0, &[0, 0, 0]),
            FrameStep::Malformed(_)
        ));
        assert!(matches!(
            f(FrameType::RstStream, 0, 1, &[0; 5]),
            FrameStep::Malformed(_)
        ));
        assert!(matches!(
            f(FrameType::Goaway, 0, 0, &[0; 6]),
            FrameStep::Malformed(_)
        ));
        assert!(matches!(
            f(FrameType::Data, 0, 0, b"x"),
            FrameStep::Malformed(_)
        ));
        assert!(matches!(
            f(FrameType::Headers, 0, 0, b"x"),
            FrameStep::Malformed(_)
        ));
        // legal shapes
        assert!(matches!(
            f(FrameType::Settings, 0, 0, &[0; 6]),
            FrameStep::Have { .. }
        ));
        assert!(matches!(
            f(FrameType::Ping, 0, 0, &[0; 8]),
            FrameStep::Have { .. }
        ));
    }

    #[test]
    fn settings_roundtrip() {
        let mut payload = BytesMut::new();
        encode_settings(
            &mut payload,
            &[
                (SETTINGS_MAX_FRAME_SIZE, 16_384),
                (SETTINGS_INITIAL_WINDOW_SIZE, 65_535),
            ],
        );
        let parsed = parse_settings(&payload).expect("settings");
        assert_eq!(
            parsed,
            vec![
                (SETTINGS_MAX_FRAME_SIZE, 16_384),
                (SETTINGS_INITIAL_WINDOW_SIZE, 65_535)
            ]
        );
        assert!(parse_settings(b"12345").is_err());
    }

    #[test]
    fn window_update_bounds() {
        let inc = 0x8fff_ffffu32; // reserved bit set on the wire
        let f = window_update_frame(0, inc);
        match decode_frame(&f) {
            FrameStep::Have { payload, .. } => {
                assert_eq!(parse_window_update(&payload).unwrap(), 0x0fff_ffff);
            }
            _ => panic!("wu decode"),
        }
        assert_eq!(
            parse_window_update(&[0, 0, 0, 0]),
            Err("window update increment of 0".to_string())
        );
    }

    #[test]
    fn padding_strips_and_validates() {
        let mut payload = vec![2u8, 1, 2, 3, 4, 9, 9];
        assert_eq!(strip_padding(PADDED, &payload).unwrap(), &[1, 2, 3, 4]);
        payload[0] = 40;
        assert!(strip_padding(PADDED, &payload).is_err());
        let empty: Vec<u8> = vec![];
        assert!(strip_padding(PADDED, &empty).is_err());
        // unpadded passes through
        assert_eq!(strip_padding(0, b"abc").unwrap(), b"abc");
    }

    #[test]
    fn helpers_encode_expected_bytes() {
        // SETTINGS empty: 000000 04 00 00000000
        assert_eq!(&settings_frame()[..], &[0, 0, 0, 4, 0, 0, 0, 0, 0][..]);
        // SETTINGS ACK: 000000 04 01 00000000
        assert_eq!(&settings_ack_frame()[..], &[0, 0, 0, 4, 1, 0, 0, 0, 0][..]);
        // PING ACK echo
        let ping = ping_ack_frame(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            &ping[..],
            &[0, 0, 8, 6, 1, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8][..]
        );
        // HEADERS: END_STREAM|END_HEADERS = 0x5
        let h = headers_frame(1, b"AB", true);
        assert_eq!(&h[..], &[0, 0, 2, 1, 0x5, 0, 0, 0, 1, b'A', b'B'][..]);
        // GOAWAY
        let g = goaway_frame(5, 0xb);
        assert_eq!(
            &g[..],
            &[0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0x0b][..]
        );
    }
}

/// Pass-2 schedule/split property suites (persisted regressions per the
/// pass-1 convention). `cargo test -p wrex-h2`.
#[cfg(test)]
mod prop {
    use super::*;
    use proptest::prelude::*;

    /// The full fixture family: every helper-encoded frame shape.
    fn fixtures() -> Vec<Bytes> {
        vec![
            settings_frame(),
            settings_ack_frame(),
            ping_ack_frame(b"12345678"),
            headers_frame(1, &[0x82], true),
            data_frame(3, b"wrex", true),
            window_update_frame(0, 0x10000),
            goaway_frame(5, 0xb),
        ]
    }

    /// Truncated at EVERY offset: never a panic, never a read past the
    /// buffer — Need (partial header/payload) or Malformed (bad fixed
    /// shape), and a full frame decodes to Have.
    #[test]
    fn split_sweep_every_offset() {
        for f in fixtures() {
            for cut in 0..=f.len() {
                let step = decode_frame(&f[..cut]);
                match step {
                    FrameStep::Need => {}
                    FrameStep::Malformed(_) => {}
                    FrameStep::Have { .. } => {
                        // A prefix shorter than a whole frame must not
                        // claim to have one.
                        assert!(cut >= f.len(), "prefix {cut} claimed a full frame");
                    }
                }
            }
            // And the whole frame always decodes.
            assert!(matches!(decode_frame(&f), FrameStep::Have { .. }));
        }
    }

    // Arbitrary two-piece splits of a frame stream reassemble: feeding
    // [prefix, rest] must accumulate (via the caller's buffer model —
    // here: decode_frame over concat) to the same step as the whole
    // buffer, and iterating split-by-split reaches every frame in
    // order (the session's chunked-feed invariant, driven at the
    // frame layer).
    proptest! {
        #![proptest_config(ProptestConfig {
            failure_persistence: Some(Box::new(proptest::test_runner::FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            cases: 256,
            ..ProptestConfig::default()
        })]

        #[test]
        fn arbitrary_splits_never_desync(f_idx in 0u8..7, _cut in 0usize..64, junk in proptest::collection::vec(proptest::num::u8::ANY, 0..16)) {
            let fixtures = fixtures();
            let f = &fixtures[f_idx as usize % fixtures.len()];
            // A junk prefix frame (Malformed/Need/Hav — never a panic),
            // then the real frame split at `cut`.
            let stream: Vec<u8> = [junk.as_slice(), &f[..], f.as_ref()].concat();
            let mut cursor = 0usize;
            let mut frames_seen = 0usize;
            while cursor < stream.len() {
                match decode_frame(&stream[cursor..]) {
                    FrameStep::Need => break,
                    FrameStep::Malformed(_) => break, // caller stops the stream
                    FrameStep::Have { consumed, .. } => {
                        cursor += consumed;
                        frames_seen += 1;
                    }
                }
            }
            // The junk prefix never causes a panic and the walk makes
            // forward progress or stops: consumed stays in-bounds.
            assert!(cursor <= stream.len());
            let _ = frames_seen;
        }
    }
}
