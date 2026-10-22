#![no_main]
//! libFuzzer target: arbitrary bytes into the h2 frame decoder
//! (wrex-h2). Invariants: never panics, `Need`/`Malformed` on short or
//! hostile inputs, and every `Have` carries a consistent
//! (consumed == HEADER_LEN + payload.len()) shape that re-encodes
//! byte-identically through the same header codec.

use libfuzzer_sys::fuzz_target;
use wrex_h2::frame::{decode_frame, FrameStep, HEADER_LEN};

fuzz_target!(|data: Vec<u8>| {
    match decode_frame(&data) {
        FrameStep::Need => {}
        FrameStep::Malformed(_) => {}
        FrameStep::Have { consumed, header, payload } => {
            assert_eq!(consumed, HEADER_LEN + payload.len());
            assert!(consumed <= data.len());
            // the stream id keeps the reserved bit masked off
            assert_eq!(header.stream_id & 0x8000_0000, 0);
            // re-encode: the header is a lossless function of its bytes
            let mut out = bytes::BytesMut::with_capacity(consumed);
            header.encode(payload.len() as u32, &mut out);
            out.extend_from_slice(&payload);
            assert_eq!(&out[..], &data[..consumed]);
            // and the first `consumed` bytes decode to the same frame
            match decode_frame(&out) {
                FrameStep::Have {
                    header: h2, payload: p2, ..
                } => {
                    assert_eq!(h2.ty, header.ty);
                    assert_eq!(h2.flags, header.flags);
                    assert_eq!(h2.stream_id, header.stream_id);
                    assert_eq!(&p2[..], &payload[..]);
                }
                _ => panic!("re-encoded frame must decode"),
            }
        }
    }
});