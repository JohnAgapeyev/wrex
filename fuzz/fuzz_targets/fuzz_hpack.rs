#![no_main]
//! libFuzzer target: arbitrary bytes into the HPACK decoder and —
//! tranche 16a — the send-side `HpackEncoder` (wrex-h2). Invariants:
//! never panics (lying lengths, hostile indexes, Huffman garbage),
//! every successful decode re-encodes through wrex's literal encoder
//! to a block that decodes back to the same header list (the
//! recipe-replay contract), and every encoder output under **both**
//! policies decodes back to exactly what went in through one stateful
//! peer context (the indexed policy's dynamic-table pairing).

use libfuzzer_sys::fuzz_target;
use wrex_h2::hpack::{encode_header_block, HpackDecoder, HpackEncodePolicy, HpackEncoder};

fuzz_target!(|data: Vec<u8>| {
    let mut dec = HpackDecoder::default();
    // decoding never panics, whatever the bytes say
    if let Ok(fields) = dec.decode(&data) {
        // every decoded field re-encodes (lossy str boundary cases
        // aside) through the literal encoder and decodes identically
        let pairs: Vec<(&str, &str)> = fields
            .iter()
            .filter_map(|(n, v)| {
                Some((std::str::from_utf8(n).ok()?, std::str::from_utf8(v).ok()?))
            })
            .collect();
        if pairs.len() == fields.len() {
            let block = encode_header_block(&pairs);
            let mut dec2 = HpackDecoder::default();
            let back = dec2.decode(&block).expect("literal block decodes");
            assert_eq!(back, fields, "literal re-encode must roundtrip");
            // literal encoding adds no dynamic-table state
            assert!(dec2.dynamic_entries().is_empty());
        }
    }

    // 16a: the same bytes, fed through both encoder policies as a
    // string pair list, decode back to themselves — the encoder's
    // blocks are always well-formed and self-consistent (size updates
    // ≤ the peer cap, indexes within range, Huffman round-trips).
    let text = String::from_utf8_lossy(&data).into_owned();
    let pairs: Vec<(&str, &str)> = text
        .split(|c: char| c == '\n' || c == '\0')
        .filter_map(|line| line.split_once(':'))
        .collect();
    for policy in [HpackEncodePolicy::Indexed, HpackEncodePolicy::Literal] {
        let mut enc = HpackEncoder::new(policy);
        let mut peer = HpackDecoder::default();
        let block = enc.encode(&pairs);
        let back = peer.decode(&block).expect("encoder block decodes");
        assert_eq!(
            back,
            pairs
                .iter()
                .map(|&(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
                .collect::<Vec<_>>(),
            "{policy:?} policy roundtrip"
        );
        // replayed sequence: deterministic per-round under one context
        // (round 2 references round-1 dynamic entries — the *same*
        // peer context decodes it, never a fresh one)
        let block2 = enc.encode(&pairs);
        assert_eq!(
            peer.decode(&block2).expect("replay decodes"),
            back,
            "{policy:?} replay decodes identically"
        );
    }
});