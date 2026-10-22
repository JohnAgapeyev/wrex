#![no_main]
//! libFuzzer target: arbitrary bytes into the HPACK decoder
//! (wrex-h2). Invariants: never panics (lying lengths, hostile
//! indexes, Huffman garbage), and every successful decode re-encodes
//! through wrex's literal encoder to a block that decodes back to the
//! same header list (the recipe-replay contract).

use libfuzzer_sys::fuzz_target;
use wrex_h2::hpack::{encode_header_block, HpackDecoder};

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
});