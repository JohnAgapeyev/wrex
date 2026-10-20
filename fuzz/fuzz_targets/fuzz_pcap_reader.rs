#![no_main]
//! libFuzzer target: raw bytes → the classic pcap reader. Must never
//! panic (tranche 5: every magic variant, truncated records, odd tails).

use libfuzzer_sys::fuzz_target;
use wrex_pcap::read;

fuzz_target!(|data: &[u8]| {
    let _ = read(data);
});