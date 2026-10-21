#![no_main]
//! libFuzzer target: raw bytes → the pcap reader (classic + pcapng
//! auto-detect). Must never panic (tranche 8b: both endiannesses, both
//! timestamp resolutions, unknown-block skips, truncated blocks).

use libfuzzer_sys::fuzz_target;
use wrex_pcap::read;

fuzz_target!(|data: &[u8]| {
    let _ = read(data);
});