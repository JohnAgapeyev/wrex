#![no_main]
//! libfuzzer target: raw bytes → the seven IPv6 extension-header
//! dissectors (tranche 17a). The start kind picks from the first byte
//! so every dissector is reachable directly; chains exercise the
//! fuzzed next_header dispatch map. Must never panic.

use libfuzzer_sys::fuzz_target;
use wrex::standard;

const KINDS: [&str; 7] = [
    "hopopts",
    "dstopts",
    "routing",
    "frag",
    "ah",
    "esp",
    "nonext",
];

fuzz_target!(|data: &[u8]| {
    let registry = standard();
    let start = KINDS[data.first().map_or(0, |b| *b as usize) % KINDS.len()];
    let _packet = wrex_core::dissect::dissect(&registry, data, start);
});
