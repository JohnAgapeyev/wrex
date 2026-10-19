#![no_main]
//! libFuzzer target: raw bytes → dns dissection. Must never panic
//! (tranche 3: name-compression pointer chains, record sections,
//! truncated sections must all stay never-fatal).

use libfuzzer_sys::fuzz_target;
use wrex::standard;

fuzz_target!(|data: &[u8]| {
    let registry = standard();
    let _packet = wrex_core::dissect::dissect(&registry, data, "dns");
});