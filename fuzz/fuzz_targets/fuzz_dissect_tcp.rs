#![no_main]
//! libfuzzer target: raw bytes → tcp dissection. Must never panic.

use libfuzzer_sys::fuzz_target;
use wrex::standard;

fuzz_target!(|data: &[u8]| {
    let registry = standard();
    let _packet = wrex_core::dissect::dissect(&registry, data, "tcp");
});
