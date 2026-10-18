#![no_main]
//! libfuzzer target: raw bytes → eth dissection. Must never panic.

use libfuzzer_sys::fuzz_target;
use wrex::standard;

fuzz_target!(|data: &[u8]| {
    let registry = standard();
    // Never fatal: any bytes must dissect without panic.
    let _packet = wrex_core::dissect::dissect(&registry, data, "eth");
});
