#![no_main]
//! libfuzzer target: raw bytes → vlan dissection. Must never panic.

use libfuzzer_sys::fuzz_target;
use wrex::standard;

fuzz_target!(|data: &[u8]| {
    let registry = standard();
    // Never fatal: any bytes must dissect without panic (QinQ recursion
    // included: 0x8100/0x88a8 chains self-nest).
    let _packet = wrex_core::dissect::dissect(&registry, data, "vlan");
});