#![no_main]
//! libfuzzer target: raw bytes → the 802.11 dissect-only codec. Must
//! never panic; any bytes dissect (the FC word, the addr4 shape, the
//! management elt walk with its overrun guard).

use libfuzzer_sys::fuzz_target;
use wrex::standard;

fuzz_target!(|data: &[u8]| {
    let registry = standard();
    let _packet = wrex_core::dissect::dissect(&registry, data, "dot11");
});
