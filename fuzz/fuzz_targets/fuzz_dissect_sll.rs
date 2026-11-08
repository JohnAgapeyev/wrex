#![no_main]
//! libfuzzer target: raw bytes → the Linux cooked-capture codecs. Must
//! never panic; any bytes dissect (the header truncation guard + the
//! ethertype dispatch into the children).

use libfuzzer_sys::fuzz_target;
use wrex::standard;

fuzz_target!(|data: &[u8]| {
    let registry = standard();
    let _p1 = wrex_core::dissect::dissect(&registry, data, "sll");
    let _p2 = wrex_core::dissect::dissect(&registry, data, "sll2");
});
