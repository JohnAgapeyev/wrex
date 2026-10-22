#![no_main]
//! libfuzzer target: raw bytes → the DHCPv6 fixed-header dissector
//! (tranche 17c). The 4-byte header parse must never panic; the
//! options region is the recorded tranche-17c tail. Must never panic.

use libfuzzer_sys::fuzz_target;
use wrex::standard;

fuzz_target!(|data: &[u8]| {
    let registry = standard();
    let _packet = wrex_core::dissect::dissect(&registry, data, "dhcp6");
});
