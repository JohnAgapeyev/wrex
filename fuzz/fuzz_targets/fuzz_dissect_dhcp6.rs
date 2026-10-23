#![no_main]
//! libfuzzer target: raw bytes → the DHCPv6 dissector (tranche 17c).
//! The fixed-header + options-region parse (u16 TLVs, the nested
//! IA_NA/IAADDR walk, the relay 12/13 extended header) must never
//! panic.

use libfuzzer_sys::fuzz_target;
use wrex::standard;

fuzz_target!(|data: &[u8]| {
    let registry = standard();
    let _packet = wrex_core::dissect::dissect(&registry, data, "dhcp6");
});
