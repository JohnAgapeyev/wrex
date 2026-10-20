#![no_main]
//! libFuzzer target: arbitrary frames → pcap writer → pcap reader
//! round-trip. The captured bytes must survive the trip byte-identically
//! (tranche 5).

use libfuzzer_sys::fuzz_target;
use std::time::{Duration, UNIX_EPOCH};
use wrex_pcap::{PcapWriter, read};

fuzz_target!(|data: &[u8]| {
    let ts = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let mut buf = Vec::new();
    {
        let mut w = PcapWriter::new(&mut buf).expect("global header to a Vec never fails");
        w.write_record(ts, data, 65535).expect("write to a Vec");
    }
    let file = read(&buf).expect("writer output must always parse");
    assert_eq!(file.records.len(), 1);
    assert_eq!(file.records[0].bytes, data);
});