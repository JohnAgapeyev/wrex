//! Foreign-capture data compatibility (`cargo test -- foreign_pcap`):
//! the in-house pcap reader against files written by OTHER tools
//! (text2pcap/editcap of the Wireshark suite, 4.7.4) — the pass-2
//! complement to the self-captured corpus: nothing here was ever
//! touched by `wrex capture`.
//!
//! Classic (all four magic variants: LE/BE x µs/ns) + pcapng must all
//! read back the same three frames, byte-identical to the source
//! corpus fixtures. Miri-safe (pure reader over committed bytes).

use wrex_pcap::linktype;
use wrex_test::corpus::Corpus;

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../wrex-test/corpus/foreign")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The three source frames (corpus fixture 0s: udp/tcp/icmpv6), the
/// ground truth every foreign file must read back.
fn expected_frames() -> Vec<Vec<u8>> {
    let corpora = Corpus::load_all();
    ["udp", "tcp", "icmpv6"]
        .iter()
        .filter_map(|name| {
            let c = corpora.iter().find(|c| c.name == *name)?;
            Some(c.frames.first()?.bytes.clone())
        })
        .collect()
}

fn assert_three_frames(file: &wrex_pcap::PcapFile, label: &str) {
    let want = expected_frames();
    assert_eq!(
        file.records.len(),
        want.len(),
        "{label}: foreign record count"
    );
    assert_eq!(file.linktype, linktype::EN10MB, "{label}: linktype");
    for (i, (got, want)) in file.records.iter().zip(&want).enumerate() {
        assert_eq!(&got.bytes, want, "{label}: frame {i} byte-identical");
        // text2pcap stamps real wall-clock times.
        assert!(got.ts > std::time::UNIX_EPOCH, "{label}: frame {i} ts");
    }
}

#[test]
fn foreign_classic_all_four_magic_variants() {
    for label in ["classic_le.pcap", "classic_be.pcap"] {
        let bytes = fixture(label);
        let file = wrex_pcap::read(&bytes).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_three_frames(&file, label);
        // Endianness detected from the magic.
        let be = label.contains("_be");
        assert_eq!(file.big_endian, be, "{label}: endianness flag");
        assert!(!file.nanosecond, "{label}: us variant");
    }
    // The ns magic patches: still parse, flagged nanosecond.
    for label in ["classic_le_ns.pcap", "classic_be_ns.pcap"] {
        let bytes = fixture(label);
        let file = wrex_pcap::read(&bytes).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_three_frames(&file, label);
        assert!(file.nanosecond, "{label}: ns flag");
    }
}

#[test]
fn foreign_pcapng_text2pcap_default() {
    let bytes = fixture("pcapng_le.pcapng");
    let file = wrex_pcap::read(&bytes).expect("pcapng_le.pcapng");
    assert_three_frames(&file, "pcapng_le.pcapng");
    assert!(!file.big_endian);
}
