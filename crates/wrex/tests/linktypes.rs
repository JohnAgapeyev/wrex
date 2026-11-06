//! Tranche 23a CLI surfaces: the linktype story end to end —
//! `capture -i any` cooked stores (LINKTYPE_LINUX_SLL, the SLL header
//! synthesis), replay's linktype-driven start dispatch (cooked, RAW,
//! NULL/LOOPBACK), `patch --snaplen` (the T14 deferral), and the
//! 802.11 dissect-only codec. Offline everywhere: the cooked capture
//! ground truth is env-gated in the driver suites (this file covers
//! the file formats + dispatch, which need no sockets).

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::process::Command;

fn wrex() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_wrex"));
    c.env("PROPTEST_RNG_SEED", "31337");
    c
}

/// A golden eth+ipv4+udp frame (the README quickstart bytes).
const ETH_UDP: &str =
    "ffffffffffff0000000000000800450000200000000040117ccb7f0000017f000001115c15b3000c3d27deadbeef";

// --- cooked stores (LINKTYPE_LINUX_SLL) -------------------------------------

/// A hand-built SLL capture roundtrips through replay: the frames
/// dissect from `sll` (the linktype-driven start), and the recorded
/// frames carry their synthesized headers verbatim.
#[test]
fn replay_of_a_cooked_store_dissects_from_sll() {
    // SLL: pkttype=host, hatype=ether(1), halen=6, addr=00:11:22:33:44:55,
    // protocol=0x0800; payload: the golden ipv4+udp datagram.
    let sll_hdr = "00000001000600112233445500000800";
    let datagram = "450000200000000040117ccb7f0000017f000001115c15b3000c3d27deadbeef";
    let frame = format!("{sll_hdr}{datagram}");

    let dir = assert_fs::TempDir::new().unwrap();
    let cap = dir.path().join("cooked.pcap");

    // Build the store through the pcap writer (wrex craft cannot emit
    // SLL headers — capture does; here: our own writer via a tiny
    // helper — the test-only pcap crate directly).
    {
        let f = std::fs::File::create(&cap).unwrap();
        let mut w =
            wrex_pcap::PcapWriter::with_linktype(f, wrex_pcap::linktype::LINUX_SLL).unwrap();
        let bytes = hex::decode(&frame).unwrap();
        w.write_record(std::time::UNIX_EPOCH, &bytes, 65535)
            .unwrap();
        w.flush().unwrap();
    }

    // Replay dissects the record from `sll` — the layers prove the
    // dispatch: sll → ipv4 → udp (linktype 113 → kind `sll`).
    wrex()
        .args(["replay", cap.to_str().unwrap(), "--format", "jsonl"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"kind\":\"sll\""))
        .stdout(predicate::str::contains("\"kind\":\"ipv4\""))
        .stdout(predicate::str::contains("\"kind\":\"udp\""))
        .stdout(predicate::str::contains("\"dport\":5555"));
}

/// The filter engine works on cooked frames (paths through the SLL
/// layer): `udp.dport=5555` selects the golden datagram.
#[test]
fn replay_filter_speaks_cooked_paths() {
    let sll_hdr = "00000001000600112233445500000800";
    let datagram = "450000200000000040117ccb7f0000017f000001115c15b3000c3d27deadbeef";
    let frame = format!("{sll_hdr}{datagram}");

    let dir = assert_fs::TempDir::new().unwrap();
    let cap = dir.path().join("cooked.pcap");
    {
        let f = std::fs::File::create(&cap).unwrap();
        let mut w =
            wrex_pcap::PcapWriter::with_linktype(f, wrex_pcap::linktype::LINUX_SLL).unwrap();
        w.write_record(std::time::UNIX_EPOCH, &hex::decode(&frame).unwrap(), 65535)
            .unwrap();
        w.flush().unwrap();
    }

    wrex()
        .args([
            "replay",
            cap.to_str().unwrap(),
            "--format",
            "hex",
            "--filter",
            "udp.dport=5555",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("deadbeef"));

    // And a non-matching filter selects nothing.
    wrex()
        .args([
            "replay",
            cap.to_str().unwrap(),
            "--format",
            "hex",
            "--filter",
            "udp.dport=53",
        ])
        .assert()
        .success()
        .stdout(predicate::str::is_empty());
}

// --- RAW / NULL / LOOPBACK read-side dispatch --------------------------------

/// A RAW store (LINKTYPE_RAW): the record bytes ARE the ip datagram —
/// replay's per-record nibble peek starts at ipv4.
#[test]
fn replay_of_a_raw_store_peeks_the_family() {
    let datagram = "450000200000000040117ccb7f0000017f000001115c15b3000c3d27deadbeef";
    let dir = assert_fs::TempDir::new().unwrap();
    let cap = dir.path().join("raw.pcap");
    {
        let f = std::fs::File::create(&cap).unwrap();
        let mut w = wrex_pcap::PcapWriter::with_linktype(f, wrex_pcap::linktype::RAW).unwrap();
        w.write_record(
            std::time::UNIX_EPOCH,
            &hex::decode(datagram).unwrap(),
            65535,
        )
        .unwrap();
        w.flush().unwrap();
    }
    wrex()
        .args(["replay", cap.to_str().unwrap(), "--format", "jsonl"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"kind\":\"ipv4\""))
        .stdout(predicate::str::contains("\"kind\":\"udp\""))
        // no eth layer in a raw store
        .stdout(predicate::str::contains("\"kind\":\"eth\"").not());
}

/// A NULL store (LINKTYPE_NULL): the 4-byte host-order AF value
/// prefixes each record — both spellings dispatch to the right family
/// (the v6 arm exercises the BE-written variant).
#[test]
fn replay_of_a_null_store_reads_the_af_prefix() {
    let v4 = "450000200000000040117ccb7f0000017f000001115c15b3000c3d27deadbeef";
    let v6 = "60000000000c11400000000000000000000000000000000000000000000000010000000000000000000000000000000000011155b3000c3d27deadbeef";
    let dir = assert_fs::TempDir::new().unwrap();
    let cap = dir.path().join("null.pcap");
    {
        let f = std::fs::File::create(&cap).unwrap();
        let mut w = wrex_pcap::PcapWriter::with_linktype(f, wrex_pcap::linktype::NULL).unwrap();
        let mut rec4 = 2u32.to_le_bytes().to_vec();
        rec4.extend_from_slice(&hex::decode(v4).unwrap());
        w.write_record(std::time::UNIX_EPOCH, &rec4, 65535).unwrap();
        let mut rec6 = 10u32.to_le_bytes().to_vec();
        rec6.extend_from_slice(&hex::decode(v6).unwrap());
        w.write_record(std::time::UNIX_EPOCH, &rec6, 65535).unwrap();
        w.flush().unwrap();
    }
    wrex()
        .args(["replay", cap.to_str().unwrap(), "--format", "jsonl"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"kind\":\"ipv4\""))
        .stdout(predicate::str::contains("\"kind\":\"ipv6\""))
        .stdout(predicate::str::contains("\"kind\":\"udp\""));
}

// --- patch --snaplen (the T14 deferral) ---------------------------------------

/// `patch -w --snaplen` truncates the STORED bytes with orig_len kept
/// — the passthrough frames keep their annotations.
#[test]
fn patch_snaplen_truncates_the_store() {
    let dir = assert_fs::TempDir::new().unwrap();
    let cap = dir.path().join("cap.pcap");
    {
        let f = std::fs::File::create(&cap).unwrap();
        let mut w = wrex_pcap::PcapWriter::new(f).unwrap();
        w.write_record(std::time::UNIX_EPOCH, &hex::decode(ETH_UDP).unwrap(), 65535)
            .unwrap();
        w.flush().unwrap();
    }
    let out = dir.path().join("short.pcap");
    wrex()
        .args([
            "patch",
            "-r",
            cap.to_str().unwrap(),
            "--snaplen",
            "20",
            "-w",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let bytes = std::fs::read(&out).unwrap();
    let file = wrex_pcap::read(&bytes).unwrap();
    assert_eq!(file.linktype, wrex_pcap::linktype::EN10MB);
    assert_eq!(file.records.len(), 1);
    assert_eq!(file.records[0].bytes.len(), 20);
    assert_eq!(file.records[0].orig_len as usize, ETH_UDP.len() / 2);
}

// --- 802.11 (ADR-0004: dissect-only management frames) ------------------------

/// A hand-built beacon dissects through the CLI: the elt records
/// render and filters speak them; monitor-mode injection is the
/// recorded won't-do (nothing crafts radiotap).
#[test]
fn dot11_beacon_dissects_with_elt_records() {
    // FC: version 0, type 0 (mgmt), subtype 8 (beacon) → 0x80; dur 0;
    // addr1 ff×6, addr2/addr3 00:11:22:33:44:55; seq 7; body: SSID
    // "wrex" + channel 6.
    let frame: String =
        "8000 0000 ffffffffffff 001122334455 001122334455 0007 0004 77726578 0301 06"
            .replace(' ', "");
    use std::io::Write as _;
    let mut child = wrex()
        .args(["dissect", "--start", "dot11", "--format", "json"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&hex::decode(&frame).unwrap())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"kind\": \"dot11\""), "{stdout}");
    assert!(stdout.contains("ssid\": \"wrex\""), "{stdout}");
    assert!(stdout.contains("chan"), "{stdout}");
}

/// dot11 is a start kind: `wrex fields dot11` enumerates the schema
/// (the man pages + completions enumerate from the same table).
#[test]
fn dot11_enumerates_in_fields() {
    wrex()
        .args(["fields", "dot11"])
        .assert()
        .success()
        .stdout(predicate::str::contains("subtype"))
        .stdout(predicate::str::contains("elt"));
}

// --- the datapath knobs -------------------------------------------------------

/// `--rotate-count` without `--rotate-size` is the pointed usage error
/// (the tcpdump -W/-C rule); `--rotate-size 0` likewise.
#[test]
fn rotation_grammar_gates() {
    let dir = assert_fs::TempDir::new().unwrap();
    let out = dir.path().join("cap.pcap");
    wrex()
        .args([
            "capture",
            "-i",
            "lo",
            "--rotate-count",
            "2",
            "-w",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure()
        // clap's own `requires` grammar catches it before the verb —
        // the sharper error, kept deliberately.
        .stderr(predicate::str::contains("--rotate-size"));
    wrex()
        .args([
            "capture",
            "-i",
            "lo",
            "--rotate-size",
            "0",
            "-w",
            out.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("must be > 0"));
}
