//! Tranche-5 integration suite (offline): `wrex replay` against a
//! synthetic pcap (built with the in-house writer), exit codes for the
//! grammar gates, and the pcap error path. The lo-socket capture/replay
//! round-trip lives in `capture_driver.rs` (env-gated).
//!
//! Every test here spawns the `wrex` binary: not Miri-safe as a unit, so
//! the file is ignored under Miri (the wrex-pcap reader/writer units and
//! proptests run under Miri instead).
#![cfg_attr(
    miri,
    ignore = "spawns the wrex binary; reader/writer units cover Miri"
)]

use std::time::{Duration, UNIX_EPOCH};

use assert_cmd::Command;

fn wrex() -> assert_cmd::Command {
    Command::new(env!("CARGO_BIN_EXE_wrex"))
}

/// §Verification 2's golden frame (craft --format hex of the standard
/// eth+ipv4+udp spec) — a well-formed, dissectable capture record.
const GOLDEN_HEX: &str =
    "ffffffffffff0000000000000800450000200000000040117ccb7f0000017f000001115c15b3000c3d27deadbeef";

/// Write a two-record pcap: the golden frame + a non-matching runt.
fn golden_pcap(path: &std::path::Path) {
    let golden = hex::decode(GOLDEN_HEX).unwrap();
    let runt = vec![0xde, 0xad, 0xbe, 0xef];
    let file = std::fs::File::create(path).unwrap();
    let mut w = wrex_pcap::PcapWriter::new(std::io::BufWriter::new(file)).unwrap();
    w.write_record(
        UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        &golden,
        65535,
    )
    .unwrap();
    w.write_record(
        UNIX_EPOCH + Duration::from_secs(1_700_000_002),
        &runt,
        65535,
    )
    .unwrap();
    w.flush().unwrap();
    drop(w);
}

/// Offline replay prints one dissected packet per line (jsonl default).
#[test]
fn replay_offline_default_jsonl() {
    let pcap = std::env::temp_dir().join("wrex-t5-offline-default.pcap");
    golden_pcap(&pcap);
    let out = wrex()
        .args(["replay", pcap.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "two records -> two jsonl lines");
    for line in &lines {
        assert!(line.contains("\"layers\""), "jsonl packet: {line}");
    }
    // The first line carries the udp layer; the runt does not.
    assert!(lines[0].contains("\"udp\""));
    // Differential vs `wrex dissect --format jsonl` of the same bytes.
    let golden = hex::decode(GOLDEN_HEX).unwrap();
    let dissect = wrex()
        .args(["dissect", "--format", "jsonl"])
        .write_stdin(golden)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(
        lines[0].trim(),
        String::from_utf8(dissect).unwrap().trim(),
        "replay jsonl must equal dissect jsonl of the same frame"
    );
    let _ = std::fs::remove_file(&pcap);
}

/// `--format raw` concatenates the captured bytes byte-transparently;
/// `--count` and `--filter` gate before printing.
#[test]
fn replay_raw_count_and_filter() {
    let pcap = std::env::temp_dir().join("wrex-t5-offline-raw.pcap");
    golden_pcap(&pcap);
    let golden = hex::decode(GOLDEN_HEX).unwrap();
    let runt = vec![0xde, 0xad, 0xbe, 0xef];

    let full = wrex()
        .args(["replay", pcap.to_str().unwrap(), "--format", "raw"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let mut want = golden.clone();
    want.extend_from_slice(&runt);
    assert_eq!(full, want, "raw replay concatenates record bytes");

    let one = wrex()
        .args([
            "replay",
            pcap.to_str().unwrap(),
            "--format",
            "raw",
            "--count",
            "1",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(one, golden);

    // udp.dport = 5555 matches only the golden frame.
    let filtered = wrex()
        .args([
            "replay",
            pcap.to_str().unwrap(),
            "--format",
            "raw",
            "--filter",
            "udp.dport=5555",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(filtered, golden);

    // A filter nothing matches: clean exit 0, no output.
    let none = wrex()
        .args([
            "replay",
            pcap.to_str().unwrap(),
            "--format",
            "raw",
            "--filter",
            "udp.dport=1",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(none.is_empty());
    let _ = std::fs::remove_file(&pcap);
}

/// Bad pcap files are data outcomes: exit 1 (not usage).
#[test]
fn replay_bad_pcap_exits_1() {
    let path = std::env::temp_dir().join("wrex-t5-bad.pcap");
    std::fs::write(&path, b"not a pcap at all, nope nope").unwrap();
    wrex()
        .args(["replay", path.to_str().unwrap()])
        .assert()
        .failure()
        .code(1);
    // Missing file: runtime too.
    let missing = std::env::temp_dir().join("wrex-t5-missing.pcap");
    let _ = std::fs::remove_file(&missing);
    wrex()
        .args(["replay", missing.to_str().unwrap()])
        .assert()
        .failure()
        .code(1);
}

/// Grammar gates are usage errors: exit 2.
#[test]
fn replay_and_capture_usage_errors() {
    let pcap = std::env::temp_dir().join("wrex-t5-usage.pcap");
    golden_pcap(&pcap);
    let p = pcap.to_str().unwrap();
    // Pacing flags are mutually exclusive.
    wrex()
        .args(["replay", p, "--rate", "10", "--interval", "100ms"])
        .assert()
        .failure()
        .code(2);
    // --rate without a send iface makes no sense.
    wrex()
        .args(["replay", p, "--rate", "10"])
        .assert()
        .failure()
        .code(2);
    wrex()
        .args(["replay", p, "--jitter", "50ms"])
        .assert()
        .failure()
        .code(2);
    // capture needs the interface AND the -w file.
    wrex()
        .args(["capture", "-w", "/tmp/wrex-t5-capture-missing.pcap"])
        .assert()
        .failure()
        .code(2);
    wrex()
        .args(["capture", "-i", "lo"])
        .assert()
        .failure()
        .code(2);
    let _ = std::fs::remove_file(&pcap);
}

/// A big-endian microsecond pcap (written by hand) replays identically:
/// the reader's variant matrix is exercised through the CLI.
#[test]
fn replay_be_pcap_variant() {
    // Big-endian global header + one BE record (sec 1, frac 2, len 4).
    let path = std::env::temp_dir().join("wrex-t5-be.pcap");
    let mut bytes = vec![0xa1, 0xb2, 0xc3, 0xd4];
    bytes.extend_from_slice(&[0x00, 0x02, 0x00, 0x04]); // version 2.4
    bytes.extend_from_slice(&[0u8; 8]); // thiszone + sigfigs
    bytes.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]); // snaplen
    bytes.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // EN10MB
    bytes.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 4]);
    bytes.extend_from_slice(&[1, 2, 3, 4]);
    std::fs::write(&path, bytes).unwrap();

    let out = wrex()
        .args(["replay", path.to_str().unwrap(), "--format", "raw"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(out, vec![1, 2, 3, 4]);
    let _ = std::fs::remove_file(&path);
}
