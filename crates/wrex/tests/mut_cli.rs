//! `wrex mut` CLI tests (assert_cmd, no sockets): determinism, output
//! formats, pcap write/read round-trips and usage errors. Driver-free —
//! the mutation engine never opens anything.
//!
//! Spawns the `wrex` binary: ignored under Miri.
#![cfg_attr(miri, ignore = "spawns the wrex binary; not Miri-safe")]

use assert_cmd::Command;
use std::io::Write;

fn wrex() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wrex"))
}

/// A golden eth+ipv4+udp frame from the craft grammar (auto-crafted,
/// pinned here): dst fffff..., 127.0.0.1 → 127.0.0.1, 4444 → 53,
/// payload deadbeef. Checksums valid (autofill).
const GOLDEN: &str =
    "ffffffffffff0000000000000800450000200000000040117ccb7f0000017f000001115c0035000c52a5deadbeef";

fn mut_out(args: &[&str]) -> (i32, String) {
    let out = wrex()
        .args(["mut"])
        .args(args)
        .assert()
        .get_output()
        .clone();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

fn mut_err(args: &[&str]) -> (i32, String) {
    let out = wrex()
        .args(["mut"])
        .args(args)
        .assert()
        .failure()
        .get_output()
        .clone();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn count_lines_and_determinism() {
    let (code, a) = mut_out(&["--count", "6", "--seed", "42", GOLDEN]);
    assert_eq!(code, 0);
    assert_eq!(a.lines().count(), 6, "one hex line per mutant");
    // Same seed → byte-identical stream.
    let (_, b) = mut_out(&["--count", "6", "--seed", "42", GOLDEN]);
    assert_eq!(a, b, "same seed must reproduce the mutant stream");
    // Different seed → different stream.
    let (_, c) = mut_out(&["--count", "6", "--seed", "43", GOLDEN]);
    assert_ne!(a, c);
    // Mutants exist: at least one differs from the seed.
    assert!(
        a.lines().any(|l| l.trim() != GOLDEN),
        "the stream never mutated"
    );
}

#[test]
fn raw_and_jsonl_formats() {
    let (code, raw) = mut_out(&["--count", "3", "--seed", "7", "--format", "raw", GOLDEN]);
    assert_eq!(code, 0);
    assert!(!raw.is_empty());

    let (code, jsonl) = mut_out(&["--count", "3", "--seed", "7", "--format", "jsonl", GOLDEN]);
    assert_eq!(code, 0);
    for line in jsonl.lines() {
        let v: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("jsonl line must parse: {e}\n{line}"));
        assert!(v.get("layers").is_some(), "mutant dissected: {line}");
    }
}

#[test]
fn pcap_write_then_read_roundtrip() {
    let tmp = std::env::temp_dir().join(format!("wrex-t6a-mut-{}.pcap", std::process::id()));
    let path = tmp.to_str().unwrap();
    let (code, hexes) = mut_out(&["--count", "4", "--seed", "9", "-w", path, GOLDEN]);
    assert_eq!(code, 0);
    assert_eq!(hexes.lines().count(), 4);

    // The pcap reads back with the in-house reader and its records
    // equal the printed mutants (hex lines in order).
    let bytes = std::fs::read(&tmp).expect("mut wrote the pcap");
    let file = wrex_pcap::read(&bytes).expect("mut wrote a valid pcap");
    assert_eq!(file.linktype, wrex_pcap::linktype::EN10MB);
    assert_eq!(file.records.len(), 4);
    let printed: Vec<&str> = hexes.lines().collect();
    for (rec, hexline) in file.records.iter().zip(printed) {
        assert_eq!(hex::encode(&rec.bytes), hexline.trim());
    }
    let _ = std::fs::remove_file(tmp);
}

#[test]
fn stdin_raw_seeds() {
    use std::process::{Command as StdCommand, Stdio};
    let seed = hex::decode(GOLDEN).unwrap();
    let mut child = StdCommand::new(env!("CARGO_BIN_EXE_wrex"))
        .args(["mut", "--count", "2", "--seed", "11"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn wrex mut");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(&seed)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait mut");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.lines().count(), 2);
}

#[test]
fn usage_errors_exit_2() {
    // No seeds anywhere → usage (stdin is piped-empty under the test
    // harness, so the empty-input usage path fires — still exit 2).
    let (code, stderr) = mut_err(&["--count", "4"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("no seed frames") || stderr.contains("empty input"),
        "{stderr}"
    );

    // Odd-length / non-hex seed → usage.
    let (code, stderr) = mut_err(&["453"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("bad seed frame"), "{stderr}");
    let (code, stderr) = mut_err(&["zz"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("bad seed frame"), "{stderr}");

    // Unknown strategy → usage.
    let (code, stderr) = mut_err(&["--strategy", "voodoo", GOLDEN]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown mutation strategy"), "{stderr}");

    // Unknown format → usage.
    let (code, stderr) = mut_err(&["--format", "yaml", GOLDEN]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown format"), "{stderr}");

    // Unreadable pcap → runtime 1.
    let (code, stderr) = mut_err(&["-r", "/nonexistent/x.pcap"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("cannot read"), "{stderr}");
}

#[test]
fn strategies_all_produce_output() {
    for s in ["field", "len", "flip", "splice", "raw", "all"] {
        let (code, out) = mut_out(&["--count", "8", "--seed", "5", "--strategy", s, GOLDEN]);
        assert_eq!(code, 0, "{s}");
        assert_eq!(out.lines().count(), 8, "{s}");
        assert!(out.lines().any(|l| l.trim() != GOLDEN), "{s} never mutated");
    }
}
