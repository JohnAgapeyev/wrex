//! `dissect --spans` (tranche 11b-γ) and `wrex diff` (tranche 12) CLI
//! tests (assert_cmd, no sockets): the span taxonomy opt-in and the
//! offline findings differential.
//!
//! Spawns the `wrex` binary: ignored under Miri.
#![cfg_attr(miri, ignore = "spawns the wrex binary; not Miri-safe")]

use assert_cmd::Command;

fn wrex() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wrex"))
}

/// The golden eth+ipv4+udp frame (the README recipe; valid checksums).
const GOLDEN: &str =
    "ffffffffffff0000000000000800450000200000000040117ccb7f0000017f000001115c15b3000c3d27deadbeef";

fn dissect_stdout(args: &[&str], frame: &str) -> String {
    use std::io::Write as _;
    use std::process::{Command as StdCommand, Stdio};
    let mut child = StdCommand::new(env!("CARGO_BIN_EXE_wrex"))
        .args(["dissect"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wrex dissect");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(&hex::decode(frame).unwrap())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait dissect");
    assert!(out.status.success(), "dissect failed: {out:?}");
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn spans_json_opt_in_and_default_unchanged() {
    // Default: no spans keys at all (the pinned shape).
    let plain = dissect_stdout(&["--format", "json"], GOLDEN);
    let v: serde_json::Value = serde_json::from_str(&plain).unwrap();
    assert!(v["layers"][0].get("spans").is_none(), "{plain}");
    assert!(v.get("payload_span").is_none(), "{plain}");

    // --spans: per-layer spans maps + the payload span, and the rest
    // of the shape (fields, anomalies) unchanged.
    let sp = dissect_stdout(&["--spans", "--format", "json"], GOLDEN);
    let sv: serde_json::Value = serde_json::from_str(&sp).unwrap();
    let eth = &sv["layers"][0];
    let ipv4 = &sv["layers"][1];
    let udp = &sv["layers"][2];
    assert_eq!(
        eth["spans"]["dst"],
        serde_json::json!({
            "type": "bytes", "start": 0, "end": 6,
        })
    );
    assert_eq!(
        eth["spans"]["type"],
        serde_json::json!({
            "type": "bytes", "start": 12, "end": 14,
        })
    );
    assert_eq!(
        ipv4["spans"]["ver"],
        serde_json::json!({
            "type": "bits", "start": 14, "end": 15, "shift": 0, "width": 4,
        })
    );
    assert_eq!(
        udp["spans"]["checksum"],
        serde_json::json!({
            "type": "bytes", "start": 40, "end": 42,
        })
    );
    // Total presence: every rendered field key has a span entry.
    for layer in sv["layers"].as_array().unwrap() {
        let fields = layer["fields"].as_object().unwrap();
        let spans = layer["spans"].as_object().unwrap();
        for key in fields.keys() {
            assert!(spans.contains_key(key), "{key} missing from spans");
        }
    }
    // Fields and anomalies stay byte-identical to the default shape.
    assert_eq!(eth["fields"], v["layers"][0]["fields"]);
    assert_eq!(sv["anomalies"], v["anomalies"]);
    assert_eq!(sv["payload_hex"], v["payload_hex"]);
    // The payload span covers the frame tail: udp payload 4 bytes.
    assert_eq!(sv["payload_span"], serde_json::json!([42, 46]));
}

#[test]
fn spans_text_opt_in() {
    let plain = dissect_stdout(&[], GOLDEN);
    assert!(!plain.contains("spans:"), "default text has no spans");
    let sp = dissect_stdout(&["--spans"], GOLDEN);
    assert!(sp.contains("spans:\n"), "{sp}");
    assert!(sp.contains("dst: bytes @0..6\n"), "{sp}");
    assert!(sp.contains("type: bytes @12..14\n"), "{sp}");
    assert!(sp.contains("payload span @42..46\n"), "{sp}");
}

/// `wrex diff`: outcome/reply deltas, one-sided probes, json/jsonl
/// shapes, and the usage/runtime exit codes.
#[test]
fn diff_reports_deltas_and_one_sided_probes() {
    let dir = std::env::temp_dir().join(format!("wrex-t12-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = dir.join("a.jsonl");
    let b = dir.join("b.jsonl");
    std::fs::write(
        &a,
        concat!(
            r#"{"target":"127.0.0.1","port":5353,"proto":"udp","round":1,"strategy":"field","#,
            r#""outcome":"reply","attempts":1,"probe_hex":"aa","reply_hex":"cc"}"#,
            "\n",
            r#"{"target":"127.0.0.1","proto":"icmp","strategy":"baseline","#,
            r#""outcome":"reply","attempts":1,"probe_hex":"01"}"#,
            "\n",
        ),
    )
    .unwrap();
    std::fs::write(
        &b,
        concat!(
            r#"{"target":"127.0.0.1","port":5353,"proto":"udp","round":1,"strategy":"len","#,
            r#""outcome":"silence","attempts":3,"probe_hex":"aa"}"#,
            "\n",
        ),
    )
    .unwrap();

    // text: one delta line per difference, one-sided probes included.
    let out = wrex()
        .args(["diff", a.to_str().unwrap(), b.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out).to_string();
    assert!(text.contains("5353/udp"), "{text}");
    assert!(text.contains("reply -> silence"), "{text}");
    assert!(text.contains("-reply cc"), "{text}");
    assert!(text.contains("attempts 1 -> 3"), "{text}");
    assert!(text.contains("only in a"), "{text}");
    assert!(text.contains("icmp"), "{text}");
    assert_eq!(text.lines().count(), 2, "{text}");

    // json: an array of the same entries.
    let out = wrex()
        .args([
            "diff",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let v: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out)).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    let changed = arr
        .iter()
        .find(|e| e["kind"] == "changed")
        .expect("changed entry");
    assert_eq!(changed["port"], 5353);
    assert_eq!(changed["deltas"][0]["delta"], "outcome");

    // jsonl: one entry per line, parses back.
    let out = wrex()
        .args([
            "diff",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "--format",
            "jsonl",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let jsonl = String::from_utf8_lossy(&out).to_string();
    assert_eq!(jsonl.lines().count(), 2);
    for line in jsonl.lines() {
        let e: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(e["kind"].is_string(), "{line}");
    }

    // raw/hex carry no report → usage (exit 2).
    wrex()
        .args([
            "diff",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            "--format",
            "raw",
        ])
        .assert()
        .failure()
        .code(2);

    // malformed line → usage (exit 2) pointing at file:line.
    let bad = dir.join("bad.jsonl");
    std::fs::write(&bad, "not json\n").unwrap();
    let out = wrex()
        .args(["diff", bad.to_str().unwrap(), b.to_str().unwrap()])
        .assert()
        .failure()
        .code(2)
        .get_output()
        .stderr
        .clone();
    let err = String::from_utf8_lossy(&out).to_string();
    assert!(err.contains("bad.jsonl:0"), "{err}");

    // unreadable file → runtime (exit 1).
    wrex()
        .args(["diff", "/nonexistent/a.jsonl", b.to_str().unwrap()])
        .assert()
        .failure()
        .code(1);

    let _ = std::fs::remove_dir_all(&dir);
}
