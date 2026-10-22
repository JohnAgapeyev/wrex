//! `wrex patch` CLI tests (assert_cmd, no sockets): the tranche-14
//! span-patch verb — typed edits + scope recomputation, shape edits,
//! index/filter selection with byte-identical passthrough, pcap
//! (-w/--pcapng) plumbing, exit-code mapping, and the `dissect
//! --frame` opt-in (the T11a deferral the tranche closes).
//!
//! Spawns the `wrex` binary: ignored under Miri.
#![cfg_attr(miri, ignore = "spawns the wrex binary; not Miri-safe")]

use assert_cmd::Command;
use std::io::Write;

fn wrex() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wrex"))
}

/// The golden eth+ipv4+udp frame (the README recipe; valid checksums,
/// dport 5555 so nothing dispatches into a deeper codec).
const GOLDEN: &str =
    "ffffffffffff0000000000000800450000200000000040117ccb7f0000017f000001115c15b3000c3d27deadbeef";

fn golden_bytes() -> Vec<u8> {
    hex::decode(GOLDEN).unwrap()
}

/// An eth+ipv4+tcp(SYN) frame crafted through the real CLI.
fn tcp_golden() -> Vec<u8> {
    craft_out(&[
        "--format",
        "raw",
        "--layer",
        "eth",
        "--layer",
        "ipv4",
        "--layer",
        "tcp",
        "--eth-dst=ff:ff:ff:ff:ff:ff",
        "--ipv4-src=127.0.0.1",
        "--ipv4-dst=127.0.0.1",
        "--tcp-sport=40000",
        "--tcp-dport=80",
        "--tcp-flags=0x02",
    ])
}

/// An eth+vlan(100)+ipv4+udp frame (the bit-window masking fixture).
fn vlan_golden() -> Vec<u8> {
    craft_out(&[
        "--format",
        "raw",
        "--layer",
        "eth",
        "--layer",
        "vlan",
        "--layer",
        "ipv4",
        "--layer",
        "udp",
        "--eth-dst=ff:ff:ff:ff:ff:ff",
        "--vlan-vid=100",
        "--ipv4-src=127.0.0.1",
        "--ipv4-dst=127.0.0.1",
        "--udp-sport=4444",
        "--udp-dport=5555",
        "--payload=hex:deadbeef",
    ])
}

/// `wrex craft` → stdout bytes (panics on failure).
fn craft_out(args: &[&str]) -> Vec<u8> {
    wrex()
        .args(["craft"])
        .args(args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone()
}

/// `wrex dissect [args]` with piped frame bytes → stdout text.
fn dissect_text(bytes: &[u8], args: &[&str]) -> String {
    use std::process::{Command as StdCommand, Stdio};
    let mut all: Vec<&str> = vec!["dissect"];
    all.extend_from_slice(args);
    let mut child = StdCommand::new(env!("CARGO_BIN_EXE_wrex"))
        .args(&all)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wrex dissect");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(bytes)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait dissect");
    assert!(
        out.status.success(),
        "dissect failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn patch_out(args: &[&str]) -> (i32, Vec<u8>) {
    let out = wrex()
        .args(["patch"])
        .args(args)
        .assert()
        .success()
        .get_output()
        .clone();
    (out.status.code().unwrap_or(-1), out.stdout.clone())
}

fn patch_err(args: &[&str]) -> (i32, String) {
    let out = wrex()
        .args(["patch"])
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

/// `patch_out` with the stdout decoded (hex/jsonl/text inspections).
fn patch_text(args: &[&str]) -> String {
    let (code, out) = patch_out(args);
    assert_eq!(code, 0);
    String::from_utf8(out).expect("utf8 stdout")
}

/// `wrex dissect` one frame to a parsed jsonl object.
fn dissect_json(bytes: &[u8]) -> serde_json::Value {
    let text = dissect_text(bytes, &["--format", "jsonl"]);
    serde_json::from_str(text.trim()).unwrap_or_else(|e| panic!("dissect jsonl: {e}\n{text}"))
}

/// The fields object of one dissected layer by kind.
fn layer_fields(v: &serde_json::Value, kind: &str) -> serde_json::Value {
    v["layers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["kind"] == kind)
        .unwrap_or_else(|| panic!("no {kind} layer in {v}"))["fields"]
        .clone()
}

/// Write a classic pcap of full records with pinned timestamps.
fn write_pcap(path: &std::path::Path, frames: &[Vec<u8>]) {
    let file = std::fs::File::create(path).unwrap();
    let mut w = wrex_pcap::PcapWriter::new(std::io::BufWriter::new(file)).unwrap();
    for (i, f) in frames.iter().enumerate() {
        let ts = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1000 + i as u64);
        w.write_record(ts, f, 65535).unwrap();
    }
    w.flush().unwrap();
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("wrex-t14-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn set_field_default_scope_recomputes() {
    let (code, out) = patch_out(&["--set", "ipv4.ttl=7", "--format", "raw", GOLDEN]);
    assert_eq!(code, 0);
    assert_eq!(
        out.len(),
        golden_bytes().len(),
        "field edit keeps the shape"
    );
    assert_eq!(out[22], 7, "ttl lands at 14+8");
    // the ipv4 checksum re-derived: different from the seed's.
    assert_ne!(&out[24..26], &golden_bytes()[24..26]);
    // re-dissection ground truth: the whole frame stays consistent.
    let v = dissect_json(&out);
    assert!(v["anomalies"].as_array().unwrap().is_empty(), "{v}");
    assert_eq!(layer_fields(&v, "ipv4")["ttl"], 7);
    // determinism: the same invocation is byte-identical.
    let (_, again) = patch_out(&["--set", "ipv4.ttl=7", "--format", "raw", GOLDEN]);
    assert_eq!(out, again);
    // multi-set: two fields in one run.
    let (_, two) = patch_out(&[
        "--set",
        "ipv4.ttl=7",
        "--set",
        "ipv4.dst=10.0.0.5",
        "--format",
        "raw",
        GOLDEN,
    ]);
    let v = dissect_json(&two);
    assert!(v["anomalies"].as_array().unwrap().is_empty(), "{v}");
    assert_eq!(layer_fields(&v, "ipv4")["dst"], "10.0.0.5");
}

#[test]
fn set_field_no_recompute_preserves_stale() {
    let (code, out) = patch_out(&[
        "--set",
        "ipv4.ttl=7",
        "--no-recompute",
        "--format",
        "raw",
        GOLDEN,
    ]);
    assert_eq!(code, 0);
    // preserve semantics: ONLY the ttl byte moved; the stale checksum
    // rides along unhealed (bytes unchanged).
    let seed = golden_bytes();
    for i in 0..seed.len() {
        let expected = if i == 22 { 7 } else { seed[i] };
        assert_eq!(out[i], expected, "byte {i} must be untouched");
    }
    let v = dissect_json(&out);
    let anomalies = v["anomalies"].as_array().unwrap();
    assert!(
        anomalies.iter().any(|a| a["path"] == "ipv4.checksum"),
        "stale checksum carried: {v}"
    );
}

#[test]
fn bit_subpaths_flagsets_and_masked_windows() {
    let tcp = tcp_golden();
    let tcp_hex = hex::encode(&tcp);

    // a flag subpath lands through the bit window.
    let out = patch_out(&["--set", "tcp.flags.ack=1", "--format", "raw", &tcp_hex]).1;
    let v = dissect_json(&out);
    assert!(v["anomalies"].as_array().unwrap().is_empty(), "{v}");
    let flags = layer_fields(&v, "tcp")["flags"].as_array().unwrap().clone();
    assert!(flags.contains(&serde_json::json!("syn")));
    assert!(flags.contains(&serde_json::json!("ack")));

    // the whole aggregate accepts bit names and raw masks.
    let out = patch_out(&["--set", "tcp.flags=0x12", "--format", "raw", &tcp_hex]).1;
    let v = dissect_json(&out);
    let flags = layer_fields(&v, "tcp")["flags"].as_array().unwrap().clone();
    assert!(flags.contains(&serde_json::json!("ack")));
    assert!(flags.contains(&serde_json::json!("syn")));

    // a sub-bit window masks without disturbing its neighbors:
    // ipv4.flags.df shares the u16 with frag_off (kept at 0).
    let out = patch_out(&["--set", "ipv4.flags.df=1", "--format", "raw", GOLDEN]).1;
    let v = dissect_json(&out);
    assert!(v["anomalies"].as_array().unwrap().is_empty(), "{v}");
    assert_eq!(out[20], 0x40, "df set, frag_off high bits untouched");
    assert_eq!(out[21], 0);

    // a bit-window field: vlan.vid is a U16 field behind a 12-bit
    // window — an over-wide value masks into the window (the craft
    // rule), and the neighbors (pcp/dei) stay untouched.
    let vlan = vlan_golden();
    let vlan_hex = hex::encode(&vlan);
    let out = patch_out(&["--set", "vlan.vid=65535", "--format", "raw", &vlan_hex]).1;
    let v = dissect_json(&out);
    assert!(v["anomalies"].as_array().unwrap().is_empty(), "{v}");
    assert_eq!(layer_fields(&v, "vlan")["vid"], 4095, "masked to 0xfff");
    let tci = u16::from_be_bytes([out[14], out[15]]);
    assert_eq!(tci, 0x0fff, "pcp/dei bits untouched");
}

#[test]
fn insert_delete_recompute_consistency() {
    // payload insert: lengths + checksums recompute (scope all).
    let (code, out) = patch_out(&["--insert", "42:01020304", "--format", "raw", GOLDEN]);
    assert_eq!(code, 0);
    assert_eq!(out.len(), 50);
    let v = dissect_json(&out);
    assert!(v["anomalies"].as_array().unwrap().is_empty(), "{v}");
    assert_eq!(v["payload_hex"], "01020304deadbeef");
    assert_eq!(layer_fields(&v, "ipv4")["total_len"], 36);
    assert_eq!(layer_fields(&v, "udp")["length"], 16);

    // payload delete.
    let (code, out) = patch_out(&["--delete", "42:2", "--format", "raw", GOLDEN]);
    assert_eq!(code, 0);
    assert_eq!(out.len(), 44);
    let v = dissect_json(&out);
    assert!(v["anomalies"].as_array().unwrap().is_empty(), "{v}");
    assert_eq!(v["payload_hex"], "beef");

    // shape edits under --no-recompute: lengths stay stale (pointed
    // data, deterministic).
    let (_, stale) = patch_out(&[
        "--insert",
        "42:01020304",
        "--no-recompute",
        "--format",
        "raw",
        GOLDEN,
    ]);
    let v = dissect_json(&stale);
    let anomalies = v["anomalies"].as_array().unwrap();
    assert!(
        anomalies.iter().any(|a| a["path"] == "ipv4.total_len"),
        "{v}"
    );
    assert!(anomalies.iter().any(|a| a["path"] == "udp.length"), "{v}");
}

#[test]
fn scope_selective_and_conflicts() {
    // selective scope: edit udp.checksum with only ipv4 recomputing —
    // the edit lands, udp stays stale, ipv4 stays clean.
    let (code, out) = patch_out(&[
        "--set",
        "udp.checksum=0001",
        "--scope",
        "ipv4.*",
        "--format",
        "raw",
        GOLDEN,
    ]);
    assert_eq!(code, 0);
    assert_eq!(&out[40..42], &[0, 1], "the edit landed");
    let v = dissect_json(&out);
    let anomalies = v["anomalies"].as_array().unwrap();
    assert!(
        anomalies.iter().any(|a| a["path"] == "udp.checksum"),
        "udp stale: {v}"
    );
    assert!(
        !anomalies
            .iter()
            .any(|a| a["path"].as_str().unwrap().starts_with("ipv4")),
        "ipv4 clean: {v}"
    );

    // an edit on a scope-selected derived field is a STATIC conflict:
    // usage (exit 2) before any output.
    let (code, stderr) = patch_err(&["--set", "udp.checksum=0001", GOLDEN]);
    assert_eq!(code, 2);
    assert!(stderr.contains("conflicts with the scope"), "{stderr}");
    let (code, stderr) = patch_err(&["--set", "udp.checksum=0001", "--scope", "udp.*", GOLDEN]);
    assert_eq!(code, 2);
    assert!(stderr.contains("conflicts with the scope"), "{stderr}");
    // ...and no conflict when the scope leaves the field alone.
    let (code, _) = patch_out(&[
        "--set",
        "udp.checksum=0001",
        "--scope",
        "udp.length",
        "--format",
        "raw",
        GOLDEN,
    ]);
    assert_eq!(code, 0);

    // scope grammar: both knobs, malformed selectors.
    let (code, stderr) = patch_err(&["--scope", "udp.*", "--no-recompute", GOLDEN]);
    assert_eq!(code, 2);
    assert!(stderr.contains("mutually exclusive"), "{stderr}");
    let (code, stderr) = patch_err(&["--scope", "bogus", GOLDEN]);
    assert_eq!(code, 2);
    assert!(stderr.contains("bad scope"), "{stderr}");
}

#[test]
fn usage_errors_exit_2() {
    // no seeds anywhere → usage (piped-empty stdin path included).
    let (code, stderr) = patch_err(&[]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("no seed frames") || stderr.contains("empty input"),
        "{stderr}"
    );
    // bad seed hex.
    let (code, stderr) = patch_err(&["--set", "ipv4.ttl=7", "453"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("bad seed frame"), "{stderr}");
    // --set grammar.
    for (args, needle) in [
        (vec!["--set", "ipv4.ttl"], "path=value"),
        (vec!["--set", "=7"], "empty path"),
        (vec!["--set", "ipv4.ttl="], "empty value"),
        (vec!["--set", "ipv4=7"], "<kind>.<field>"),
        (vec!["--set", "nope.ttl=7"], "unknown layer"),
        (vec!["--set", "ipv4.bogus=7"], "unknown field"),
        (vec!["--set", "ipv4.ttl=abc"], "bad --set"),
        (vec!["--set", "ipv4.ttl=999"], "out of range"),
        (vec!["--set", "tcp.flags.syn=yes", GOLDEN], "bad --set"),
        (vec!["--set", "ipv4.ttl=wire:zz"], "bad --set"),
    ] {
        let (code, stderr) = patch_err(&args);
        assert_eq!(code, 2, "{args:?}");
        assert!(stderr.contains(needle), "{args:?}: {stderr}");
    }
    // --insert / --delete grammar.
    for (args, needle) in [
        (vec!["--insert", "14"], "AT:HEX"),
        (vec!["--insert", "x:aabb"], "bad --insert"),
        (vec!["--insert", "14:zz"], "bad --insert"),
        (vec!["--insert", "14:"], "empty --insert"),
        (vec!["--delete", "14"], "AT:LEN"),
        (vec!["--delete", "x:2"], "bad --delete"),
        (vec!["--delete", "14:0"], "zero-length"),
    ] {
        let (code, stderr) = patch_err(&args);
        assert_eq!(code, 2, "{args:?}");
        assert!(stderr.contains(needle), "{args:?}: {stderr}");
    }
    // --index grammar.
    for (args, needle) in [
        (vec!["--index", "0", GOLDEN], "1-based"),
        (vec!["--index", "5-3", GOLDEN], "reversed"),
        (vec!["--index", "x", GOLDEN], "bad --index"),
        (vec!["--index", "", GOLDEN], "empty"),
    ] {
        let (code, stderr) = patch_err(&args);
        assert_eq!(code, 2, "{args:?}");
        assert!(stderr.contains(needle), "{args:?}: {stderr}");
    }
    // bad filter / format.
    let (code, stderr) = patch_err(&["--filter", "nope", GOLDEN]);
    assert_eq!(code, 2);
    assert!(stderr.contains("bad filter term"), "{stderr}");
    let (code, stderr) = patch_err(&["--filter", "nope.x=1", GOLDEN]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown layer"), "{stderr}");
    let (code, stderr) = patch_err(&["--format", "yaml", GOLDEN]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown format"), "{stderr}");
}

#[test]
fn frame_level_errors_exit_1() {
    // a path missing from THIS frame: runtime, named frame.
    let (code, stderr) = patch_err(&["--set", "tcp.dport=80", GOLDEN]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("frame 1: no dissected field at path `tcp.dport`"),
        "{stderr}"
    );
    // width mismatch on a Bytes span: chaddr is a 16-byte region.
    let (code, stderr) = patch_err(&[
        "--set",
        "dhcp.chaddr=hex:aabb",
        "--no-recompute",
        &dhcp_frame_hex(),
    ]);
    assert_eq!(code, 1);
    assert!(stderr.contains("wants 16 bytes, got 2"), "{stderr}");
    // out-of-bounds insert.
    let (code, stderr) = patch_err(&["--insert", "99:aa", GOLDEN]);
    assert_eq!(code, 1);
    assert!(stderr.contains("frame 1:"), "{stderr}");
    // unreadable pcap / bad pcap bytes: runtime.
    let (code, stderr) = patch_err(&["-r", "/nonexistent/x.pcap"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("cannot read"), "{stderr}");
    let dir = tmpdir("badpcap");
    let bad = dir.join("bad.pcap");
    std::fs::write(&bad, b"not a pcap at all").unwrap();
    let (code, stderr) = patch_err(&["-r", bad.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(stderr.contains("patch:"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn index_selection_and_passthrough() {
    let dir = tmpdir("index");
    let src = dir.join("src.pcap");
    let out = dir.join("out.pcap");
    let tcp = tcp_golden();
    write_pcap(&src, &[golden_bytes(), tcp.clone()]);

    // patch frame 1 only: frame 2 passes through byte-identical.
    let (code, stdout) = patch_out(&[
        "-r",
        src.to_str().unwrap(),
        "--index",
        "1",
        "--set",
        "ipv4.ttl=9",
        "-w",
        out.to_str().unwrap(),
        "--format",
        "raw",
    ]);
    assert_eq!(code, 0);
    // the file: 2 records, timestamps preserved.
    let file = wrex_pcap::read(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(file.records.len(), 2);
    assert_eq!(file.records[1].bytes, tcp, "frame 2 passthrough");
    assert_eq!(file.records[0].bytes[22], 9, "frame 1 patched");
    // default scope recomputed frame 1's checksum: dissect clean.
    let v = dissect_json(&file.records[0].bytes);
    assert!(v["anomalies"].as_array().unwrap().is_empty(), "{v}");
    // stdout carries the whole stream, identical to the file records.
    assert_eq!(
        stdout,
        [file.records[0].bytes.clone(), file.records[1].bytes.clone()].concat()
    );
    assert_eq!(
        file.records[0].ts,
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1000)
    );
    assert_eq!(
        file.records[1].ts,
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1001)
    );

    // an index that matches nothing: pure passthrough (data, exit 0).
    let (code, stdout) = patch_out(&[
        "-r",
        src.to_str().unwrap(),
        "--index",
        "7-9",
        "--set",
        "ipv4.ttl=9",
        "--format",
        "raw",
    ]);
    assert_eq!(code, 0);
    assert_eq!(stdout, [golden_bytes(), tcp.clone()].concat());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn filter_selection_and_intersection() {
    let dir = tmpdir("filter");
    let src = dir.join("src.pcap");
    let out = dir.join("out.pcap");
    let tcp = tcp_golden();
    write_pcap(&src, &[golden_bytes(), tcp.clone()]);

    // --filter selects which frames get patched (nothing dropped).
    let (code, stdout) = patch_out(&[
        "-r",
        src.to_str().unwrap(),
        "--filter",
        "tcp.dport=80",
        "--set",
        "tcp.window=9999",
        "-w",
        out.to_str().unwrap(),
        "--format",
        "raw",
    ]);
    assert_eq!(code, 0);
    assert_eq!(stdout.len(), golden_bytes().len() + tcp.len());
    assert_eq!(&stdout[..golden_bytes().len()], golden_bytes());
    let file = wrex_pcap::read(&std::fs::read(&out).unwrap()).unwrap();
    let v = dissect_json(&file.records[1].bytes);
    assert_eq!(layer_fields(&v, "tcp")["window"], 9999);

    // both selectors = intersection: index 2 (tcp) + udp filter → no
    // frame matches → pure passthrough.
    let (code, stdout) = patch_out(&[
        "-r",
        src.to_str().unwrap(),
        "--index",
        "2",
        "--filter",
        "udp.dport=5555",
        "--set",
        "ipv4.ttl=9",
        "--format",
        "raw",
    ]);
    assert_eq!(code, 0);
    assert_eq!(stdout, [golden_bytes(), tcp.clone()].concat());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn truncated_record_passthrough_keeps_orig_len() {
    let dir = tmpdir("origlen");
    let src = dir.join("src.pcap");
    let out = dir.join("out.pcap");
    // frame 1: a snaplen-truncated record (10 stored, 100 on the wire);
    // frame 2: the golden, patched.
    let file = std::fs::File::create(&src).unwrap();
    let mut w = wrex_pcap::PcapWriter::new(std::io::BufWriter::new(file)).unwrap();
    w.write_record_orig(std::time::UNIX_EPOCH, &golden_bytes()[..10], 100, 65535)
        .unwrap();
    w.write_record(
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1),
        &golden_bytes(),
        65535,
    )
    .unwrap();
    w.flush().unwrap();

    let (code, _) = patch_out(&[
        "-r",
        src.to_str().unwrap(),
        "--index",
        "2",
        "--set",
        "ipv4.ttl=9",
        "-w",
        out.to_str().unwrap(),
        "--format",
        "hex",
    ]);
    assert_eq!(code, 0);
    let file = wrex_pcap::read(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(file.records.len(), 2);
    // the untouched truncated record keeps its annotation and bytes.
    assert_eq!(file.records[0].orig_len, 100);
    assert_eq!(file.records[0].bytes, golden_bytes()[..10].to_vec());
    // the patched record carries its own length.
    assert_eq!(file.records[1].orig_len, golden_bytes().len() as u32);
    assert_eq!(file.records[1].bytes[22], 9);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pcapng_write_and_format_family() {
    let dir = tmpdir("pcapng");
    let src = dir.join("src.pcap");
    let out = dir.join("out.pcapng");
    write_pcap(&src, &[golden_bytes(), tcp_golden()]);

    // --pcapng -w: the T8b writer; the reader auto-detects it back.
    let stdout = patch_text(&[
        "-r",
        src.to_str().unwrap(),
        "--set",
        "ipv4.ttl=9",
        "-w",
        out.to_str().unwrap(),
        "--pcapng",
        "--format",
        "hex",
    ]);
    let file = wrex_pcap::read(&std::fs::read(&out).unwrap()).unwrap();
    assert!(file.pcapng, "the reader found the SHB");
    assert_eq!(file.records.len(), 2);
    for (rec, line) in file.records.iter().zip(stdout.lines()) {
        assert_eq!(hex::encode(&rec.bytes), line.trim());
        assert_eq!(rec.bytes[22], 9, "patched");
    }

    // jsonl/text dissect the output frames (patched state visible).
    let jsonl = patch_text(&[
        "-r",
        src.to_str().unwrap(),
        "--set",
        "ipv4.ttl=9",
        "--format",
        "jsonl",
    ]);
    assert_eq!(jsonl.lines().count(), 2);
    for line in jsonl.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(layer_fields(&v, "ipv4")["ttl"], 9);
        assert!(v["anomalies"].as_array().unwrap().is_empty(), "{line}");
    }
    let text = patch_text(&[
        "-r",
        src.to_str().unwrap(),
        "--set",
        "ipv4.ttl=9",
        "--format",
        "text",
    ]);
    assert!(text.contains("ttl: 9"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stdin_seed() {
    use std::process::{Command as StdCommand, Stdio};
    let mut child = StdCommand::new(env!("CARGO_BIN_EXE_wrex"))
        .args(["patch", "--set", "ipv4.ttl=7", "--format", "hex"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn wrex patch");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(&golden_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait patch");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let patched = patch_out(&["--set", "ipv4.ttl=7", "--format", "hex", GOLDEN]).1;
    assert_eq!(stdout.as_bytes(), patched.as_slice());
}

/// A dhcp corpus frame with a real options region, as CLI hex.
fn dhcp_frame_hex() -> String {
    let reg = wrex::standard();
    for corpus in wrex_test::corpus::Corpus::load_all() {
        if corpus.name != "dhcp" {
            continue;
        }
        for frame in &corpus.frames {
            let p = wrex_core::dissect::dissect(&reg, &frame.bytes, "auto");
            if p.layers.iter().any(|l| {
                l.kind == "dhcp"
                    && l.fields.contains_key("msg_type")
                    && l.fields.contains_key("sname")
            }) {
                return hex::encode(&frame.bytes);
            }
        }
    }
    panic!("no dhcp corpus frame with msg_type + sname");
}

#[test]
fn wire_escape_and_reencode_regions() {
    let frame = dhcp_frame_hex();
    // The typed grammar cannot speak dhcp's 1-byte option-53 TLV
    // (msg_type is Str behind a 1-byte span): wire: hands the region
    // raw bytes. sname is a ReEncode region: typed presentation bytes,
    // the codec NUL-pads.
    let (code, out) = patch_out(&[
        "--set",
        "dhcp.msg_type=wire:08",
        "--set",
        "dhcp.sname=myserver",
        "--no-recompute",
        "--format",
        "raw",
        &frame,
    ]);
    assert_eq!(code, 0);
    let v = dissect_json(&out);
    let dhcp = layer_fields(&v, "dhcp");
    assert_eq!(dhcp["msg_type"], "inform");
    assert_eq!(dhcp["sname"], "myserver");

    // the typed grammar pointedly refuses what it cannot encode: a
    // Str field over a raw span (the presentation is not the wire).
    let (code, stderr) = patch_err(&["--set", "dhcp.msg_type=inform", "--no-recompute", &frame]);
    assert_eq!(code, 1);
    assert!(stderr.contains("wire:HEX"), "{stderr}");
}

#[test]
fn identity_self_value_and_normalize_degenerates() {
    // self-value edit under preserve semantics: byte-identity.
    let (code, out) = patch_out(&[
        "--set",
        "udp.dport=5555",
        "--no-recompute",
        "--format",
        "raw",
        GOLDEN,
    ]);
    assert_eq!(code, 0);
    assert_eq!(out, golden_bytes());

    // zero edits + --no-recompute: pure passthrough (the T11a
    // degenerate).
    let (code, out) = patch_out(&["--no-recompute", "--format", "raw", GOLDEN]);
    assert_eq!(code, 0);
    assert_eq!(out, golden_bytes());

    // zero edits + default scope = normalize: build a stale frame,
    // re-derive everything, dissect comes back clean with the edit
    // kept.
    let stale = patch_out(&[
        "--set",
        "ipv4.ttl=7",
        "--no-recompute",
        "--format",
        "raw",
        GOLDEN,
    ])
    .1;
    let v = dissect_json(&stale);
    assert!(!v["anomalies"].as_array().unwrap().is_empty(), "setup");
    let (code, normalized) = patch_out(&["--format", "raw", &hex::encode(&stale)]);
    assert_eq!(code, 0);
    let v = dissect_json(&normalized);
    assert!(v["anomalies"].as_array().unwrap().is_empty(), "{v}");
    assert_eq!(layer_fields(&v, "ipv4")["ttl"], 7, "the edit survives");
}

#[test]
fn dissect_frame_opt_in() {
    let golden = golden_bytes();
    // --frame: json gains the top-level frame key (the input bytes).
    let text = dissect_text(&golden, &["--frame", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["frame"], GOLDEN);
    // default json: byte-identical pinned shape, no frame key.
    let plain = dissect_text(&golden, &["--format", "json"]);
    let pv: serde_json::Value = serde_json::from_str(&plain).unwrap();
    assert!(pv.get("frame").is_none());
    assert_eq!(pv["layers"], v["layers"]);
    assert_eq!(pv["payload_hex"], v["payload_hex"]);
    // jsonl rides the same object; text adds a frame line.
    let line = dissect_text(&golden, &["--frame", "--format", "jsonl"]);
    let lv: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(lv["frame"], GOLDEN);
    let t = dissect_text(&golden, &["--frame"]);
    assert!(
        t.contains(&format!("frame ({} bytes): {GOLDEN}", golden.len())),
        "{t}"
    );
    let t_plain = dissect_text(&golden, &[]);
    assert!(!t_plain.contains("frame ("), "{t_plain}");
    // composes with --spans.
    let both = dissect_text(&golden, &["--frame", "--spans"]);
    assert!(
        both.contains("frame (") && both.contains("spans:"),
        "{both}"
    );
}
