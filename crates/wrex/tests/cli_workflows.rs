//! Executable golden workflows (HP3-c): every `Today:` incantation of
//! the [use-case catalog](../../docs/usecases.md) runs here end-to-end
//! — documentation cannot lie: every documented command is a command
//! CI actually runs. `WF-n` runs `UC-n`'s pipeline.
//!
//! Offline workflows run per-commit; driver-dependent ones are
//! env-gated (`WREX_DRIVER_TESTS=1`, the same harness the driver
//! suites use — the recorded recommendation for the open decision
//! #10 at the 2026-10-23 extension pass).
//!
//! Spawns the `wrex` binary (and local stub servers): ignored under
//! Miri.
#![cfg_attr(miri, ignore = "spawns the wrex binary; not Miri-safe")]

use std::io::Write as _;

use assert_cmd::Command;
use wrex_test::corpus::Corpus;

fn wrex() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wrex"))
}

fn driver_tests_enabled() -> bool {
    std::env::var("WREX_DRIVER_TESTS").as_deref() == Ok("1") && wrex_test::loopback_ready(false)
}

fn tmpdir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("wrex-wf-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn corpus_frames(name: &str) -> Vec<Vec<u8>> {
    let corpora = Corpus::load_all();
    let c = corpora
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("corpus {name}"));
    c.frames.iter().map(|f| f.bytes.clone()).collect()
}

/// A classic pcap on disk built from frames (the capture verb's own
/// writer lineage, driven from the dev-dep — the test's input file).
fn write_pcap(path: &std::path::Path, frames: &[Vec<u8>]) {
    let file = std::fs::File::create(path).expect("create pcap");
    let mut w = wrex_pcap::PcapWriter::new(std::io::BufWriter::new(file)).expect("writer");
    for (i, f) in frames.iter().enumerate() {
        let ts = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1000 + i as u64);
        w.write_record(ts, f, 65535).expect("write");
    }
    w.flush().expect("flush");
}

fn stdout_of(cmd: &mut Command) -> String {
    let out = cmd.assert().success().get_output().clone();
    String::from_utf8_lossy(&out.stdout).to_string()
}

// ---------------------------------------------------------------------------
// Offline workflows (per-commit)
// ---------------------------------------------------------------------------

/// **UC-11 / WF-11**: "Does my weird capture file parse?" — every
/// foreign fixture (text2pcap/editcap lineage: all four classic magics
/// + pcapng) replays as jsonl.
#[test]
fn wf11_foreign_captures_parse() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../wrex-test/corpus/foreign");
    let mut files = 0;
    for name in [
        "classic_le.pcap",
        "classic_be.pcap",
        "classic_le_ns.pcap",
        "classic_be_ns.pcap",
        "pcapng_le.pcapng",
    ] {
        let path = dir.join(name);
        let out = stdout_of(wrex().args(["replay", path.to_str().unwrap(), "--format", "jsonl"]));
        let lines = out.lines().count();
        assert!(lines >= 3, "{name}: {lines} frames");
        files += 1;
    }
    assert_eq!(files, 5, "every foreign fixture replays");
}

/// **UC-12 / WF-12**: "Reassemble fragments in a capture" — the frag
/// corpus's v4 pair consumed into one reassembled datagram.
#[test]
fn wf12_reassemble_a_capture() {
    let dir = tmpdir("12");
    let pcap = dir.join("cap.pcap");
    // frames 01/02: the v4 fragment pair (01 bin = wire-honest frag0
    // since the HP3-a corpus regeneration).
    write_pcap(&pcap, &corpus_frames("frag")[..2]);
    let plain = stdout_of(wrex().args(["replay", pcap.to_str().unwrap(), "--format", "jsonl"]));
    assert_eq!(plain.lines().count(), 2, "both fragments print by default");
    let out = stdout_of(wrex().args([
        "replay",
        pcap.to_str().unwrap(),
        "--reassemble",
        "--format",
        "jsonl",
    ]));
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 1, "fragments consumed into one datagram");
    assert!(
        lines[0].contains("\"udp\""),
        "the reassembled L4 dissects: {lines:?}"
    );
}

/// **UC-14 / WF-14**: "Build an exact frame by hand" — `fields` for
/// discovery, then craft → dissect (the offline half; the send half
/// is the env-gated wf14 companion).
#[test]
fn wf14_craft_by_hand() {
    let fields = stdout_of(wrex().args(["fields", "tcp"]));
    assert!(fields.contains("flags"), "discovery lists fields: {fields}");
    let frame = stdout_of(wrex().args([
        "craft",
        "--format",
        "hex",
        "--layer",
        "eth",
        "--layer",
        "ipv4",
        "--layer",
        "tcp",
        "--ipv4-src=127.0.0.1",
        "--ipv4-dst=127.0.0.1",
        "--tcp-sport=4444",
        "--tcp-dport=80",
    ]));
    let hex = frame.trim();
    assert_eq!(hex.len(), 14 * 2 + 20 * 2 + 20 * 2, "eth+ipv4+tcp bytes");
    let out = stdout_of(
        wrex()
            .args(["dissect", "--format", "json"])
            .write_stdin(hex::decode(hex).expect("hex")),
    );
    assert!(out.contains("\"tcp\""), "the crafted frame dissects: {out}");
}

/// **UC-15 / WF-15**: "Rewrite a captured stream onto new ports,
/// replay it" — patch --filter --set -w, then the edited pcap
/// re-dissects with the new port (the offline half; `replay -i` is
/// the env-gated companion).
#[test]
fn wf15_rewrite_a_stream() {
    let dir = tmpdir("15");
    let cap = dir.join("cap.pcap");
    write_pcap(&cap, &corpus_frames("tcp"));
    let edited = dir.join("edited.pcap");
    stdout_of(wrex().args([
        "patch",
        "-r",
        cap.to_str().unwrap(),
        "--filter",
        "tcp.dport=19",
        "--set",
        "tcp.dport=8080",
        "-w",
        edited.to_str().unwrap(),
    ]));
    let out = stdout_of(wrex().args(["replay", edited.to_str().unwrap(), "--format", "jsonl"]));
    // every frame passed through (byte-identical passthrough is
    // pinned by the patch_cli suite; here the count must hold).
    assert_eq!(out.lines().count(), corpus_frames("tcp").len());
    // the edited frames carry the new port with a healed checksum;
    // the unselected ones pass through verbatim — a real capture, its
    // pre-existing wrong checksums deliberately stay wrong (the T11a
    // corpus contract).
    let edited: Vec<&str> = out.lines().filter(|l| l.contains("8080")).collect();
    assert!(!edited.is_empty(), "the edited port is on the wire: {out}");
    for line in &edited {
        assert!(
            !line.contains("mismatch"),
            "the edited frame's checksum re-derived: {line}"
        );
    }
}

/// **UC-16 / WF-16**: "Fix/normalize a broken capture" — zero edits +
/// default scope IS the normalize verb.
#[test]
fn wf16_normalize_a_capture() {
    let dir = tmpdir("16");
    let cap = dir.join("cap.pcap");
    write_pcap(&cap, &corpus_frames("udp"));
    let fixed = dir.join("fixed.pcap");
    stdout_of(wrex().args([
        "patch",
        "-r",
        cap.to_str().unwrap(),
        "-w",
        fixed.to_str().unwrap(),
    ]));
    let out = stdout_of(wrex().args(["replay", fixed.to_str().unwrap(), "--format", "jsonl"]));
    assert_eq!(out.lines().count(), corpus_frames("udp").len());
    assert!(
        !out.contains("mismatch"),
        "normalized capture is anomaly-free: {out}"
    );
}

/// **UC-17 / WF-17**: "Send deliberately-stale checksums" —
/// `--no-recompute` keeps the original checksum after an edit.
#[test]
fn wf17_stale_checksums_by_choice() {
    let frames = corpus_frames("tcp");
    let seed = hex::encode(&frames[0]);
    let out = stdout_of(wrex().args([
        "patch",
        "--set",
        "tcp.window=512",
        "--no-recompute",
        "--format",
        "hex",
        &seed,
    ]));
    let patched = out.trim();
    assert_ne!(patched, seed, "the window edit landed");
    let dissect = stdout_of(
        wrex()
            .args(["dissect", "--format", "text"])
            .write_stdin(hex::decode(patched).expect("hex")),
    );
    assert!(
        dissect.contains("mismatch"),
        "the stale checksum is carried unhealed: {dissect}"
    );
}

/// **UC-18 / WF-18**: "Show where this field physically lives" —
/// `dissect --spans --format json` emits the wire geometry.
#[test]
fn wf18_field_geometry() {
    let frames = corpus_frames("tcp");
    let out = stdout_of(
        wrex()
            .args(["dissect", "--spans", "--format", "json"])
            .write_stdin(frames[0].clone()),
    );
    assert!(out.contains("\"spans\""), "per-layer span maps: {out}");
    assert!(out.contains("\"payload_span\""), "the payload tail: {out}");
}

/// **UC-19 / WF-19**: "Edit a shared DNS pointer-target" — a
/// `wire:` patch on the compressed answer name rewrites the shared
/// target in place; every alias through the pointer sees it.
#[test]
fn wf19_edit_a_shared_pointer_target() {
    // The dns corpus reply frame: its answer name is a compression
    // pointer to the question at offset 12 (example.com), so the
    // patch target is the SHARED region — the tranche-13a re-attach.
    let frame = corpus_frames("dns")[1].clone();
    let seed = hex::encode(&frame);
    // example.net — a same-width wire name (13 bytes) replacing the
    // shared target.
    let wire = "076578616d706c65036e657400";
    let out = stdout_of(wrex().args([
        "patch",
        "--set",
        &format!("dns.an.0.name=wire:{wire}"),
        "--format",
        "hex",
        &seed,
    ]));
    let patched = hex::decode(out.trim()).expect("hex");
    let dissect = stdout_of(
        wrex()
            .args(["dissect", "--format", "text"])
            .write_stdin(patched),
    );
    assert!(
        dissect.contains("example.net"),
        "the target rewrite is visible through the pointer: {dissect}"
    );
    assert!(
        !dissect.contains("example.com"),
        "the old name is gone everywhere (aliases included): {dissect}"
    );
}

/// **UC-20 / WF-20**: "Mutate this seed offline, deterministically."
#[test]
fn wf20_deterministic_mutation() {
    let frames = corpus_frames("tcp");
    let seed = hex::encode(&frames[0]);
    let a = stdout_of(wrex().args(["mut", "--count", "8", "--seed", "42", &seed]));
    assert_eq!(a.lines().count(), 8, "one hex line per mutant");
    let b = stdout_of(wrex().args(["mut", "--count", "8", "--seed", "42", &seed]));
    assert_eq!(a, b, "same seed reproduces the mutant stream");
}

/// **UC-22 / WF-22**: "Diff two probe runs" — outcome deltas between a
/// baseline and a mutated run.
#[test]
fn wf22_diff_two_runs() {
    let dir = tmpdir("22");
    let baseline = dir.join("baseline.jsonl");
    let mutated = dir.join("mutated.jsonl");
    std::fs::write(
        &baseline,
        concat!(
            "{\"target\":\"127.0.0.1\",\"port\":5000,\"proto\":\"udp\",\"round\":null,",
            "\"outcome\":\"reply\",\"probe_hex\":\"00\",\"reply_hex\":\"aa\"}\n",
        ),
    )
    .unwrap();
    std::fs::write(
        &mutated,
        concat!(
            "{\"target\":\"127.0.0.1\",\"port\":5000,\"proto\":\"udp\",\"round\":null,",
            "\"outcome\":\"silence\",\"probe_hex\":\"00\"}\n",
        ),
    )
    .unwrap();
    let out = stdout_of(wrex().args([
        "diff",
        baseline.to_str().unwrap(),
        mutated.to_str().unwrap(),
    ]));
    assert!(
        out.contains("reply") && out.contains("silence"),
        "the outcome delta renders: {out}"
    );
    // json format for tooling.
    let js = stdout_of(wrex().args([
        "diff",
        "--format",
        "json",
        baseline.to_str().unwrap(),
        mutated.to_str().unwrap(),
    ]));
    let v: serde_json::Value = serde_json::from_str(&js).expect("json array");
    assert!(v.as_array().is_some_and(|a| !a.is_empty()), "{js}");
}

/// A plain TCP stub (the http suite's pattern): accept, read, respond —
/// one fresh connection per exchange (the wf25 test replays the recipe
/// against the same stub repeatedly).
fn spawn_http_stub(response: &'static [u8]) -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { break };
            let mut buf = [0u8; 4096];
            let _ = std::io::Read::read(&mut conn, &mut buf);
            let _ = conn.write_all(response);
        }
    });
    port
}

/// **UC-25 / WF-25**: "Reproduce an API exchange byte-exactly in CI" —
/// a recipe against the stub, byte-identical replay.
#[test]
fn wf25_recipe_replay() {
    let port = spawn_http_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let dir = tmpdir("25");
    let recipe = dir.join("req.json");
    std::fs::write(
        &recipe,
        format!(r#"{{"method": "GET", "url": "http://127.0.0.1:{port}/api"}}"#),
    )
    .unwrap();
    let a = stdout_of(wrex().args([
        "http",
        "--recipe",
        recipe.to_str().unwrap(),
        "--format",
        "json",
    ]));
    let b = stdout_of(wrex().args([
        "http",
        "--recipe",
        recipe.to_str().unwrap(),
        "--format",
        "json",
    ]));
    assert_eq!(a, b, "recipe replay is byte-identical");
    assert!(a.contains("200"), "status renders: {a}");
    // a fresh stub for the second run (one connection per exchange).
    let port2 = spawn_http_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    std::fs::write(
        &recipe,
        format!(r#"{{"method": "GET", "url": "http://127.0.0.1:{port2}/api"}}"#),
    )
    .unwrap();
    let c = stdout_of(wrex().args([
        "http",
        "--recipe",
        recipe.to_str().unwrap(),
        "--format",
        "json",
    ]));
    assert_eq!(a, c, "byte-identical across stub instances too");
}

/// **UC-23 / WF-23**: "Fuzz a TLS-wrapped service" — app-mode probes
/// over fresh TLS connections against the in-test rustls stub (plain
/// sockets, no capabilities — the same stub the fuzz_cli suite uses).
#[test]
fn wf23_fuzz_a_tls_service() {
    use wrex_test::tls_stub::{StubRequest, TlsStub};
    const RESPONSE: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok";
    let stub: TlsStub = wrex_test::tls_stub::spawn(RESPONSE.to_vec(), 2, 16, StubRequest::HttpHead);
    let port = stub.addr.port().to_string();
    let out = stdout_of(wrex().args([
        "fuzz",
        "--mode",
        "http",
        "--ports",
        &port,
        "--tls",
        "--tls-insecure",
        "--baseline",
        "--rounds",
        "4",
        "--retries",
        "0",
        "--timeout",
        "2s",
        "--rate",
        "0",
        "--seed",
        "42",
        "--format",
        "jsonl",
        "127.0.0.1",
    ]));
    assert!(
        out.lines().all(|l| l.contains("\"proto\":\"http\"")),
        "one http finding per probe: {out}"
    );
    assert!(
        out.contains("reply"),
        "the stub's replies are recorded: {out}"
    );
}

// ---------------------------------------------------------------------------
// Driver-dependent workflows (env-gated: WREX_DRIVER_TESTS=1)
// ---------------------------------------------------------------------------

/// **UC-2 / WF-2**: "What's listening on this host?" — scan against a
/// bound TCP listener: open.
#[test]
fn wf02_scan_for_listeners() {
    if !driver_tests_enabled() {
        eprintln!("wf02: skipping (WREX_DRIVER_TESTS != 1)");
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port().to_string();
    std::thread::spawn(move || {
        let _ = listener.accept();
    });
    let out = stdout_of(wrex().args([
        "scan",
        "-i",
        "lo",
        "--ports",
        &port,
        "--seed",
        "42",
        "--timeout",
        "1s",
        "127.0.0.1",
    ]));
    assert!(out.contains("open"), "the listener is found: {out}");
}

/// **UC-7 / WF-7**: "Capture this interface, inspect later" —
/// capture under live traffic, then replay the capture.
#[test]
fn wf07_capture_then_inspect() {
    if !driver_tests_enabled() {
        eprintln!("wf07: skipping (WREX_DRIVER_TESTS != 1)");
        return;
    }
    let dir = tmpdir("07");
    let cap = dir.join("cap.pcap");
    // Live traffic: a concurrent wrex send onto lo while capture runs.
    let cap_path = cap.to_string_lossy().to_string();
    let mut capture = std::process::Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args(["capture", "-i", "lo", "-w", &cap_path, "--timeout", "2s"])
        .spawn()
        .expect("spawn capture");
    std::thread::sleep(std::time::Duration::from_millis(200));
    let _ = wrex()
        .args([
            "send",
            "-i",
            "lo",
            "--layer",
            "eth",
            "--layer",
            "ipv4",
            "--layer",
            "udp",
            "--ipv4-src=127.0.0.1",
            "--ipv4-dst=127.0.0.1",
            "--udp-sport=1",
            "--udp-dport=2",
            "--payload=hex:aa",
        ])
        .output();
    let status = capture.wait().expect("wait capture");
    assert!(status.success(), "capture exit");
    let out = stdout_of(wrex().args(["replay", &cap_path, "--format", "jsonl"]));
    assert!(
        out.lines().any(|l| l.contains("\"udp\"")),
        "the captured traffic inspects: {out}"
    );
}

/// **UC-14 / WF-14 (send half)**: the crafted frame goes onto the
/// wire and a concurrent recv sees it.
#[test]
fn wf14_send_the_frame() {
    if !driver_tests_enabled() {
        eprintln!("wf14 send: skipping (WREX_DRIVER_TESTS != 1)");
        return;
    }
    let recv = std::process::Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "recv",
            "-i",
            "lo",
            "--count",
            "1",
            "--format",
            "jsonl",
            "--filter",
            "udp.dport=5999",
        ])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn recv");
    std::thread::sleep(std::time::Duration::from_millis(200));
    let _ = wrex()
        .args([
            "send",
            "-i",
            "lo",
            "--layer",
            "eth",
            "--layer",
            "ipv4",
            "--layer",
            "udp",
            "--ipv4-src=127.0.0.1",
            "--ipv4-dst=127.0.0.1",
            "--udp-sport=4444",
            "--udp-dport=5999",
            "--payload=hex:bb",
        ])
        .output();
    let out = recv.wait_with_output().expect("recv output");
    assert!(out.status.success(), "recv exit: {out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("\"udp\""),
        "the sent frame is observed on the wire: {text}"
    );
}

/// **UC-21 / WF-21**: "Probe a service with mutated frames, record
/// every outcome" — baseline + rounds against a bound responder.
#[test]
fn wf21_probe_a_service() {
    if !driver_tests_enabled() {
        eprintln!("wf21: skipping (WREX_DRIVER_TESTS != 1)");
        return;
    }
    // A UDP responder on lo.
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    let port = sock.local_addr().unwrap().port().to_string();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        if let Ok((n, peer)) = sock.recv_from(&mut buf) {
            let _ = sock.send_to(&buf[..n], peer);
        }
    });
    let out = stdout_of(wrex().args([
        "fuzz",
        "-i",
        "lo",
        "--mode",
        "udp",
        "--ports",
        &port,
        "--baseline",
        "--rounds",
        "4",
        "--seed",
        "42",
        "--timeout",
        "1s",
        "--format",
        "jsonl",
        "127.0.0.1",
    ]));
    assert!(
        out.contains("reply"),
        "the responder's replies are recorded: {out}"
    );
}

/// **UC-24 / WF-24 (replay half)**: the mutated corpus re-sent onto
/// the wire verbatim.
#[test]
fn wf24_replay_the_probe_corpus() {
    if !driver_tests_enabled() {
        eprintln!("wf24 replay: skipping (WREX_DRIVER_TESTS != 1)");
        return;
    }
    let dir = tmpdir("24");
    let cap = dir.join("prod.pcap");
    write_pcap(&cap, &corpus_frames("udp"));
    let probes = dir.join("probes.pcap");
    stdout_of(wrex().args([
        "mut",
        "-r",
        cap.to_str().unwrap(),
        "--strategy",
        "all",
        "--count",
        "16",
        "--seed",
        "7",
        "-w",
        probes.to_str().unwrap(),
    ]));
    // Verbatim re-send: the exit is the contract (frames on the wire).
    let out = wrex()
        .args([
            "replay",
            "-i",
            "lo",
            "--rate",
            "50",
            probes.to_str().unwrap(),
        ])
        .output()
        .expect("spawn replay");
    assert!(out.status.success(), "replay -i exit: {out:?}");
}
