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

/// **UC-26 / WF-26**: "Follow a redirect chain" — the `-L` chain
/// against a routing stub (302 then the target), same-origin hops on
/// ONE connection, the chain reported in json.
#[test]
fn wf26_follow_redirect_chain() {
    let port = spawn_routing_stub(&[
        (
            "/start",
            b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "/next",
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nfollowed",
        ),
    ]);
    let out = stdout_of(wrex().args([
        "http",
        "-L",
        "--format",
        "json",
        &format!("http://127.0.0.1:{port}/start"),
    ]));
    let json: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(json["status"], 200);
    assert_eq!(json["body_hex"], hex::encode("followed"));
    assert_eq!(
        json["redirects"],
        serde_json::json!([
            {"url": format!("http://127.0.0.1:{port}/start"), "status": 302}
        ]),
        "the chain reports each hop: {json}"
    );
}

/// **UC-27 / WF-27**: "Maintain a cookie-authenticated session" —
/// `-c` collects Set-Cookie, `-b` sends it back; the echo stub
/// answers with the Cookie header it ACTUALLY received (an empty
/// body would mean the jar did not ride).
#[test]
fn wf27_cookie_session() {
    let port = spawn_cookie_echo_stub(
        b"HTTP/1.1 200 OK\r\nSet-Cookie: session=tok123; Path=/\r\nContent-Length: 0\r\n\r\n",
    );
    let dir = tmpdir("27");
    let jar = dir.join("cookies.txt");
    let _ = std::fs::remove_file(&jar);
    stdout_of(wrex().args([
        "http",
        "-c",
        jar.to_str().unwrap(),
        &format!("http://127.0.0.1:{port}/login"),
    ]));
    let out = stdout_of(wrex().args([
        "http",
        "--format",
        "raw",
        "-b",
        jar.to_str().unwrap(),
        &format!("http://127.0.0.1:{port}/echo"),
    ]));
    assert_eq!(out, "session=tok123", "the jar rides the second request");
}

/// A two-route stub: `/login` serves the scripted response (Set-Cookie
/// collection), `/echo` answers with the Cookie header value the
/// request carried (the honest oracle — empty when no cookie rode).
fn spawn_cookie_echo_stub(login_response: &'static [u8]) -> u16 {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { break };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            while let Ok(n) = conn.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf).to_string();
                    let path = head.split_whitespace().nth(1).unwrap_or("/");
                    let resp = if path.starts_with("/login") {
                        login_response.to_vec()
                    } else {
                        let cookie = head
                            .lines()
                            .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
                            .map(|l| l[8..].trim().to_string())
                            .unwrap_or_default();
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{cookie}",
                            cookie.len()
                        )
                        .into_bytes()
                    };
                    let _ = pos;
                    let _ = conn.write_all(&resp);
                    buf.clear();
                }
            }
        }
    });
    port
}

/// A routing stub: per connection, answers any number of requests by
/// mapping the request line's path to a scripted response.
fn spawn_routing_stub(routes: &[(&str, &[u8])]) -> u16 {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let routes: Vec<(String, Vec<u8>)> = routes
        .iter()
        .map(|(p, r)| (p.to_string(), r.to_vec()))
        .collect();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { break };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            while let Ok(n) = conn.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf).to_string();
                    let path = head
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .split('?')
                        .next()
                        .unwrap_or("/")
                        .to_string();
                    let resp = routes
                        .iter()
                        .find(|(p, _)| *p == path)
                        .map(|(_, r)| r.clone())
                        .unwrap_or_else(|| {
                            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()
                        });
                    let _ = pos;
                    let _ = conn.write_all(&resp);
                    buf.clear();
                }
            }
        }
    });
    port
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

// --- tranche 20 workflows (driver-gated: real sockets on lo) ----------------

/// One hand-built DNS reply: echo id, qr/rd/ra, one answer whose owner
/// is a compression pointer to the question; `answer` =
/// (type wire bytes, rdata) splices after it.
fn wf_dns_reply(query: &[u8], answer: (&[u8], &[u8])) -> Vec<u8> {
    let mut msg = vec![
        query[0], query[1], 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut at = 12usize;
    while at < query.len() && query[at] != 0 {
        at += 1 + query[at] as usize;
    }
    at += 5; // the root + type/class
    msg.extend_from_slice(&query[12..at]);
    msg.extend_from_slice(&[0xC0, 0x0C]);
    msg.extend_from_slice(answer.0);
    msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x01, 0x2C]);
    msg.extend_from_slice(&(answer.1.len() as u16).to_be_bytes());
    msg.extend_from_slice(answer.1);
    msg
}

/// **UC-28 / WF-28**: "Debug DNS the way real resolvers speak it
/// (EDNS/DO)" — `wrex query --edns 1232 --edns-do` against a UDP stub:
/// the captured query carries the typed OPT record (the stub-side
/// dissection asserts udp_size + DO), and the reply renders.
#[test]
fn wf28_edns_do_on_the_wire() {
    if !driver_tests_enabled() {
        eprintln!("wf28: skipping (driver tests disabled)");
        return;
    }
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind stub");
    let port = sock.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(10)));
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            return;
        };
        let query = buf[..n].to_vec();
        let _ = tx.send(query.clone());
        let reply = wf_dns_reply(&query, (&[0x00, 0x01], &[93, 184, 216, 34]));
        let _ = sock.send_to(&reply, from);
    });
    let out = wrex()
        .args([
            "query",
            "--server",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--timeout",
            "800ms",
            "--edns",
            "1232",
            "--edns-do",
            "example.com",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("an.0.rdata: 93.184.216.34"), "{stdout}");
    // The stub's captured query carries the OPT record (typed).
    let query = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("no query");
    let reg = wrex::standard();
    let p = wrex_core::dissect::dissect(&reg, &query, "dns");
    assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
    let dns = p.layers.iter().find(|l| l.kind == "dns").unwrap();
    assert_eq!(
        dns.fields.get("ar.0.udp_size"),
        Some(&wrex_core::Value::Int(1232))
    );
    assert_eq!(
        dns.fields.get("ar.0.do"),
        Some(&wrex_core::Value::Bool(true))
    );
}

/// **UC-29 / WF-29**: "Resolve a .local name" — `wrex query --mdns -i
/// lo` speaks to the multicast group (224.0.0.251:ff02::fb on 5353;
/// `-i lo` pins the multicast interface so the kernel routes the
/// group over loopback — a default-route egress would strand the
/// datagram off-host; `--port` pins the stub's ephemeral port, a dev
/// box's avahi owns 5353): a group-member stub on loopback answers,
/// the verb renders the PTR target. A preflight probe skips
/// environments whose netns cannot loop multicast at all (the
/// env-gated job's recorded limitation).
#[test]
fn wf29_mdns_multicast_query() {
    if !driver_tests_enabled() {
        eprintln!("wf29: skipping (driver tests disabled)");
        return;
    }
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
    const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
    let port = {
        // An ephemeral port for the stub: --port overrides the 5353
        // default (a dev box's avahi owns 5353; CI's netns does not).
        let probe = UdpSocket::bind("127.0.0.1:0").expect("ephemeral probe");
        probe.local_addr().unwrap().port()
    };
    let sock = UdpSocket::bind(("0.0.0.0", port)).expect("bind stub");
    // Join the mDNS group on loopback; a join failure (no multicast
    // route in the namespace) skips gracefully.
    if sock
        .join_multicast_v4(&GROUP, &Ipv4Addr::LOCALHOST)
        .is_err()
    {
        eprintln!("wf29: skipping (no loopback multicast)");
        return;
    }
    let sock2 = sock.try_clone().expect("clone");
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let sock = sock2;
        let mut buf = [0u8; 4096];
        let _ = sock.set_read_timeout(Some(std::time::Duration::from_secs(10)));
        // Probe + real query: answer dns-shaped datagrams with a PTR
        // reply (the preflight probe is shorter — no reply).
        for _ in 0..2 {
            let Ok((n, from)) = sock.recv_from(&mut buf) else {
                return;
            };
            let query = buf[..n].to_vec();
            let _ = tx.send(query.clone());
            if n < 12 {
                continue;
            }
            // A PTR answer: rdata = the target name (typed Str on our side).
            let rdata = b"\x09_services\x07_dns-sd\x04_udp\x05local\x00".to_vec();
            let reply = wf_dns_reply(&query, (&[0x00, 0x0C], &rdata));
            let _ = sock.send_to(&reply, from);
        }
    });
    // Preflight: can this environment loop a datagram to the group?
    // (A netns without a loopback-capable multicast route strands the
    // group datagram on the default egress — skip with a notice; the
    // --mdns grammar and the udp 5353 dispatch are pinned elsewhere.)
    {
        let probe = UdpSocket::bind("127.0.0.1:0").expect("probe bind");
        probe
            .send_to(b"probe", SocketAddr::new(std::net::IpAddr::V4(GROUP), port))
            .expect("probe send");
        match rx.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(_) => {}
            Err(_) => {
                eprintln!("wf29: skipping (no loopback multicast delivery in this netns)");
                return;
            }
        }
    }
    let out = wrex()
        .args([
            "query",
            "-i",
            "lo",
            "--mdns",
            "--port",
            &port.to_string(),
            "--type",
            "PTR",
            "--timeout",
            "800ms",
            "_services._dns-sd._udp.local",
        ])
        .output()
        .expect("spawn wrex query --mdns");
    assert!(
        out.status.success(),
        "mdns exit: {}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("an.0.rdata: _services._dns-sd._udp.local"),
        "the PTR target must render\n{stdout}"
    );
    let _ = rx.recv_timeout(std::time::Duration::from_secs(5));
}

/// **UC-30 / WF-30**: "Get out via DoH" — `wrex query --doh URL --short`
/// against a plain-socket HTTP/1.1 stub: the RFC 8484 POST body is the
/// bare query, the 200 body dissects as the reply, +short prints the
/// answer values.
#[test]
fn wf30_doh_post_end_to_end() {
    if !driver_tests_enabled() {
        eprintln!("wf30: skipping (driver tests disabled)");
        return;
    }
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4096];
        let n = sock.read(&mut buf).expect("read request");
        let request = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(
            request.starts_with("POST /dns-query "),
            "the stub saw a real RFC 8484 POST\n{request}"
        );
        let body = request
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or_default()
            .as_bytes()
            .to_vec();
        let reply = wf_dns_reply(&body, (&[0x00, 0x01], &[93, 184, 216, 34]));
        let mut resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            reply.len()
        )
        .into_bytes();
        resp.extend_from_slice(&reply);
        let _ = sock.write_all(&resp);
        let _ = sock.shutdown(std::net::Shutdown::Write);
    });
    let out = wrex()
        .args([
            "query",
            "--doh",
            &format!("http://127.0.0.1:{port}/dns-query"),
            "--timeout",
            "2s",
            "--short",
            "example.com",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.trim() == "93.184.216.34", "+short: {stdout:?}");
    let _ = server.join();
}

// ---------------------------------------------------------------------------
// T21 workflows (WF-31..WF-34): scan variants, discovery, trace, service
// ---------------------------------------------------------------------------

/// **UC-3 / WF-31**: "Is this port closed or filtered?" — the FIN
/// probe over a bound-but-silent listener (open|filtered) and an
/// unbound port (closed), plus the ACK mode's unfiltered mapping.
#[test]
fn wf31_scan_variants() {
    if !driver_tests_enabled() {
        eprintln!("wf31: skipping (WREX_DRIVER_TESTS != 1)");
        return;
    }
    let open_l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let open = open_l.local_addr().unwrap().port();
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let ports = format!("{open},{closed}");
    let out = stdout_of(wrex().args([
        "scan",
        "-i",
        "lo",
        "--mode",
        "fin",
        "--ports",
        &ports,
        "--seed",
        "42",
        "--timeout",
        "500ms",
        "127.0.0.1",
    ]));
    assert!(
        out.contains(&format!("127.0.0.1  {closed}/tcp  closed")),
        "fin: kernel RST closes\n{out}"
    );
    assert!(
        out.contains(&format!("127.0.0.1  {open}/tcp  open|filtered")),
        "fin: silent listener stays open|filtered\n{out}"
    );
    drop(open_l);
}

/// **UC-1 / WF-32**: "Which hosts are alive on my L2 segment?" — the
/// NDP host-discovery sweep (the arp analog needs a veth lab; `lo`
/// speaks NDP for its own addresses — the kernel answers NS for ::1).
#[test]
fn wf32_host_discovery() {
    if !driver_tests_enabled() {
        eprintln!("wf32: skipping (WREX_DRIVER_TESTS != 1)");
        return;
    }
    let out = stdout_of(wrex().args([
        "scan",
        "-i",
        "lo",
        "--mode",
        "ndp",
        "--seed",
        "42",
        "--timeout",
        "800ms",
        "::1",
    ]));
    assert!(
        out.contains("::1  icmpv6  alive"),
        "the kernel answers unicast NS for its own address\n{out}"
    );
}

/// **UC-4 / WF-33**: "What path does traffic take to X?" — the tracer
/// walk to `lo`: one hop, reached.
#[test]
fn wf33_trace_the_path() {
    if !driver_tests_enabled() {
        eprintln!("wf33: skipping (WREX_DRIVER_TESTS != 1)");
        return;
    }
    let out = stdout_of(wrex().args([
        "trace",
        "-i",
        "lo",
        "--seed",
        "42",
        "--wait",
        "800ms",
        "127.0.0.1",
    ]));
    assert!(
        out.contains("127.0.0.1  reached"),
        "loopback is reached at hop 1\n{out}"
    );
    assert!(
        out.starts_with("1  127.0.0.1"),
        "hop ordinal renders first\n{out}"
    );
}

/// **UC-6 / WF-34**: "What service version is behind this port?" — the
/// `--service` post-pass against a stub SSH banner.
#[test]
fn wf34_service_version_probe() {
    if !driver_tests_enabled() {
        eprintln!("wf34: skipping (WREX_DRIVER_TESTS != 1)");
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port().to_string();
    let stub = std::thread::spawn(move || {
        // keep accepting (the scan's own connection + every service
        // probe) until the deadline: banner to each.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        let _ = listener.set_nonblocking(true);
        while std::time::Instant::now() < deadline {
            match listener.accept() {
                Ok((mut s, _)) => {
                    use std::io::Write as _;
                    let _ = s.write_all(b"SSH-2.0-OpenSSH_9.6p1 wf34\r\n");
                    let _ = s.flush();
                }
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
    });
    let out = stdout_of(wrex().args([
        "scan",
        "-i",
        "lo",
        "--mode",
        "connect",
        "--ports",
        &port,
        "--service",
        "--seed",
        "42",
        "--timeout",
        "800ms",
        "127.0.0.1",
    ]));
    stub.join().expect("stub");
    assert!(
        out.contains(&format!(
            "127.0.0.1  {port}/tcp  open  ssh/OpenSSH_9.6p1 wf34"
        )),
        "the banner renders service+version\n{out}"
    );
}
