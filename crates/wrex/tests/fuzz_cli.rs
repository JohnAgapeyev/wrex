//! `wrex fuzz` CLI grammar tests (assert_cmd): every case exercises an
//! exit-2 usage error before any driver opens. Real-socket ground truth
//! lives in `fuzz_driver.rs` (env-gated `WREX_DRIVER_TESTS=1`).
//!
//! Spawns the `wrex` binary: ignored under Miri.
#![cfg_attr(miri, ignore = "spawns the wrex binary; not Miri-safe")]

use assert_cmd::Command;

fn wrex() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wrex"))
}

fn fuzz_err(args: &[&str]) -> (i32, String) {
    let out = wrex()
        .args(["fuzz"])
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
fn iface_and_target_grammar_errors() {
    // No -i → usage.
    let (code, stderr) = fuzz_err(&["127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("fuzz requires -i"), "{stderr}");

    // No targets → usage (clap required).
    let out = wrex()
        .args(["fuzz", "-i", "lo"])
        .assert()
        .failure()
        .get_output()
        .clone();
    assert_eq!(out.status.code().unwrap_or(-1), 2);

    // Unknown mode → usage.
    let (code, stderr) = fuzz_err(&["-i", "lo", "--mode", "sctp", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown fuzz mode"), "{stderr}");

    // udp without --ports → usage.
    let (code, stderr) = fuzz_err(&["-i", "lo", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("udp mode requires --ports"), "{stderr}");

    // icmp + --ports → usage.
    let (code, stderr) = fuzz_err(&["-i", "lo", "--mode", "icmp", "--ports", "22", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("takes no --ports"), "{stderr}");

    // rounds 0 without baseline → usage.
    let (code, stderr) = fuzz_err(&["-i", "lo", "--rounds", "0", "--ports", "53", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("--rounds 0"), "{stderr}");

    // --rate + --interval → usage.
    let (code, stderr) = fuzz_err(&[
        "-i",
        "lo",
        "--ports",
        "53",
        "--rate",
        "10",
        "--interval",
        "1s",
        "127.0.0.1",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("mutually exclusive"), "{stderr}");

    // raw/hex formats carry no findings → usage.
    let (code, stderr) = fuzz_err(&["-i", "lo", "--ports", "53", "--format", "raw", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("carry no findings"), "{stderr}");

    // Unknown strategy → usage.
    let (code, stderr) = fuzz_err(&[
        "-i",
        "lo",
        "--ports",
        "53",
        "--strategy",
        "voodoo",
        "127.0.0.1",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown mutation strategy"), "{stderr}");

    // Bad targets → usage.
    let (code, stderr) = fuzz_err(&["-i", "lo", "--ports", "53", "999.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("bad target"), "{stderr}");
}

// --- tranche 9b: application-layer modes ------------------------------------
//
// Plain sockets only (no CAP_NET_RAW, no env gate needed — but not
// Miri-safe: spawns the wrex binary + TCP threads).

/// Tranche-9b ground truth on `lo`: a bound TCP responder records
/// baseline + mutated probe findings, and a pinned seed replays
/// byte-identical probe streams.
#[test]
fn http_mode_findings_against_tcp_stub() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    use std::io::{Read, Write};
    let recorder = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let rec2 = recorder.clone();
    std::thread::spawn(move || {
        for _ in 0..64 {
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match conn.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                }
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            rec2.lock().unwrap().push(buf);
            let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
            let _ = conn.shutdown(std::net::Shutdown::Write);
        }
    });

    let args = [
        "--mode",
        "http",
        "--ports",
        &port.to_string(),
        "--baseline",
        "--rounds",
        "2",
        "--retries",
        "0",
        "--timeout",
        "500ms",
        "--rate",
        "0",
        "--seed",
        "42",
    ];
    let out = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args(["fuzz"])
        .args(args)
        .args(["127.0.0.1"])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let lines: Vec<&str> = stdout.lines().collect();
    // baseline + 2 rounds = 3 findings, one per probe
    assert_eq!(lines.len(), 3, "{stdout}");
    assert!(lines[0].contains("/http"), "{lines:?}");
    assert!(lines[0].contains("baseline"), "{lines:?}");
    assert!(lines[0].contains("reply"), "{lines:?}");
    assert!(lines[1].contains("round 1"), "{lines:?}");
    assert!(lines[2].contains("round 2"), "{lines:?}");
    // every probe carried request bytes to the wire
    let served = recorder.lock().unwrap().len();
    assert_eq!(served, 3, "one fresh connection per probe");
    // the baseline probe was a well-formed GET (the unmutated seed)
    let baseline = &recorder.lock().unwrap()[0];
    let text = String::from_utf8_lossy(baseline).to_string();
    assert!(text.starts_with("GET / HTTP/1.1\r\n"), "{text}");
    assert!(text.contains("Host: 127.0.0.1"), "{text}");

    // Same seed → byte-identical probe streams (jsonl determinism).
    let out2 = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args(["fuzz", "--format", "jsonl"])
        .args(args)
        .args(["127.0.0.1"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let out3 = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args(["fuzz", "--format", "jsonl"])
        .args(args)
        .args(["127.0.0.1"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(out2, out3, "same seed must replay identically");
    let jsonl = String::from_utf8_lossy(&out2).to_string();
    assert!(jsonl.contains("\"proto\":\"http\""), "{jsonl}");
}

#[test]
fn dns_mode_silence_on_dead_port_is_a_finding() {
    // A dead port (listener dropped): every probe resolves silence
    // (connect refused), exit 0 — findings are data.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let out = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "fuzz",
            "--mode",
            "dns",
            "--ports",
            &port.to_string(),
            "--rounds",
            "1",
            "--retries",
            "0",
            "--timeout",
            "300ms",
            "--rate",
            "0",
            "--seed",
            "7",
            "127.0.0.1",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(stdout.contains("silence"), "{stdout}");
    assert!(
        stdout.contains("53/dns") || stdout.contains("dns"),
        "{stdout}"
    );
}

#[test]
fn app_mode_grammar_errors_are_usage() {
    // Tranche 10a: v6 app targets are IN charter now (dual-family
    // kernel driver) — a dead `::1` port resolves as silence findings,
    // exit 0. The format guard still applies.
    let out = wrex()
        .args([
            "fuzz",
            "--mode",
            "http",
            "--rounds",
            "1",
            "--timeout",
            "100ms",
            "::1",
        ])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(stdout.contains("::1"), "{stdout}");
    assert!(stdout.contains("silence"), "{stdout}");
    // raw/hex carry no findings (app modes too)
    let (code, stderr) = fuzz_err(&["--mode", "http", "--format", "raw", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("carry no findings"), "{stderr}");
}
