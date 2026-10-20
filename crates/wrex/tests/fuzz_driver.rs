//! Fuzz ground-truth tests (env-gated: `WREX_DRIVER_TESTS=1`): the
//! stateful prober against real kernel endpoints on `lo` — a bound UDP
//! responder must record baseline replies, an unbound port ICMP
//! unreachables, and a pinned seed must reproduce byte-identical
//! findings. Auto-skip otherwise.
//!
//! Opens raw sockets and spawns processes: ignored under Miri.
#![cfg_attr(miri, ignore = "raw sockets + subprocesses; not Miri-safe")]

use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::time::Duration;

fn driver_tests_enabled() -> bool {
    std::env::var("WREX_DRIVER_TESTS").as_deref() == Ok("1")
}

/// True when the failure is just the sandbox (no CAP_NET_RAW).
fn cap_missing(stderr: &str) -> bool {
    stderr.contains("CAP_NET_RAW")
}

fn skip(name: &str) {
    eprintln!("fuzz driver tests: skipping {name} (WREX_DRIVER_TESTS != 1)");
}

/// Run `wrex fuzz …`, return (exit code, stdout, stderr).
fn fuzz_out(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args(["fuzz", "-i", "lo", "--timeout", "800ms"])
        .args(args)
        .output()
        .expect("spawn wrex fuzz");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

/// A UDP responder bound on 127.0.0.1: echo every datagram back.
fn udp_responder() -> (std::thread::JoinHandle<()>, u16) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    let port = sock.local_addr().expect("addr").port();
    let handle = std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        for _ in 0..64 {
            // Each recv gets its own timeout bound so the thread ends.
            let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
            let (n, peer) = match sock.recv_from(&mut buf) {
                Ok(v) => v,
                Err(_) => return,
            };
            let _ = sock.send_to(&buf[..n], peer);
        }
    });
    (handle, port)
}

/// Parse a jsonl findings stdout into typed rows.
fn findings(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad finding line: {e}: {l}")))
        .collect()
}

#[test]
fn udp_baseline_and_rounds_ground_truth() {
    if !driver_tests_enabled() {
        skip("udp_baseline_and_rounds_ground_truth");
        return;
    }
    let (_responder, port) = udp_responder();
    let ports = port.to_string();
    // baseline + 2 mutated rounds against the live responder.
    let (code, stdout, stderr) = fuzz_out(&[
        "--ports",
        &ports,
        "--rounds",
        "2",
        "--baseline",
        "--seed",
        "42",
        "--format",
        "jsonl",
        "127.0.0.1",
    ]);
    if cap_missing(&stderr) {
        eprintln!("fuzz driver tests: skipping (no CAP_NET_RAW; CI runs under sudo)");
        return;
    }
    assert_eq!(code, 0, "probe run completed\n{stderr}");
    let rows = findings(&stdout);
    assert_eq!(rows.len(), 3, "baseline + 2 rounds\n{stdout}");
    // The baseline probe (an empty datagram to the bound port) must
    // have been echoed: a recorded reply.
    let baseline = &rows[0];
    assert_eq!(
        baseline["strategy"], "baseline",
        "baseline probe is recorded first\n{stdout}"
    );
    assert_eq!(
        baseline["outcome"], "reply",
        "bound responder must echo the baseline\n{stdout}"
    );
    assert!(
        baseline["reply_hex"]
            .as_str()
            .is_some_and(|h| !h.is_empty()),
        "reply bytes recorded\n{stdout}"
    );
    assert_eq!(baseline["port"].as_u64(), Some(u64::from(port)));
    // Mutated rounds carry their labels (findings resolve in time
    // order, not probe-ordinal order — compare as sets).
    let mut rounds: Vec<u64> = rows[1..]
        .iter()
        .filter_map(|r| r["round"].as_u64())
        .collect();
    rounds.sort_unstable();
    assert_eq!(rounds, vec![1, 2], "both mutated rounds recorded\n{stdout}");
}

#[test]
fn udp_unbound_port_unreachable() {
    if !driver_tests_enabled() {
        skip("udp_unbound_port_unreachable");
        return;
    }
    // Bind then drop: a port the kernel will reject with ICMP 3/3.
    let unbound = {
        let s = UdpSocket::bind("127.0.0.1:0").expect("bind udp");
        let p = s.local_addr().unwrap().port();
        drop(s);
        p
    };
    let ports = unbound.to_string();
    let (code, stdout, stderr) = fuzz_out(&[
        "--ports",
        &ports,
        "--rounds",
        "0",
        "--baseline",
        "--seed",
        "7",
        "--format",
        "jsonl",
        "127.0.0.1",
    ]);
    if cap_missing(&stderr) {
        eprintln!("fuzz driver tests: skipping (no CAP_NET_RAW; CI runs under sudo)");
        return;
    }
    assert_eq!(code, 0, "probe run completed\n{stderr}");
    let rows = findings(&stdout);
    assert_eq!(rows.len(), 1);
    // The kernel answers the empty datagram with an ICMP port
    // unreachable quoting it — the recorded attribution (a newtype
    // variant: {"unreachable": <code>}).
    assert_eq!(
        rows[0]["outcome"]["unreachable"],
        serde_json::json!(3),
        "unbound port must attribute unreachable:3\n{stdout}"
    );
}

#[test]
fn seed_reproducibility() {
    if !driver_tests_enabled() {
        skip("seed_reproducibility");
        return;
    }
    let (_responder, port) = udp_responder();
    let ports = port.to_string();
    let args = [
        "--ports",
        &ports,
        "--rounds",
        "2",
        "--seed",
        "48879", // 0xBEEF (clap u64 takes decimal)
        "--format",
        "jsonl",
        "127.0.0.1",
    ];
    let (code_a, a, stderr_a) = fuzz_out(&args);
    if cap_missing(&stderr_a) {
        eprintln!("fuzz driver tests: skipping (no CAP_NET_RAW; CI runs under sudo)");
        return;
    }
    assert_eq!(code_a, 0);
    let (code_b, b, _) = fuzz_out(&args);
    assert_eq!(code_b, 0);
    // The probe bytes are seed-pinned: identical streams (rtt/attempts
    // may vary under load — compare the probe_hex + strategy + round).
    let proj = |s: &str| -> Vec<String> {
        findings(s)
            .into_iter()
            .map(|f| {
                format!(
                    "{}:{}:{}",
                    f["strategy"].as_str().unwrap_or(""),
                    f["round"],
                    f["probe_hex"].as_str().unwrap_or("")
                )
            })
            .collect()
    };
    assert_eq!(proj(&a), proj(&b), "same seed must reproduce the probes");
}

#[test]
fn usage_before_sockets_still_holds() {
    if !driver_tests_enabled() {
        skip("usage_before_sockets_still_holds");
        return;
    }
    // Even with the gate on, grammar errors stay exit 2 before any
    // socket work (same suite as fuzz_cli, one representative case).
    let out = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "fuzz",
            "-i",
            "lo",
            "--mode",
            "icmp",
            "--ports",
            "22",
            "127.0.0.1",
        ])
        .stderr(Stdio::piped())
        .output()
        .expect("spawn wrex fuzz");
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(out.status.code(), Some(2), "{err}");
}
