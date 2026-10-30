//! Trace ground-truth tests (env-gated: `WREX_DRIVER_TESTS=1`): real
//! TTL walks on `lo` — the kernel answers echo probes (reached at hop
//! 1) and UDP probes to unbound ports with port-unreachable (reached).
//!
//! The state machine itself is unit-tested in `wrex-scan` under
//! `ScriptedDriver` (every cross-talk/silent/backoff path).
//!
//! Spawns the `wrex` binary: ignored under Miri.
#![cfg_attr(miri, ignore = "raw sockets + subprocesses; not Miri-safe")]

use std::process::Command;

fn driver_tests_enabled() -> bool {
    std::env::var("WREX_DRIVER_TESTS").as_deref() == Ok("1") && wrex_test::loopback_ready(false)
}

fn skip(name: &str) {
    eprintln!("trace driver tests: skipping {name} (WREX_DRIVER_TESTS != 1)");
}

fn trace_out(args: &[&str]) -> (i32, String) {
    let mut all: Vec<std::ffi::OsString> = vec![
        "trace".into(),
        "-i".into(),
        "lo".into(),
        "--wait".into(),
        "800ms".into(),
    ];
    for a in args {
        all.push((*a).into());
    }
    let out = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args(&all)
        .output()
        .expect("spawn wrex trace");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

#[test]
fn icmp_walk_reaches_loopback() {
    if !driver_tests_enabled() {
        skip("icmp_walk_reaches_loopback");
        return;
    }
    let (code, stdout) = trace_out(&["--seed", "42", "127.0.0.1"]);
    assert_eq!(code, 0, "walk completed");
    assert!(
        stdout.contains("127.0.0.1  reached"),
        "loopback must answer echo probes at hop 1\n{stdout}"
    );
    // jsonl renders the hop record shape
    let (code, jsonl) = trace_out(&["--seed", "42", "--format", "jsonl", "127.0.0.1"]);
    assert_eq!(code, 0);
    assert!(jsonl.contains("\"hop\":1"), "{jsonl}");
    assert!(jsonl.contains("\"state\":\"reached\""), "{jsonl}");
    assert!(jsonl.contains("\"target\":\"127.0.0.1\""), "{jsonl}");
}

#[test]
fn udp_walk_port_unreachable_reaches() {
    if !driver_tests_enabled() {
        skip("udp_walk_port_unreachable_reaches");
        return;
    }
    // 33434 on lo: nothing binds → the kernel answers ICMP 3/3 quoting
    // our datagram → reached (the classic traceroute destination mark)
    let (code, stdout) = trace_out(&["--mode", "udp", "--port", "33434", "127.0.0.1"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("reached"),
        "kernel port-unreachable must end the udp walk\n{stdout}"
    );
    assert!(
        stdout.lines().count() <= 2,
        "the walk must end at the destination, not walk max hops\n{stdout}"
    );
}

#[test]
fn v6_walk_reaches_loopback() {
    if !driver_tests_enabled() {
        skip("v6_walk_reaches_loopback");
        return;
    }
    let (code, stdout) = trace_out(&["--seed", "7", "::1"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("::1  reached"),
        "v6 loopback must answer icmpv6 echo probes\n{stdout}"
    );
}
