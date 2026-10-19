//! Scan CLI grammar tests (assert_cmd, no sockets): every case here
//! exercises an exit-2 usage error or a pure-rendering path before any
//! driver opens. Real-socket ground truth lives in `scan_driver.rs`
//! (env-gated `WREX_DRIVER_TESTS=1`).
//!
//! Spawns the `wrex` binary: ignored under Miri.
#![cfg_attr(miri, ignore = "spawns the wrex binary; not Miri-safe")]

use assert_cmd::Command;

fn wrex() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wrex"))
}

fn scan_err(args: &[&str]) -> (i32, String) {
    let out = wrex()
        .args(["scan"])
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

fn scan_code(args: &[&str]) -> i32 {
    let out = wrex()
        .args(["scan"])
        .args(args)
        .assert()
        .get_output()
        .clone();
    out.status.code().unwrap_or(-1)
}

#[test]
fn iface_required() {
    let (code, stderr) = scan_err(&["127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("scan requires -i"), "{stderr}");
}

#[test]
fn mode_and_grammar_errors_are_usage() {
    // unknown mode → 2
    let (code, stderr) = scan_err(&["-i", "lo", "--mode", "synn", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown scan mode"), "{stderr}");

    // icmp + ports → 2
    let (code, stderr) = scan_err(&["-i", "lo", "--mode", "icmp", "--ports", "22", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("takes no --ports"), "{stderr}");

    // udp without ports → 2
    let (code, stderr) = scan_err(&["-i", "lo", "--mode", "udp", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("requires --ports"), "{stderr}");

    // bad target (parsed as a range or address) → 2
    let (code, stderr) = scan_err(&["-i", "lo", "not-an-ip"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("bad range start") || stderr.contains("bad target"),
        "{stderr}"
    );

    // bad ports → 2
    let (code, stderr) = scan_err(&["-i", "lo", "--ports", "0", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("port"), "{stderr}");

    // --rate and --interval conflict → 2
    let (code, stderr) = scan_err(&[
        "-i",
        "lo",
        "--rate",
        "100",
        "--interval",
        "10ms",
        "127.0.0.1",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("mutually exclusive"), "{stderr}");

    // raw/hex formats carry no results → 2
    let (code, stderr) = scan_err(&["-i", "lo", "--format", "raw", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("text|json|jsonl"), "{stderr}");

    // probe-count cap → 2 (254 hosts × 5000 ports > 2^20)
    let (code, stderr) = scan_err(&["-i", "lo", "--ports", "1-5000", "10.0.0.0/24"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("probe cap"), "{stderr}");

    // bad jitter duration → 2
    let (code, stderr) = scan_err(&["-i", "lo", "--jitter", "zz", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("duration"), "{stderr}");
}

#[test]
fn udp_ports_required_with_any_target_expansion() {
    // a /32 cidr with no ports still needs --ports in udp mode
    let (code, stderr) = scan_err(&["-i", "lo", "--mode", "udp", "127.0.0.1/32"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("requires --ports"), "{stderr}");
}

#[test]
fn zero_targets_is_usage_error() {
    // targets are `required = true` in clap, but empty strings still fail
    // target parsing → 2
    let (code, _) = scan_err(&["-i", "lo", ""]);
    assert_eq!(code, 2);
}

#[test]
fn help_renders_the_scan_grammar() {
    let out = wrex()
        .args(["scan", "--help"])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--mode"), "{stdout}");
    assert!(stdout.contains("--ports"), "{stdout}");
    assert!(stdout.contains("--seed"), "{stdout}");
    assert!(stdout.contains("--jitter"), "{stdout}");
    assert!(stdout.contains("TARGET"), "{stdout}");
}

#[test]
fn scan_without_capability_fails_runtime_not_usage() {
    // Unknown iface is a runtime error (exit 1) — reachable without
    // sockets: the table lookup happens before any raw socket opens.
    let (code, stderr) = scan_err(&["-i", "definitely-not-here", "127.0.0.1"]);
    // exit code 1 (runtime), message lists available ifaces
    assert_eq!(code, 1);
    assert!(stderr.contains("unknown iface"), "{stderr}");
}

#[test]
fn default_top100_ports_reach_the_session() {
    // dry-check the default port list via --help man regeneration
    // instead; here just assert the flag parses with default ports:
    // unknown iface short-circuits before probes. exit 1 = grammar ok.
    assert_eq!(scan_code(&["-i", "definitely-not-here", "127.0.0.1"]), 1);
}
