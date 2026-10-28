//! Query CLI grammar tests (assert_cmd, no sockets): usage errors (exit
//! 2) and the runtime-capability path (exit 1) all resolve before any
//! raw socket opens. Real-socket ground truth lives in `query_driver.rs`
//! (env-gated `WREX_DRIVER_TESTS=1`).
//!
//! Spawns the `wrex` binary: ignored under Miri.
#![cfg_attr(miri, ignore = "spawns the wrex binary; not Miri-safe")]

use assert_cmd::Command;

fn wrex() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wrex"))
}

fn query_err(args: &[&str]) -> (i32, String) {
    let out = wrex()
        .args(["query"])
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
fn server_required() {
    let (code, stderr) = query_err(&["example.com"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("query requires --server"), "{stderr}");

    // --server alone (no -i): accepted on every transport now (perf-
    // pass 3b: kernel sockets; -i only pins the source address) —
    // grammar errors are the only exit-2 class before sockets.
    let (code, stderr) = query_err(&["--server", "127.0.0.1", "a..b"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("label"), "{stderr}");
}

#[test]
fn grammar_errors_are_usage() {
    // bad type
    let (code, stderr) = query_err(&[
        "-i",
        "lo",
        "--server",
        "127.0.0.1",
        "--type",
        "BOGUS",
        "example.com",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown dns type"), "{stderr}");

    // bad class
    let (code, stderr) = query_err(&[
        "-i",
        "lo",
        "--server",
        "127.0.0.1",
        "--class",
        "NOPE",
        "example.com",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown dns class"), "{stderr}");

    // bad server
    let (code, stderr) = query_err(&["-i", "lo", "--server", "not-an-ip", "example.com"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("bad server"), "{stderr}");

    // bad name fails at encode (usage layer, before sockets)
    let (code, stderr) = query_err(&["-i", "lo", "--server", "127.0.0.1", "a..b"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("empty label"), "{stderr}");

    // raw/hex formats carry no reply
    let (code, stderr) = query_err(&[
        "-i",
        "lo",
        "--server",
        "127.0.0.1",
        "--format",
        "raw",
        "example.com",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("text|json|jsonl"), "{stderr}");

    // bad timeout duration
    let (code, stderr) = query_err(&[
        "-i",
        "lo",
        "--server",
        "127.0.0.1",
        "--timeout",
        "zz",
        "example.com",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("duration"), "{stderr}");
}

#[test]
fn unknown_iface_is_runtime_not_usage() {
    // unknown iface → exit 1 (table lookup happens before sockets)
    let (code, stderr) = query_err(&[
        "-i",
        "definitely-not-here",
        "--server",
        "127.0.0.1",
        "example.com",
    ]);
    assert_eq!(code, 1);
    assert!(stderr.contains("unknown iface"), "{stderr}");
}

#[test]
fn help_renders_the_query_grammar() {
    let out = wrex()
        .args(["query", "--help"])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--server"), "{stdout}");
    assert!(stdout.contains("--seed"), "{stdout}");
    assert!(stdout.contains("NXDOMAIN"), "{stdout}");
}

/// Tranche 10a: `--server` accepts either family — and since perf-
/// pass 3b every transport is a kernel socket, so no -i is demanded
/// anywhere; a v6 server without -i is past the usage gates (a dead
/// port is a runtime failure, not a usage error).
#[test]
fn v6_server_is_in_charter() {
    // A v6 literal is NOT a bad-server usage error.
    let (code, stderr) = query_err(&["-i", "lo", "--server", "::1", "a..b"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("label") && !stderr.contains("bad server"),
        "{stderr}"
    );

    // --tcp over a dead ::1 port: connect refusal is a runtime error
    // (exit 1) — proving the v6 family went past the usage gates into
    // the (now dual-family) kernel driver.
    let out = wrex()
        .args([
            "query",
            "--tcp",
            "--server",
            "::1",
            "--port",
            "1",
            "--timeout",
            "200ms",
            "example.com",
        ])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("query --tcp") || stderr.contains("no reply"),
        "{stderr}"
    );
}
