//! Trace CLI grammar tests (assert_cmd, no sockets): usage gates and
//! help rendering before any driver opens. Real-walk ground truth is
//! env-gated (`WREX_DRIVER_TESTS=1`) in `trace_driver.rs` and the
//! state machine itself is unit-tested in `wrex-scan` (ScriptedDriver).
//!
//! Spawns the `wrex` binary: ignored under Miri.
#![cfg_attr(miri, ignore = "spawns the wrex binary; not Miri-safe")]

use assert_cmd::Command;

fn wrex() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wrex"))
}

fn trace_err(args: &[&str]) -> (i32, String) {
    let out = wrex()
        .args(["trace"])
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

fn trace_code(args: &[&str]) -> i32 {
    let out = wrex()
        .args(["trace"])
        .args(args)
        .assert()
        .get_output()
        .clone();
    out.status.code().unwrap_or(-1)
}

#[test]
fn iface_and_target_required() {
    let (code, stderr) = trace_err(&["127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("trace requires -i"), "{stderr}");
    // no target: clap-level usage error
    let (code, _) = trace_err(&["-i", "lo"]);
    assert_eq!(code, 2);
}

#[test]
fn mode_and_knob_grammar_errors_are_usage() {
    let (code, stderr) = trace_err(&["-i", "lo", "--mode", "zzz", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown trace mode"), "{stderr}");
    // icmp takes no --port
    let (code, stderr) = trace_err(&["-i", "lo", "--mode", "icmp", "--port", "1", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("takes no --port"), "{stderr}");
    // one target per walk: a multi-address spec is a usage error
    let (code, stderr) = trace_err(&["-i", "lo", "127.0.0.0-127.0.0.2"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("one target"), "{stderr}");
    // guards: max-hops 0, wait 0, backoff 0
    for bad in [
        &["-i", "lo", "--max-hops", "0", "127.0.0.1"][..],
        &["-i", "lo", "--wait", "0s", "127.0.0.1"][..],
        &["-i", "lo", "--backoff", "0", "127.0.0.1"][..],
    ] {
        let (code, stderr) = trace_err(bad);
        assert_eq!(code, 2, "{bad:?}");
        assert!(stderr.contains("trace: "), "{stderr}");
    }
    // bad wait duration
    let (code, stderr) = trace_err(&["-i", "lo", "--wait", "zz", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("duration"), "{stderr}");
    // raw/hex carry no hop records
    let (code, stderr) = trace_err(&["-i", "lo", "--format", "raw", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("text|json|jsonl"), "{stderr}");
}

#[test]
fn grammar_ok_paths_reach_the_iface_lookup() {
    // every mode/knob combination parses; unknown iface short-circuits
    // with exit 1 (runtime) before any raw socket opens.
    assert_eq!(trace_code(&["-i", "definitely-not-here", "127.0.0.1"]), 1);
    assert_eq!(
        trace_code(&[
            "-i",
            "definitely-not-here",
            "--mode",
            "udp",
            "--port",
            "33434",
            "127.0.0.1"
        ]),
        1
    );
    assert_eq!(
        trace_code(&[
            "-i",
            "definitely-not-here",
            "--mode",
            "tcp",
            "--max-hops",
            "12",
            "--wait",
            "2s",
            "--backoff",
            "2",
            "--seed",
            "42",
            "127.0.0.1"
        ]),
        1
    );
}

#[test]
fn help_renders_the_trace_grammar() {
    let out = wrex()
        .args(["trace", "--help"])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&out.stdout);
    for want in [
        "--mode",
        "--max-hops",
        "--wait",
        "--backoff",
        "--seed",
        "TARGET",
    ] {
        assert!(stdout.contains(want), "missing `{want}`:\n{stdout}");
    }
    // the verb enumerates in the root help too
    let root = wrex().arg("--help").assert().success().get_output().clone();
    let rootout = String::from_utf8_lossy(&root.stdout);
    assert!(rootout.contains("trace"), "{rootout}");
}
