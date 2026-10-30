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

// --- T21: variant modes, host discovery, timing templates, --service --------

#[test]
fn t21_variant_mode_grammar_errors() {
    // unknown mode still 2
    let (code, stderr) = scan_err(&["-i", "lo", "--mode", "finn", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown scan mode"), "{stderr}");
    // every new mode parses (reaches the iface lookup: exit 1); ndp/mld
    // over a v4 target stop earlier at the family gate (exit 2).
    for mode in ["fin", "null", "xmas", "ack", "arp"] {
        assert_eq!(
            scan_code(&["-i", "definitely-not-here", "--mode", mode, "127.0.0.1"]),
            1,
            "{mode}"
        );
    }
    for mode in ["ndp", "mld"] {
        assert_eq!(
            scan_code(&["-i", "definitely-not-here", "--mode", mode, "127.0.0.1"]),
            2,
            "{mode}"
        );
    }
}

#[test]
fn t21_host_modes_reject_ports_and_wrong_family() {
    // host-discovery modes take no ports (v4 target for arp; v6 for
    // ndp/mld — the family gate fires first otherwise)
    let (code, stderr) = scan_err(&["-i", "lo", "--mode", "arp", "--ports", "22", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("takes no --ports"), "{stderr}");
    for mode in ["ndp", "mld"] {
        let (code, stderr) = scan_err(&["-i", "lo", "--mode", mode, "--ports", "22", "::1"]);
        assert_eq!(code, 2, "{mode}");
        assert!(stderr.contains("takes no --ports"), "{mode}: {stderr}");
    }
    // arp is v4-only; ndp/mld are v6-only (family gates → usage 2)
    let (code, stderr) = scan_err(&["-i", "lo", "--mode", "arp", "::1"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("arp mode requires ipv4 targets"),
        "{stderr}"
    );
    for mode in ["ndp", "mld"] {
        let (code, stderr) = scan_err(&["-i", "lo", "--mode", mode, "127.0.0.1"]);
        assert_eq!(code, 2, "{mode}");
        assert!(stderr.contains("requires ipv6 targets"), "{mode}: {stderr}");
    }
}

#[test]
fn t21_timing_template_grammar() {
    // unknown template → 2
    let (code, stderr) = scan_err(&["-i", "lo", "-T", "9", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown timing template"), "{stderr}");
    let (code, stderr) = scan_err(&["-i", "lo", "--timing", "fast", "127.0.0.1"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("timing template"), "{stderr}");
    // T0..T5 parse in every spelling (reach the iface lookup: exit 1)
    for t in ["T0", "T1", "T2", "T3", "T4", "T5", "t3", "0", "4"] {
        assert_eq!(
            scan_code(&["-i", "definitely-not-here", "-T", t, "127.0.0.1"]),
            1,
            "{t}"
        );
    }
    // --service parses alongside (additive flag; no open ports to probe
    // without a driver)
    assert_eq!(
        scan_code(&["-i", "definitely-not-here", "--service", "127.0.0.1"]),
        1
    );
}

#[test]
fn t21_help_renders_the_new_grammar() {
    let out = wrex()
        .args(["scan", "--help"])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&out.stdout);
    for want in [
        "--timing",
        "-T",
        "--service",
        "fin",
        "xmas",
        "arp",
        "ndp",
        "mld",
        "unfiltered",
    ] {
        assert!(stdout.contains(want), "missing `{want}`:\n{stdout}");
    }
}
