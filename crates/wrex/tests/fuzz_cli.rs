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
