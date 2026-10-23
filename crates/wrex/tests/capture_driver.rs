//! Tranche-5 driver integration tests (env-gated: `WREX_DRIVER_TESTS=1`):
//! `wrex capture` on `lo` under live traffic, and the capture → replay
//! send round-trip. Auto-skip otherwise.
//!
//! Opens raw sockets: ignored under Miri.
#![cfg_attr(miri, ignore = "raw sockets + subprocesses; not Miri-safe")]

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn driver_tests_enabled() -> bool {
    std::env::var("WREX_DRIVER_TESTS").as_deref() == Ok("1")
}

/// True when the failure is just the sandbox (no CAP_NET_RAW): skip
/// with a notice — CI runs this suite under passwordless sudo.
fn cap_missing(stderr: &str) -> bool {
    stderr.contains("CAP_NET_RAW")
}

const SEND_ARGS: &[&str] = &[
    "send",
    "-i",
    "lo",
    "--count",
    "3",
    "--interval",
    "100ms",
    "--layer",
    "eth",
    "--layer",
    "ipv4",
    "--layer",
    "udp",
    "--ipv4-src=127.0.0.1",
    "--ipv4-dst=127.0.0.1",
    // Distinct ports from the driver.rs roundtrip recipe (sport=1
    // dport=2): parallel test binaries share `lo`, and the driver.rs
    // recv filters on `udp.dport=2` — don't feed it our frames.
    "--udp-sport=41",
    "--udp-dport=42",
    // "TS#" — ASCII bytes, even-length hex.
    "--payload=hex:545323",
];

/// §Verification T5: capture live `lo` traffic into a pcap, then
/// assert the file is a valid classic pcap holding our frames.
#[test]
fn lo_capture_writes_valid_pcap() {
    if !driver_tests_enabled() {
        eprintln!("driver tests: skipping (WREX_DRIVER_TESTS != 1)");
        return;
    }
    let pcap = std::env::temp_dir().join(format!("wrex-t5-capture-{}.pcap", std::process::id()));
    let path = pcap.to_str().unwrap().to_string();
    let mut capture = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "capture",
            "-i",
            "lo",
            "-w",
            path.as_str(),
            "--count",
            "1",
            "--timeout",
            "15s",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wrex capture");
    // Give capture a moment to bind, then push frames at it.
    std::thread::sleep(Duration::from_millis(300));
    let send = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args(SEND_ARGS)
        .output()
        .expect("spawn wrex send");
    let _ = capture.wait(); // --count 1 ends it as soon as a frame lands

    if !send.status.success() {
        let stderr = String::from_utf8_lossy(&send.stderr).to_string();
        if cap_missing(&stderr) {
            eprintln!("driver tests: skipping capture (no CAP_NET_RAW; CI runs under sudo)");
            let _ = std::fs::remove_file(&pcap);
            return;
        }
        panic!("send failed: {stderr}");
    }

    // The pcap must parse with the in-house reader and hold >= 1 frame.
    let bytes = std::fs::read(&pcap).unwrap_or_else(|e| panic!("read {}: {e}", pcap.display()));
    let file =
        wrex_pcap::read(&bytes).unwrap_or_else(|e| panic!("capture wrote an invalid pcap: {e}"));
    assert!(
        !file.records.is_empty(),
        "capture wrote no records (send echoed on lo)"
    );
    assert_eq!(file.linktype, wrex_pcap::linktype::EN10MB);
    // Timestamps are capture wall-clock, not zero.
    assert!(file.records[0].ts > std::time::UNIX_EPOCH);
    let _ = std::fs::remove_file(&pcap);
}

/// §Verification T5: the captured pcap re-sends verbatim onto `lo`
/// (`wrex replay -i lo`), and a concurrent `wrex recv` observes the
/// replayed bytes.
#[test]
fn lo_replay_roundtrip() {
    if !driver_tests_enabled() {
        eprintln!("driver tests: skipping (WREX_DRIVER_TESTS != 1)");
        return;
    }
    // Stage 1: capture one frame (the same recipe as the capture test).
    let pcap = std::env::temp_dir().join(format!("wrex-t5-replay-{}.pcap", std::process::id()));
    let path = pcap.to_str().unwrap().to_string();
    let mut capture = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "capture",
            "-i",
            "lo",
            "-w",
            path.as_str(),
            "--count",
            "1",
            "--timeout",
            "15s",
        ])
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wrex capture");
    std::thread::sleep(Duration::from_millis(300));
    let send = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args(SEND_ARGS)
        .output()
        .expect("spawn wrex send");
    let _ = capture.wait();
    if !send.status.success() {
        let stderr = String::from_utf8_lossy(&send.stderr).to_string();
        if cap_missing(&stderr) {
            eprintln!("driver tests: skipping replay (no CAP_NET_RAW; CI runs under sudo)");
            let _ = std::fs::remove_file(&pcap);
            return;
        }
        panic!("send failed: {stderr}");
    }
    let captured = std::fs::read(&pcap).unwrap_or_else(|e| panic!("read {}: {e}", pcap.display()));
    assert!(
        !wrex_pcap::read(&captured)
            .expect("capture wrote an invalid pcap")
            .records
            .is_empty(),
        "capture wrote no records (send echoed on lo)"
    );

    // Stage 2: replay the captured frame onto lo, watched by recv.
    let mut recv: Child = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "recv",
            "-i",
            "lo",
            "--count",
            "1",
            "--timeout",
            "10s",
            "--format",
            "raw",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wrex recv");
    std::thread::sleep(Duration::from_millis(300));
    let replay = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args(["replay", path.as_str(), "-i", "lo", "--rate", "0"])
        .output()
        .expect("spawn wrex replay");
    if !replay.status.success() {
        let stderr = String::from_utf8_lossy(&replay.stderr).to_string();
        if cap_missing(&stderr) {
            eprintln!("driver tests: skipping replay send (no CAP_NET_RAW; CI runs under sudo)");
            let _ = recv.kill();
            let _ = recv.wait();
            let _ = std::fs::remove_file(&pcap);
            return;
        }
        panic!("replay failed: {stderr}");
    }

    let mut out = Vec::new();
    if let Some(mut stdout) = recv.stdout.take() {
        stdout.read_to_end(&mut out).expect("read recv stdout");
    }
    let status = recv.wait().expect("wait recv");
    assert!(status.success(), "recv exited {status}");
    assert!(
        !out.is_empty(),
        "recv captured no replayed frame (replay --rate 0 should have echoed on lo)"
    );
    let _ = std::fs::remove_file(&pcap);
}
