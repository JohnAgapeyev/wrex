//! Driver integration tests (env-gated: `WREX_DRIVER_TESTS=1`): AF_PACKET
//! send/recv round-trip on `lo`. Auto-skip otherwise.
//!
//! Spawns processes and opens raw sockets: ignored under Miri.
#![cfg_attr(miri, ignore = "raw sockets + subprocesses; not Miri-safe")]

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn driver_tests_enabled() -> bool {
    std::env::var("WREX_DRIVER_TESTS").as_deref() == Ok("1")
}

/// Spawn `wrex recv -i lo --count 1 --format raw` with piped stdout.
fn spawn_recv() -> Child {
    Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args(["recv", "-i", "lo", "--count", "1", "--format", "raw"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn wrex recv")
}

/// Tranche 17a ground truth: an icmpv6 echo through a PadN hop-by-hop
/// extension header on `lo` — the kernel must process the ext chain
/// and answer (type 128 in, 129 back). The env-gated proof that the
/// ext codecs speak wire the kernel accepts, over the unchanged
/// `RawIpv6Driver`.
#[test]
fn lo_echo_through_hopopts_alive() {
    if !driver_tests_enabled() {
        eprintln!("driver tests: skipping lo_echo_through_hopopts (WREX_DRIVER_TESTS != 1)");
        return;
    }
    let mut recv = spawn_recv();
    std::thread::sleep(Duration::from_millis(300));

    let frame_args = [
        "send",
        "-i",
        "lo",
        "--count",
        "5",
        "--interval",
        "200ms",
        "--layer",
        "eth",
        "--layer",
        "ipv6",
        "--layer",
        "hopopts",
        "--hopopts-options",
        "hex:010400000000",
        "--layer",
        "icmpv6",
        "--icmpv6-type",
        "128",
        "--ipv6-src=::1",
        "--ipv6-dst=::1",
    ];
    let send = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args(frame_args)
        .output()
        .expect("spawn wrex send");
    if !send.status.success() {
        let stderr = String::from_utf8_lossy(&send.stderr).to_string();
        if stderr.contains("CAP_NET_RAW") {
            eprintln!(
                "driver tests: skipping lo_echo_through_hopopts (no CAP_NET_RAW; CI runs under sudo)"
            );
            let _ = recv.kill();
            let _ = recv.wait();
            return;
        }
        panic!("send failed: {stderr}");
    }

    let mut out = Vec::new();
    if let Some(mut stdout) = recv.stdout.take() {
        stdout.read_to_end(&mut out).expect("read recv stdout");
    }
    let status = recv.wait().expect("wait recv");
    assert!(status.success(), "recv exited {status}");
    assert!(
        !out.is_empty(),
        "recv captured no reply (the kernel should echo through the hopopts chain)"
    );

    // The captured reply must dissect as an icmpv6 echo REPLY (129)
    // from ::1 — the ext chain reached the kernel and came back.
    let mut dissect = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args(["dissect", "--format", "json", "--start", "auto"])
        .stdout(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn wrex dissect");
    dissect
        .stdin
        .take()
        .expect("dissect stdin")
        .write_all(&out)
        .expect("pipe reply frame");
    let dis = dissect.wait_with_output().expect("collect dissect");
    let json: serde_json::Value = serde_json::from_slice(&dis.stdout).expect("dissect json");
    let kinds: Vec<&str> = json["layers"]
        .as_array()
        .expect("layers")
        .iter()
        .map(|l| l["kind"].as_str().expect("kind"))
        .collect();
    assert!(
        kinds.contains(&"icmpv6"),
        "expected an icmpv6 reply layer in {kinds:?}"
    );
    let icmp = json["layers"]
        .as_array()
        .expect("layers")
        .iter()
        .find(|l| l["kind"] == "icmpv6")
        .expect("icmpv6 layer");
    assert_eq!(
        icmp["fields"]["type"], 129,
        "the reply must be an echo reply"
    );
}

/// §Verification 5: send 10 copies paced; recv must emit the identical
/// frame bytes (repeats defeat the startup race).
#[test]
fn lo_loopback_send_recv_roundtrip() {
    if !driver_tests_enabled() {
        eprintln!("driver tests: skipping (WREX_DRIVER_TESTS != 1)");
        return;
    }
    // A loopback eth frame the kernel will reflect back: eth+ipv4+udp.
    let mut recv = spawn_recv();
    // give recv a moment to bind (paced repeats cover the race anyway)
    std::thread::sleep(Duration::from_millis(300));

    let frame_args = [
        "send",
        "-i",
        "lo",
        "--count",
        "10",
        "--interval",
        "200ms",
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
    ];
    let send = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args(frame_args)
        .output()
        .expect("spawn wrex send");
    if !send.status.success() {
        let stderr = String::from_utf8_lossy(&send.stderr).to_string();
        // Missing CAP_NET_RAW (no sudo here): skip with a notice — the
        // PermissionDenied → hint mapping is covered by unit tests, and CI
        // runs this test under passwordless sudo.
        if stderr.contains("CAP_NET_RAW") {
            eprintln!("driver tests: skipping lo roundtrip (no CAP_NET_RAW; CI runs under sudo)");
            let _ = recv.kill();
            let _ = recv.wait();
            return;
        }
        panic!("send failed: {stderr}");
    }

    // Collect recv stdout (one frame).
    let mut out = Vec::new();
    if let Some(mut stdout) = recv.stdout.take() {
        stdout.read_to_end(&mut out).expect("read recv stdout");
    }
    let status = recv.wait().expect("wait recv");
    assert!(status.success(), "recv exited {status}");
    assert!(
        !out.is_empty(),
        "recv captured no frame (send should have echoed on lo)"
    );

    // The sent frame must be byte-equal to `craft` of the same spec.
    let craft_args = vec![
        "craft".to_string(),
        "--format".into(),
        "raw".into(),
        "--layer".into(),
        "eth".into(),
        "--layer".into(),
        "ipv4".into(),
        "--layer".into(),
        "udp".into(),
        "--ipv4-src=127.0.0.1".into(),
        "--ipv4-dst=127.0.0.1".into(),
        "--udp-sport=1".into(),
        "--udp-dport=2".into(),
        "--payload=hex:aa".into(),
    ];
    let craft = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args(&craft_args)
        .output()
        .expect("spawn wrex craft");
    assert!(craft.status.success());
    let want = craft.stdout;
    // Loopback-delivered frame == the crafted bytes (padded ethernet
    // frames may carry trailing zero padding: compare prefix).
    assert!(
        out.starts_with(&want) || want.starts_with(&out),
        "recv frame differs from crafted bytes\n recv: {}\nwant: {}",
        hex::encode(&out),
        hex::encode(&want)
    );
}
