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

/// Capability probe (shared in wrex-test): `lo` + optional IPv6.
fn loopback_ready(v6: bool) -> bool {
    wrex_test::loopback_ready(v6)
}

/// Spawn `wrex recv -i lo --count N --timeout T --format hex` with
/// piped stdout — unfiltered and BOUNDED. The hopopts test classifies
/// every captured frame after this bounded window (a filtered recv
/// hung 22+ CI minutes when no matching reply arrived); sibling
/// traffic is excluded by post-hoc classification, not a filter.
fn spawn_recv_bounded(count: u64, timeout: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "recv",
            "-i",
            "lo",
            "--count",
            &count.to_string(),
            "--timeout",
            timeout,
            "--format",
            "hex",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn wrex recv")
}

/// Spawn `wrex recv -i lo --count 1 --format raw --filter F` with piped
/// stdout — the roundtrip test's byte-compare capture. The filter is
/// load-bearing (sibling tests share `lo` and cargo runs them in
/// parallel), and the send's paced repeats guarantee a match within
/// seconds (verified in CI), so an unbounded recv is safe here.
fn spawn_recv_filtered(filter: &str) -> Child {
    Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "recv", "-i", "lo", "--count", "1", "--format", "raw", "--filter", filter,
        ])
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
    if !loopback_ready(true) {
        return;
    }
    // Bounded capture (15s): every lo frame in the window, classified
    // after the window closes — never a blocking filter (the sibling
    // roundtrip test's udp frames land here too and are ignored below).
    let mut recv = spawn_recv_bounded(10, "15s");
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
    let lines: Vec<String> = String::from_utf8_lossy(&out)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    assert!(
        !lines.is_empty(),
        "recv captured nothing in the 15s window (the kernel should echo \
         through the hopopts chain)"
    );

    // Classify every captured frame; at least one must dissect as an
    // icmpv6 echo REPLY (129) — the ext chain reached the kernel and
    // came back. The inventory prints on failure so the kernel's
    // actual behavior is visible in the CI log.
    let mut saw_reply = false;
    let mut inventory: Vec<String> = Vec::new();
    for line in &lines {
        let bytes = match hex::decode(line) {
            Ok(b) => b,
            Err(_) => {
                inventory.push(format!("unhexable line `{line}`"));
                continue;
            }
        };
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
            .write_all(&bytes)
            .expect("pipe reply frame");
        let dis = dissect.wait_with_output().expect("collect dissect");
        let json: serde_json::Value = serde_json::from_slice(&dis.stdout).expect("dissect json");
        let kinds: Vec<&str> = json["layers"]
            .as_array()
            .map(|ls| {
                ls.iter()
                    .map(|l| l["kind"].as_str().unwrap_or("?"))
                    .collect()
            })
            .unwrap_or_default();
        inventory.push(format!(
            "{line} -> {}",
            if kinds.is_empty() {
                "(no layers)".to_string()
            } else {
                kinds.join(",")
            }
        ));
        if kinds.contains(&"icmpv6")
            && json["layers"].as_array().and_then(|ls| {
                ls.iter()
                    .find(|l| l["kind"] == "icmpv6")
                    .and_then(|l| l["fields"]["type"].as_u64())
            }) == Some(129)
        {
            saw_reply = true;
        }
    }
    eprintln!("hopopts capture inventory:\n{}", inventory.join("\n"));
    assert!(
        saw_reply,
        "no icmpv6 echo REPLY (type 129) in the window; captured:\n{}",
        inventory.join("\n")
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
    if !loopback_ready(false) {
        return;
    }
    // A loopback eth frame the kernel will reflect back: eth+ipv4+udp.
    // The recv filter (udp.dport=2) keeps the sibling test's icmpv6/scan
    // traffic out of this capture — parallel tests share `lo`.
    let mut recv = spawn_recv_filtered("udp.dport=2");
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
