//! Driver integration tests (env-gated: `WREX_DRIVER_TESTS=1`): AF_PACKET
//! send/recv round-trip on `lo`. Auto-skip otherwise.
//!
//! Spawns processes and opens raw sockets: ignored under Miri.
#![cfg_attr(miri, ignore = "raw sockets + subprocesses; not Miri-safe")]

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

fn driver_tests_enabled() -> bool {
    std::env::var("WREX_DRIVER_TESTS").as_deref() == Ok("1")
}

/// XDP attaches are exclusive per interface: two concurrent
/// `capture -i lo` children race for `lo`'s single XDP slot (the
/// second attach gets EBUSY — the step-tagged downgrade note — and
/// the no-note regression assert goes flaky). The two XDP-attaching
/// ground truths serialize on this lock for the capture child's
/// lifetime; every other driver test rides AF_PACKET (`recv`,
/// `-i any` cooked capture) and never contends.
static XDP_ATTACH: Mutex<()> = Mutex::new(());

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
    let mut recv = spawn_recv_bounded(24, "15s");
    std::thread::sleep(Duration::from_millis(300));

    // Three probe variants in one window (the kernel's echo behavior
    // pinned per variable — inventory-diagnosed in CI):
    //   A: ext-free, eth dst broadcast (the craft default shape)
    //   B: ext-free, eth dst = iface MAC (the RawIpv6Driver shape)
    //   C: hopopts chain, eth dst = iface MAC (B + the 17a ext claim)
    // Each variant carries a distinct echo.id so replies are
    // attributable, and a distinct icmpv6.seq marker.
    let variants: &[(&str, &[&str])] = &[
        (
            "A/ext-free/bcast",
            &[
                "send",
                "-i",
                "lo",
                "--count",
                "2",
                "--interval",
                "100ms",
                "--layer",
                "eth",
                "--layer",
                "ipv6",
                "--layer",
                "icmpv6",
                "--icmpv6-type",
                "128",
                "--icmpv6-echo-id",
                "1111",
                "--ipv6-src=::1",
                "--ipv6-dst=::1",
            ],
        ),
        (
            "B/ext-free/ifmac",
            &[
                "send",
                "-i",
                "lo",
                "--count",
                "2",
                "--interval",
                "100ms",
                "--layer",
                "eth",
                "--eth-dst=00:00:00:00:00:00",
                "--layer",
                "ipv6",
                "--layer",
                "icmpv6",
                "--icmpv6-type",
                "128",
                "--icmpv6-echo-id",
                "2222",
                "--ipv6-src=::1",
                "--ipv6-dst=::1",
            ],
        ),
        (
            "C/hopopts/ifmac",
            &[
                "send",
                "-i",
                "lo",
                "--count",
                "2",
                "--interval",
                "100ms",
                "--layer",
                "eth",
                "--eth-dst=00:00:00:00:00:00",
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
                "--icmpv6-echo-id",
                "3333",
                "--ipv6-src=::1",
                "--ipv6-dst=::1",
            ],
        ),
    ];
    for (label, args) in variants.iter() {
        let send = Command::new(env!("CARGO_BIN_EXE_wrex"))
            .args(*args)
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
            panic!("send ({label}) failed: {stderr}");
        }
    }
    let send = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "send",
            "-i",
            "lo",
            "--count",
            "2",
            "--interval",
            "100ms",
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
        ])
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

// --- tranche 23a: the cooked capture ground truth ---------------------------

/// `capture -i any` on `lo`: the store carries LINKTYPE_LINUX_SLL and
/// every recorded frame starts with the synthesized 16-byte SLL header
/// (pkttype host/outgoing, hatype ether, halen 6, lo's MAC, the inner
/// ethertype) — replay of the store dissects from `sll` and the filter
/// engine speaks the cooked paths. The T5 capture round-trip,
/// transposed to the cooked view.
#[test]
fn cooked_capture_and_replay_roundtrip() {
    if !driver_tests_enabled() {
        eprintln!("skipping (WREX_DRIVER_TESTS != 1)");
        return;
    }
    assert!(
        loopback_ready(false),
        "lo must be up for the cooked capture"
    );
    let dir = wrex_test::tempdir();
    let cap = dir.path().join("cooked.pcap");

    // Generate loopback traffic while a bounded capture runs.
    let capture = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "capture",
            "-i",
            "any",
            "--count",
            "1",
            "--timeout",
            "3s",
            "-w",
            cap.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn wrex capture");
    std::thread::sleep(Duration::from_millis(300));
    wrex_test::send_udp_on_lo();
    let out = capture.wait_with_output().expect("capture exits");
    assert!(out.status.success(), "capture must end cleanly");

    // The store is a LINKTYPE_LINUX_SLL classic pcap whose records
    // carry the synthesized header + payload.
    let bytes = std::fs::read(&cap).expect("the capture file exists");
    let file = wrex_pcap::read(&bytes).expect("the capture parses");
    assert_eq!(file.linktype, wrex_pcap::linktype::LINUX_SLL);
    assert!(!file.records.is_empty(), "at least one frame");
    let rec = &file.records[0];
    assert!(rec.bytes.len() >= 16, "the SLL header is present");
    // SLL: the hatype/halen/pkttype fields are KERNEL METADATA (on
    // `lo` the hatype is ARPHRD_LOOPBACK 772, not ether) — the pinned
    // invariants are the structural ones: pkttype is a defined kernel
    // class (u16 BE at +0, 0..=4; the live runs saw 1 = broadcast —
    // lo's reflected frames classify by their eth.dst) and the inner
    // ethertype BE at +14 names the family (the udp probe rides ipv4;
    // sibling v6 noise is fine).
    let pkttype = u16::from_be_bytes([rec.bytes[0], rec.bytes[1]]);
    assert!(pkttype <= 4, "pkttype {pkttype} is a defined class");
    let ethertype = u16::from_be_bytes([rec.bytes[14], rec.bytes[15]]);
    assert!(
        ethertype == 0x0800 || ethertype == 0x86dd,
        "the probe rides an ip ethertype, got {ethertype:#06x}"
    );

    // Replay dissects from `sll` (the linktype-driven start) and the
    // filter engine speaks the cooked path.
    let out = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "replay",
            cap.to_str().unwrap(),
            "--format",
            "jsonl",
            "--count",
            "1",
        ])
        .output()
        .expect("spawn wrex replay");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"kind\":\"sll\""),
        "replay must dissect from sll: {stdout}"
    );
    let out = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "replay",
            cap.to_str().unwrap(),
            "--format",
            "hex",
            "--count",
            "1",
            "--filter",
            "sll.protocol=0x0800",
        ])
        .output()
        .expect("spawn wrex replay (filtered)");
    assert!(out.status.success());
    assert!(
        !out.stdout.is_empty() || ethertype != 0x0800,
        "the ipv4 filter selects the probe frame"
    );
}

/// The XDP datapath's fallback honesty: unprivileged (the unshare
/// sandbox), the probe reports eBPF unavailable and capture falls
/// back to the AF_PACKET path with the downgrade note (pointed, never
/// a failure). Under the privileged CI gate the probe flips and the
/// XDP path engages — the note is absent.
#[test]
fn capture_xdp_fallback_note_matches_privileges() {
    if !driver_tests_enabled() {
        eprintln!("skipping (WREX_DRIVER_TESTS != 1)");
        return;
    }
    assert!(loopback_ready(false), "lo must be up");
    let dir = wrex_test::tempdir();
    let cap = dir.path().join("cap.pcap");
    // Hold the attach lock through the capture child's lifetime —
    // the filtered-capture sibling attaches too (one XDP program per
    // iface; concurrent attaches race, this is the serialization).
    let _attach = XDP_ATTACH.lock().unwrap_or_else(|p| p.into_inner());
    let out = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "capture",
            "-i",
            "lo",
            "--count",
            "1",
            "--timeout",
            "1s",
            "-w",
            cap.to_str().unwrap(),
        ])
        .output()
        .expect("spawn wrex capture");
    assert!(out.status.success(), "capture exits cleanly either way");
    let stderr = String::from_utf8_lossy(&out.stderr);
    match wrex_io::xdp::xdp_datapath_available() {
        Ok(()) => {
            // Privileged on an AF_XDP-capable kernel: the datapath must
            // ENGAGE (probe → compile → XSK open → prog load → LINK
            // create — every refusal step-tagged in the note; the
            // bpf_link fd owns the attachment, so a killed capture
            // can never orphan it). A downgrade note is a regression.
            // NOTE (the live-root post-mortem): the first two live
            // rounds showed EINVAL everywhere — that was OUR wrong
            // uapi constant (XSKMAP 42 vs the header's 17), not the
            // kernels; the header pass fixed it. This arm gates the
            // full chain (probe → compile → XSK open → prog load →
            // netlink attach) on every capable kernel.
            assert!(
                !stderr.contains("using the AF_PACKET path"),
                "XDP-capable kernel: the datapath must engage, got the downgrade note: {stderr}"
            );
            eprintln!("XDP datapath engaged (no downgrade note)");
        }
        Err(why) => {
            // No XDP for this process/kernel (privileges — the sandbox
            // class — or a build without CONFIG_XDP_SOCKETS): the
            // fallback note MUST print and name the honest cause.
            assert!(
                stderr.contains("using the AF_PACKET path"),
                "the downgrade note must print when the datapath is unavailable: {stderr}"
            );
            eprintln!("XDP unavailable ({why}) — the fallback engaged");
        }
    }
}

/// The FILTERED XDP datapath, end to end: `capture -i lo --filter
/// udp.dport=9` runs the filter walk (probe → compile → XSK open →
/// prog load → bpf_link) and the MATCHING frames must flow through
/// the XSK into the store — the one clean load the tranche's live
/// rounds never reached, now a ground truth instead of a manual
/// confirmation. Race-free by construction: paced probes run for the
/// capture's whole window (repeats defeat the startup attach race —
/// the roundtrip rule), `--count` ends the capture as soon as the
/// frames land, and the deadline bounds a broken datapath. The frame
/// assertions hold on EITHER datapath (the fallback's residual
/// userspace filter keeps semantics exact); only the note assert
/// branches on capability — the honest-split gate.
#[test]
fn filtered_xdp_capture_delivers_matching_frames() {
    if !driver_tests_enabled() {
        eprintln!("skipping (WREX_DRIVER_TESTS != 1)");
        return;
    }
    assert!(loopback_ready(false), "lo must be up");
    let dir = wrex_test::tempdir();
    let cap = dir.path().join("filtered.pcap");

    // Serialize with the fallback-note test: `lo` takes ONE XDP
    // program; a concurrent attach takes EBUSY, not a turn.
    let _attach = XDP_ATTACH.lock().unwrap_or_else(|p| p.into_inner());
    let mut capture = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "capture",
            "-i",
            "lo",
            "--filter",
            "udp.dport=9",
            "--count",
            "3",
            "--timeout",
            "12s",
            "-w",
            cap.to_str().unwrap(),
        ])
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn wrex capture");

    // Paced probes for the whole window: plain UDP to the discard
    // port (no capabilities — the stack reflects it through `lo`'s
    // ingress, where the XDP filter runs). Whenever the attach
    // completes, the next probe redirects; `--count 3` ends the
    // capture; the deadline bounds the broken case. The kernel's
    // ICMP port-unreachable replies to the probes are icmp — the
    // filter excludes them, so only probes fill the count.
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind probe socket");
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut probes = 0u32;
    while Instant::now() < deadline {
        if capture.try_wait().expect("poll capture").is_some() {
            break;
        }
        sock.send_to(b"wrex-xdp-probe", "127.0.0.1:9")
            .expect("send probe");
        probes += 1;
        std::thread::sleep(Duration::from_millis(150));
    }
    let out = capture.wait_with_output().expect("capture exits");
    drop(_attach);
    assert!(out.status.success(), "capture exited {}", out.status);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();

    // Datapath honesty (the fallback test's rule, on the FILTER
    // program this time): a capable kernel must ENGAGE the whole
    // chain — a downgrade note here is a regression; an unavailable
    // datapath must print it and name the honest cause.
    match wrex_io::xdp::xdp_datapath_available() {
        Ok(()) => assert!(
            !stderr.contains("using the AF_PACKET path"),
            "XDP-capable kernel: the FILTERED datapath must engage, got the downgrade note: {stderr}"
        ),
        Err(why) => assert!(
            stderr.contains("using the AF_PACKET path"),
            "the downgrade note must print when the datapath is unavailable ({why}): {stderr}"
        ),
    }

    // The frames flowed and the filter selected exactly them — on
    // either datapath (the store is the contract, not the road).
    let bytes = std::fs::read(&cap).expect("the capture file exists");
    let file = wrex_pcap::read(&bytes).expect("the capture parses");
    assert_eq!(file.linktype, wrex_pcap::linktype::EN10MB);
    assert_eq!(
        file.records.len(),
        3,
        "--count 3 must fill from the paced probes (sent {probes}); \
         the datapath dropped or never delivered matching frames"
    );
    assert!(probes >= 1, "the pacer must have run (sent {probes})");
    let mut inventory = Vec::new();
    for rec in &file.records {
        // The hopopts pattern, not the wrex-test helper: the helper's
        // PATH fallback cannot see `target-sudo/debug` under the sudo
        // env; `CARGO_BIN_EXE_wrex` is this package's own compile-time
        // guarantee (the sibling ground truths use the same).
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
            .write_all(&rec.bytes)
            .expect("pipe the captured frame");
        let dis = dissect.wait_with_output().expect("collect dissect");
        let parsed: serde_json::Value = serde_json::from_slice(&dis.stdout).expect("dissect json");
        let layers = parsed["layers"].as_array().cloned().unwrap_or_default();
        let kinds: Vec<&str> = layers
            .iter()
            .map(|l| l["kind"].as_str().unwrap_or("?"))
            .collect();
        let udp_dport = layers
            .iter()
            .find(|l| l["kind"] == "udp")
            .and_then(|l| l["fields"]["dport"].as_u64());
        inventory.push(format!(
            "{} -> {}",
            hex::encode(&rec.bytes),
            kinds.join(",")
        ));
        assert_eq!(
            udp_dport,
            Some(9),
            "every captured frame is the probe (filter leakage?): {}",
            parsed
        );
        assert!(kinds.contains(&"ipv4"), "the probe rides ipv4: {parsed}");
    }
    eprintln!("filtered capture inventory:\n{}", inventory.join("\n"));
}
