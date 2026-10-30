//! Scan ground-truth tests (env-gated: `WREX_DRIVER_TESTS=1`): real
//! probes on `lo` against real kernel endpoints — a bound TCP listener
//! must classify open, an unbound port closed (kernel RST), a bound UDP
//! socket open|filtered, an unbound one closed (kernel ICMP unreach),
//! and 127.0.0.1 alive under icmp. Auto-skip otherwise.
//!
//! Spawns processes and opens raw sockets: ignored under Miri.
#![cfg_attr(miri, ignore = "raw sockets + subprocesses; not Miri-safe")]

use std::io::Read;
use std::net::{TcpListener, UdpSocket};
use std::process::{Command, Stdio};
use std::time::Duration;

fn driver_tests_enabled() -> bool {
    // Capability probe (pass-2): lo must exist — a runner without
    // loopback is an environment problem, skip with a notice.
    std::env::var("WREX_DRIVER_TESTS").as_deref() == Ok("1") && wrex_test::loopback_ready(false)
}

/// Run `wrex scan …`, return (exit code, stdout).
fn scan_out(timeout: &str, args: &[&str]) -> (i32, String) {
    let mut all: Vec<std::ffi::OsString> = vec![
        "scan".into(),
        "-i".into(),
        "lo".into(),
        "--timeout".into(),
        timeout.into(),
    ];
    for a in args {
        all.push((*a).into());
    }
    let out = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args(&all)
        .output()
        .expect("spawn wrex scan");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

fn skip(name: &str) {
    eprintln!("scan driver tests: skipping {name} (WREX_DRIVER_TESTS != 1)");
}

/// Strip the wall-clock rtt suffix (`…  (2ms)`) from scan lines before
/// a reproducibility compare: the seed pins identities and schedule,
/// not the runner's timing (the fuzz driver suite projects out the
/// same fields — see its seed-reproducibility test).
fn strip_rtt(out: &str) -> String {
    out.lines()
        .map(|l| match (l.ends_with("ms)"), l.rfind("  (")) {
            (true, Some(at)) => &l[..at],
            _ => l,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Bind a TCP listener on an ephemeral 127.0.0.1 port.
fn tcp_listener() -> TcpListener {
    TcpListener::bind("127.0.0.1:0").expect("bind tcp")
}

fn bound_port(l: &TcpListener) -> u16 {
    l.local_addr().expect("local addr").port()
}

#[test]
fn syn_scan_ground_truth() {
    if !driver_tests_enabled() {
        skip("syn_scan_ground_truth");
        return;
    }
    // a closed ephemeral port: bind then drop
    let closed = {
        let l = tcp_listener();
        let p = bound_port(&l);
        drop(l);
        p
    };
    let open_l = tcp_listener();
    let open = bound_port(&open_l);

    let ports = format!("{open},{closed}");
    let (code, stdout) = scan_out("800ms", &["--ports", &ports, "127.0.0.1"]);
    assert_eq!(code, 0, "scan completed");
    assert!(
        stdout.contains(&format!("127.0.0.1  {open}/tcp  open")),
        "bound listener must classify open\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("127.0.0.1  {closed}/tcp  closed")),
        "unbound port must classify closed\n{stdout}"
    );
    drop(open_l);
}

#[test]
fn connect_scan_ground_truth() {
    if !driver_tests_enabled() {
        skip("connect_scan_ground_truth");
        return;
    }
    let l = tcp_listener();
    let port = bound_port(&l);
    let ports = port.to_string();
    let (code, stdout) = scan_out(
        "800ms",
        &["--mode", "connect", "--ports", &ports, "127.0.0.1"],
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains(&format!("127.0.0.1  {port}/tcp  open")),
        "connect scan must see the listener open\n{stdout}"
    );
}

#[test]
fn udp_scan_ground_truth() {
    if !driver_tests_enabled() {
        skip("udp_scan_ground_truth");
        return;
    }
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    let bound = sock.local_addr().expect("addr").port();
    let unbound = {
        let s = UdpSocket::bind("127.0.0.1:0").expect("bind udp");
        let p = s.local_addr().unwrap().port();
        drop(s);
        p
    };
    let ports = format!("{bound},{unbound}");
    let (code, stdout) = scan_out("800ms", &["--mode", "udp", "--ports", &ports, "127.0.0.1"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains(&format!("127.0.0.1  {bound}/udp  open|filtered")),
        "bound udp socket must classify open|filtered (no reply scripted)\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("127.0.0.1  {unbound}/udp  closed")),
        "unbound udp port must classify closed (kernel ICMP unreach)\n{stdout}"
    );
}

#[test]
fn icmp_scan_ground_truth() {
    if !driver_tests_enabled() {
        skip("icmp_scan_ground_truth");
        return;
    }
    let (code, stdout) = scan_out("800ms", &["--mode", "icmp", "127.0.0.1"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("127.0.0.1  icmp  alive"),
        "loopback must answer echo requests\n{stdout}"
    );
}

/// Seed determinism over a fully-filtered scan (no listeners): two runs
/// with the same seed emit byte-identical text output.
#[test]
fn seed_determinism_ground_truth() {
    if !driver_tests_enabled() {
        skip("seed_determinism_ground_truth");
        return;
    }
    // a definitely-closed high port
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = bound_port(&l);
    drop(l);
    let ports = format!("{port}");
    let args = [
        "--ports".to_string(),
        ports,
        "--seed".to_string(),
        "1337".to_string(),
        "127.0.0.1".to_string(),
    ];
    let run = || {
        let out = Command::new(env!("CARGO_BIN_EXE_wrex"))
            .args(["scan", "-i", "lo", "--timeout", "300ms"])
            .args(&args)
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn scan")
            .wait_with_output()
            .expect("wait");
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).to_string()
    };
    let a = run();
    let b = run();
    // The deterministic content (target/port/proto/state/attempts)
    // must match byte-for-byte; the rtt suffix is wall-clock.
    assert_eq!(
        strip_rtt(&a),
        strip_rtt(&b),
        "same seed must be byte-reproducible (modulo rtt)\n{a}\n{b}"
    );
    assert!(a.contains("closed"), "closed port expected\n{a}");

    // pacing sanity: whole scan finishes well under a sane wall budget
    let t0 = std::time::Instant::now();
    let _ = run();
    assert!(t0.elapsed() < Duration::from_secs(30), "scan took too long");
}

/// RawIpDriver ground truth via the scan verb with a scripted-free path:
/// two concurrent scans must not cross-match each other (distinct seeds
/// give distinct source ports, and reply matching is 4-tuple keyed).
#[test]
fn concurrent_scans_do_not_cross_match() {
    if !driver_tests_enabled() {
        skip("concurrent_scans_do_not_cross_match");
        return;
    }
    let l = tcp_listener();
    let open = bound_port(&l);
    let closed = {
        let c = tcp_listener();
        let p = bound_port(&c);
        drop(c);
        p
    };
    let ports = format!("{open},{closed}");
    let args = ["--ports", &ports, "127.0.0.1"];
    let mut procs = Vec::new();
    for i in 0..3 {
        let mut all: Vec<std::ffi::OsString> = vec![
            "scan".into(),
            "-i".into(),
            "lo".into(),
            "--timeout".into(),
            "800ms".into(),
            "--seed".into(),
            format!("42424{i}").into(),
        ];
        for a in args {
            all.push(a.into());
        }
        procs.push(
            Command::new(env!("CARGO_BIN_EXE_wrex"))
                .args(&all)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn scan"),
        );
    }
    for (i, mut p) in procs.into_iter().enumerate() {
        let mut out = String::new();
        if let Some(mut stdout) = p.stdout.take() {
            stdout.read_to_string(&mut out).expect("read stdout");
        }
        let status = p.wait().expect("wait");
        assert!(status.success(), "scan failed: {out}");
        assert!(
            out.contains(&format!("127.0.0.1  {open}/tcp  open")),
            "concurrent scan {i} must still classify the listener open\n{out}"
        );
        assert!(
            out.contains(&format!("127.0.0.1  {closed}/tcp  closed")),
            "concurrent scan {i} must still classify the closed port\n{out}"
        );
    }
    drop(l);
}

/// The burst-reply drop class (the perf-diff scan finding): a
/// 1000-port `--rate 0` scan against all-closed loopback ports must
/// classify every port closed. With the kernel's default 212992-byte
/// tap receive buffer the initial 256-probe burst's reply tail was
/// silently dropped (256 − ~222-frame capacity = 34 frames) and every
/// dropped probe paid the double 1s timeout, reporting "filtered" on
/// a port that answered in 4µs. The tap's SO_RCVBUF bump (wrex-io
/// rx.rs) is the fix; this is its tripwire. The assertion is
/// zero-filtered (drop counts vary with the runner's
/// `net.core.rmem_default`), plus a wall ceiling that fails when
/// timeout tails (the pre-fix 2s signature) reappear.
#[test]
fn burst_scan_loses_no_replies() {
    if !driver_tests_enabled() {
        skip("burst_scan_loses_no_replies");
        return;
    }
    // 2000-2999: below the ephemeral range and unbound in this suite
    // (listeners here bind :0), so every port answers RST instantly.
    let start = std::time::Instant::now();
    let (code, stdout) = scan_out("1s", &["--rate", "0", "--ports", "2000-2999", "127.0.0.1"]);
    assert_eq!(code, 0, "scan completed\n{stdout}");
    let classified = stdout.lines().filter(|l| l.contains("/tcp")).count();
    assert_eq!(classified, 1000, "every probed port classifies\n{stdout}");
    assert!(
        !stdout.contains("filtered"),
        "a dropped reply is a misclassification, not a filtered port \
         (tap receive-buffer overflow)\n{stdout}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "burst wall {:?} — timeout tails mean dropped replies",
        start.elapsed()
    );
}

// --- T21: variant modes, timing templates, --service (ground truth) -----------

/// A bound listener over `lo` answers nothing (no accept loop): a
/// FIN/NULL/XMAS probe on it gets silence → `open|filtered`; an
/// unbound port answers RST → `closed`. An ACK probe on the unbound
/// port must classify `unfiltered`.
#[test]
fn fin_null_xmas_ack_ground_truth() {
    if !driver_tests_enabled() {
        skip("fin_null_xmas_ack_ground_truth");
        return;
    }
    let open_l = tcp_listener();
    let open = bound_port(&open_l);
    let closed = {
        let l = tcp_listener();
        let p = bound_port(&l);
        drop(l);
        p
    };
    let ports = format!("{open},{closed}");
    for mode in ["fin", "null", "xmas"] {
        let (code, stdout) = scan_out("800ms", &["--mode", mode, "--ports", &ports, "127.0.0.1"]);
        assert_eq!(code, 0, "{mode}");
        assert!(
            stdout.contains(&format!("127.0.0.1  {closed}/tcp  closed")),
            "{mode}: unbound port must classify closed (kernel RST)\n{stdout}"
        );
        assert!(
            stdout.contains(&format!("127.0.0.1  {open}/tcp  open|filtered")),
            "{mode}: bound-but-silent listener classifies open|filtered\n{stdout}"
        );
    }
    // ack: the kernel RST on the unbound port proves it unfiltered (the
    // bound-but-silent port may answer RST or stay silent per stack
    // mood — the mode's claim is only about the RST-answered case, so
    // assert the certain half).
    let (code, stdout) = scan_out("800ms", &["--mode", "ack", "--ports", &ports, "127.0.0.1"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains(&format!("127.0.0.1  {closed}/tcp  unfiltered")),
        "ack: RST → unfiltered\n{stdout}"
    );
}

/// `-T4` sugar rides the same machinery: aggressive template, fast
/// timeout, same classifications.
#[test]
fn timing_template_ground_truth() {
    if !driver_tests_enabled() {
        skip("timing_template_ground_truth");
        return;
    }
    let closed = {
        let l = tcp_listener();
        let p = bound_port(&l);
        drop(l);
        p
    };
    let ports = closed.to_string();
    let (code, stdout) = scan_out("800ms", &["-T", "4", "--ports", &ports, "127.0.0.1"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains(&format!("127.0.0.1  {closed}/tcp  closed")),
        "-T4 must reach the same classification\n{stdout}"
    );
}

/// `--service` post-pass: a stub SSH banner on an open port renders
/// the additive service suffix (text) and key (jsonl). The stub keeps
/// accepting until the deadline — the scan's own connection and every
/// service probe connection each consume one accept.
#[test]
fn service_probe_ground_truth() {
    if !driver_tests_enabled() {
        skip("service_probe_ground_truth");
        return;
    }
    fn banner_stub(l: TcpListener) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            let _ = l.set_nonblocking(true);
            while std::time::Instant::now() < deadline {
                match l.accept() {
                    Ok((mut s, _)) => {
                        use std::io::Write as _;
                        let _ = s.write_all(b"SSH-2.0-OpenSSH_9.6p1 wrex-test\r\n");
                        let _ = s.flush();
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
                }
            }
        })
    }
    // text pass
    let l1 = tcp_listener();
    let port1 = bound_port(&l1);
    let jh1 = banner_stub(l1);
    let ports1 = port1.to_string();
    let (code, stdout) = scan_out(
        "800ms",
        &[
            "--mode",
            "connect",
            "--ports",
            &ports1,
            "--service",
            "--seed",
            "42",
            "127.0.0.1",
        ],
    );
    let _ = jh1.join();
    assert_eq!(code, 0);
    assert!(
        stdout.contains(&format!(
            "127.0.0.1  {port1}/tcp  open  ssh/OpenSSH_9.6p1 wrex-test"
        )),
        "service suffix must render on the text line\n{stdout}"
    );
    // jsonl pass: the additive keys
    let l2 = tcp_listener();
    let port2 = bound_port(&l2);
    let jh2 = banner_stub(l2);
    let ports2 = port2.to_string();
    let (code, out_jsonl) = scan_out(
        "800ms",
        &[
            "--mode",
            "connect",
            "--ports",
            &ports2,
            "--service",
            "--seed",
            "42",
            "--format",
            "jsonl",
            "127.0.0.1",
        ],
    );
    let _ = jh2.join();
    assert_eq!(code, 0);
    assert!(
        out_jsonl.contains("\"service\":\"ssh\""),
        "service key must be additive in jsonl\n{out_jsonl}"
    );
    assert!(
        out_jsonl.contains("\"version\":\"OpenSSH_9.6p1 wrex-test\""),
        "version capture must ride\n{out_jsonl}"
    );
}
