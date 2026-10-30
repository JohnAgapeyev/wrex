//! Query ground-truth tests (env-gated: `WREX_DRIVER_TESTS=1`): the
//! real `wrex query` over its kernel UDP socket against a kernel UDP
//! stub on `lo` — no external network, real sockets, real kernel
//! routing (perf-pass 3b: the raw-IP + AF_PACKET tap path is retired;
//! these now pin the dig-style transport's semantics).
//!
//! Spawns processes: ignored under Miri.
#![cfg_attr(miri, ignore = "subprocesses; not Miri-safe")]

use std::net::UdpSocket;
use std::process::Command;
use std::time::Duration;

fn driver_tests_enabled() -> bool {
    // Capability probe (pass-2): lo must exist — a runner without
    // loopback is an environment problem, skip with a notice.
    std::env::var("WREX_DRIVER_TESTS").as_deref() == Ok("1") && wrex_test::loopback_ready(false)
}

fn skip(name: &str) {
    eprintln!("query driver tests: skipping {name} (WREX_DRIVER_TESTS != 1)");
}

/// DNS wire helpers (test-local: the stub builds replies by hand; the
/// craft-side surface lives in the codec unit tests).
fn build_reply(query: &[u8], rcode: u8, answer: bool) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&query[..2]); // echo id
    msg.extend_from_slice(&[0x81, 0x80 | rcode]); // qr, rd, ra | rcode
    // counts: qd=1, an=answer?, ns=0, ar=0 (eight bytes!)
    msg.extend_from_slice(&[0x00, 0x01, 0x00, u8::from(answer), 0x00, 0x00, 0x00, 0x00]);
    // question: echo verbatim (labels until the zero, then type/class)
    let mut at = 12usize;
    while query[at] != 0 {
        at += 1 + query[at] as usize;
    }
    at += 5;
    msg.extend_from_slice(&query[12..at]);
    if answer {
        msg.extend_from_slice(&[0xC0, 0x0C]); // owner -> question
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // ttl 60
        msg.extend_from_slice(&[0x00, 0x04, 93, 184, 216, 34]);
    }
    msg
}

/// One stub round: bind, answer one query with the given reply, return
/// (port, captured query).
fn stub(reply_kind: (u8, bool)) -> (u16, std::sync::mpsc::Receiver<Vec<u8>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind stub");
    let port = sock.local_addr().unwrap().port();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let _ = sock.set_read_timeout(Some(Duration::from_secs(20)));
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            return;
        };
        let query = buf[..n].to_vec();
        let _ = tx.send(query.clone());
        let reply = build_reply(&query, reply_kind.0, reply_kind.1);
        // Answer the datagram's source (the connected kernel socket's
        // 4-tuple demux routes the reply straight back to the query).
        let _ = sock.send_to(&reply, from);
    });
    (port, rx)
}

fn run_query(port: u16, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "query",
            "--server",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--timeout",
            "800ms",
        ])
        .args(args)
        .output()
        .expect("spawn wrex query");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

#[test]
fn query_ground_truth_reply() {
    if !driver_tests_enabled() {
        skip("query_ground_truth_reply");
        return;
    }
    let (port, query_rx) = stub((0, true));
    let (code, stdout, stderr) = run_query(port, &["example.com"]);
    assert_eq!(code, 0, "a reply is success regardless of rcode\n{stderr}");
    assert!(
        stdout.contains("an.0.rdata: 93.184.216.34"),
        "typed A rdata must surface in text output\n{stdout}"
    );
    assert!(stdout.contains("an.0.ttl: 60"), "{stdout}");

    // The query the stub saw must dissect and match the name/type.
    let query = query_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("no query");
    let registry = wrex::standard();
    let packet = wrex_core::dissect::dissect(&registry, &query, "dns");
    use wrex_core::value::Value;
    let dns = packet.layers.iter().find(|l| l.kind == "dns").unwrap();
    assert_eq!(
        dns.fields.get("qd.0.name"),
        Some(&Value::Str("example.com".into()))
    );
    assert_eq!(dns.fields.get("qd.0.type"), Some(&Value::Str("A".into())));
    assert!(matches!(
        dns.fields.get("flags"),
        Some(Value::List(items)) if items.contains(&Value::Str("rd".into()))
    ));
}

/// Tranche 10a: the query over a v6 server (`::1` stub on lo) — the
/// kernel socket speaks v6 natively; the reply dissects from dns.
#[test]
fn query_ground_truth_reply_v6() {
    if !driver_tests_enabled() {
        skip("query_ground_truth_reply_v6");
        return;
    }
    let sock = UdpSocket::bind("[::1]:0").expect("bind v6 stub");
    let port = sock.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let _ = sock.set_read_timeout(Some(Duration::from_secs(20)));
        let Ok((n, from)) = sock.recv_from(&mut buf) else {
            return;
        };
        let query = buf[..n].to_vec();
        let reply = build_reply(&query, 0, true);
        let _ = sock.send_to(&reply, from);
    });
    let out = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "query",
            "--server",
            "::1",
            "--port",
            &port.to_string(),
            "--timeout",
            "800ms",
            "example.com",
        ])
        .output()
        .expect("spawn wrex query");
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(code, 0, "v6 reply is success\n{stderr}\n{stdout}");
    assert!(
        stdout.contains("an.0.rdata: 93.184.216.34"),
        "typed A rdata must surface in the v6 text output\n{stdout}"
    );
}

#[test]
fn query_ground_truth_nxdomain_is_data() {
    if !driver_tests_enabled() {
        skip("query_ground_truth_nxdomain_is_data");
        return;
    }
    let (port, _rx) = stub((3, false)); // NXDOMAIN, no answers
    let (code, stdout, stderr) = run_query(port, &["missing.example.com"]);
    assert_eq!(
        code, 0,
        "NXDOMAIN is data (exit 0), not an error\n{stderr}\n{stdout}"
    );
    assert!(stdout.contains("rcode: 3"), "{stdout}");
}

#[test]
fn query_ground_truth_timeout_is_runtime_error() {
    if !driver_tests_enabled() {
        skip("query_ground_truth_timeout_is_runtime_error");
        return;
    }
    // No stub listens; --retries 0 for a fast exit.
    let out = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "query",
            "--server",
            "127.0.0.1",
            "--port",
            "53053",
            "--timeout",
            "300ms",
            "--retries",
            "0",
            "example.com",
        ])
        .output()
        .expect("spawn wrex query");
    let code = out.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert_eq!(code, 1, "silence is exit 1\n{stderr}");
    assert!(stderr.contains("no reply"), "{stderr}");
}

#[test]
fn query_seed_determinism_on_the_wire() {
    if !driver_tests_enabled() {
        skip("query_seed_determinism_on_the_wire");
        return;
    }
    // Two runs with the same seed against the same stub: the captured
    // queries must be byte-identical (source port + id from the seed).
    let mut queries = Vec::new();
    for _ in 0..2 {
        let (port, query_rx) = stub((0, true));
        let (code, _, stderr) = run_query(port, &["--seed", "1337", "example.com"]);
        assert_eq!(code, 0, "{stderr}");
        queries.push(
            query_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("no query"),
        );
    }
    assert_eq!(queries[0], queries[1], "same seed must be byte-identical");
}

#[test]
fn query_tcp_ground_truth() {
    if !driver_tests_enabled() {
        skip("query_tcp_ground_truth");
        return;
    }
    // A TCP DNS stub: read the 2-byte length prefix + query, reply with
    // the same id, length-prefixed. Plain sockets (no caps needed),
    // env-gated alongside the other wire tests for consistency.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let Ok((mut conn, _)) = listener.accept() else {
            return;
        };
        use std::io::{Read, Write};
        let mut len_buf = [0u8; 2];
        conn.read_exact(&mut len_buf).unwrap();
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut query = vec![0u8; len];
        conn.read_exact(&mut query).unwrap();
        // reply: id echoed, qr/rd/ra, one A answer
        let mut reply = Vec::new();
        reply.extend_from_slice(&query[..2]);
        reply.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
        reply.extend_from_slice(&query[12..]);
        reply.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 93, 184, 216,
            34,
        ]);
        conn.write_all(&(reply.len() as u16).to_be_bytes()).unwrap();
        conn.write_all(&reply).unwrap();
        let _ = conn.shutdown(std::net::Shutdown::Write);
    });

    let out = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "query",
            "--server",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--tcp",
            "--timeout",
            "800ms",
            "example.com",
        ])
        .output()
        .expect("spawn wrex query --tcp");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "query --tcp must succeed\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("an.0.rdata: 93.184.216.34"),
        "typed A rdata must surface\n{stdout}"
    );
    server.join().unwrap();
}

/// Tranche 20a: `--edns SIZE` advertises EDNS0 on the wire — the stub
/// captures the query and asserts the OPT record landed (arcount 1,
/// the class field = the advertised size, the DO bit set with
/// `--edns-do`); the reply (no OPT) still dissects clean.
#[test]
fn query_ground_truth_edns() {
    if !driver_tests_enabled() {
        skip("query_ground_truth_edns");
        return;
    }
    let (port, query_rx) = stub((0, true));
    let (code, stdout, stderr) = run_query(port, &["--edns", "1232", "--edns-do", "example.com"]);
    assert_eq!(code, 0, "a reply is success regardless of rcode\n{stderr}");
    assert!(
        stdout.contains("an.0.rdata: 93.184.216.34"),
        "the reply's answer must surface\n{stdout}"
    );
    // The stub's query carries the OPT record: arcount=1, class=1232,
    // DO set (word bit 15 of the ttl).
    let query = query_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("no query");
    let registry = wrex::standard();
    let p = wrex_core::dissect::dissect(&registry, &query, "dns");
    assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
    let dns = p.layers.iter().find(|l| l.kind == "dns").unwrap();
    assert_eq!(dns.fields.get("arcount"), Some(&wrex_core::Value::Int(1)));
    assert_eq!(
        dns.fields.get("ar.0.type"),
        Some(&wrex_core::Value::Str("OPT".into()))
    );
    assert_eq!(
        dns.fields.get("ar.0.udp_size"),
        Some(&wrex_core::Value::Int(1232))
    );
    assert_eq!(
        dns.fields.get("ar.0.do"),
        Some(&wrex_core::Value::Bool(true))
    );
}
