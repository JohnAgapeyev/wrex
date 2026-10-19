//! Query ground-truth tests (env-gated: `WREX_DRIVER_TESTS=1`): the
//! real `wrex query` over raw-IP injection against a kernel UDP stub
//! on `lo` — no external network, real sockets, real kernel routing.
//!
//! Spawns processes and opens raw sockets: ignored under Miri.
#![cfg_attr(miri, ignore = "raw sockets + subprocesses; not Miri-safe")]

use std::net::UdpSocket;
use std::process::Command;
use std::time::Duration;

fn driver_tests_enabled() -> bool {
    std::env::var("WREX_DRIVER_TESTS").as_deref() == Ok("1")
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
        // Answer the datagram's claimed source (the raw-socket sender);
        // the kernel routes it to loopback, where our AF_PACKET RX sees
        // it even though no kernel socket is bound to that port.
        let _ = sock.send_to(&reply, from);
    });
    (port, rx)
}

fn run_query(port: u16, args: &[&str]) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "query",
            "-i",
            "lo",
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
            "-i",
            "lo",
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
