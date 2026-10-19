//! dig subprocess differential (env-gated: `WREX_DIFF_DIG=1` + dig on
//! PATH; the CI differential job installs dnsutils and sets the env).
//! No external network: an in-test stub UDP responder plays the server.
//!
//! Two directions, both against ground truth:
//! 1. **Query side**: dig sends `example.com A` at the stub; we dissect
//!    the captured query bytes and compare them field-for-field with
//!    our own craft of the same question (id and EDNS OPT aside — dig
//!    picks a random id and always appends an OPT record).
//! 2. **Reply side**: the stub answers with a hand-built A reply (with
//!    a compression pointer — we exercise pointer decode against dig's
//!    rendering); dig must print the answer our dissection carries.
//!
//! Spawns dig and binds UDP sockets: ignored under Miri.
#![cfg_attr(miri, ignore = "subprocess dig; not Miri-safe")]

use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use wrex_core::Registry;

fn dig_enabled() -> bool {
    (std::env::var("WREX_DIFF_DIG").as_deref() == Ok("1") || which_dig().is_some())
        && which_dig().is_some()
}

fn which_dig() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|p| p.join("dig"))
        .find(|p| p.is_file())
}

fn registry() -> Registry {
    wrex::standard()
}

/// The reply the stub serves: qr/rd/ra, one A answer (93.184.216.34),
/// owner name as a compression pointer to the question (exercises the
/// pointer path on both dissectors).
fn build_reply(query: &[u8], echo_id: bool) -> Vec<u8> {
    let id: [u8; 2] = if echo_id {
        [query[0], query[1]]
    } else {
        [0x12, 0x34]
    };
    let mut msg = Vec::new();
    msg.extend_from_slice(&id);
    msg.extend_from_slice(&[0x81, 0x80]); // qr, rd, ra
    msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    // Question: echo the question section verbatim. The qname starts
    // after the 12-byte header; scan labels to the terminating zero,
    // then the 4 type/class bytes.
    let name_end = {
        let mut at = 12usize;
        while at < query.len() && query[at] != 0 {
            at += 1 + query[at] as usize;
        }
        at + 1
    };
    let question = &query[12..name_end + 4];
    msg.extend_from_slice(question);
    // Answer: pointer to the question name (offset 12), A, IN, ttl, rdata.
    msg.extend_from_slice(&[0xC0, 0x0C]);
    msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
    msg.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // ttl 300
    msg.extend_from_slice(&[0x00, 0x04, 93, 184, 216, 34]);
    msg
}

/// Stub UDP server: captures one dig query, serves the hand-built
/// reply, forwards the query bytes back to the test.
fn stub_server() -> (std::net::SocketAddr, mpsc::Receiver<Vec<u8>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind stub");
    let addr = sock.local_addr().expect("addr");
    let (tx_query, query_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(_) => return,
        };
        let query = buf[..n].to_vec();
        let _ = tx_query.send(query.clone());
        let reply = build_reply(&query, true);
        let _ = sock.send_to(&reply, from);
        // The reply is queued in the kernel; the socket may close now.
    });
    (addr, query_rx)
}

#[test]
fn dns_differential_dig_stub_server() {
    if !dig_enabled() {
        eprintln!("dns_dig: skipping (dig not on PATH or WREX_DIFF_DIG unset)");
        return;
    }
    let (addr, query_rx) = stub_server();
    let port = addr.port();

    let out = Command::new(which_dig().unwrap())
        .args([
            "@127.0.0.1",
            "-p",
            &port.to_string(),
            "example.com",
            "A",
            "+short",
            "+time=2",
            "+tries=1",
            "+ignore",
            "+noedns",
            "+noad",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn dig");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(out.status.success(), "dig failed: {stdout}");
    // dig rendered our hand-built answer.
    assert!(
        stdout.contains("93.184.216.34"),
        "dig did not print the answer: {stdout}"
    );

    let query = query_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("stub saw no query");

    // --- Query side: dissect dig's query, compare with our craft ------
    let reg = registry();
    let packet = wrex_core::dissect::dissect(&reg, &query, "dns");
    let dns = packet
        .layers
        .iter()
        .find(|l| l.kind == "dns")
        .expect("dig query must dissect into a dns layer");
    use wrex_core::value::Value;
    assert_eq!(
        dns.fields.get("qd.0.name"),
        Some(&Value::Str("example.com".into())),
        "{:?}",
        dns.fields
    );
    assert_eq!(dns.fields.get("qd.0.type"), Some(&Value::Str("A".into())));
    assert_eq!(dns.fields.get("qd.0.class"), Some(&Value::Str("IN".into())));
    let flags = dns.fields.get("flags").expect("flags");
    assert!(
        matches!(flags, Value::List(items) if items.contains(&Value::Str("rd".into()))),
        "dig sets rd: {flags:?}"
    );

    // Our craft of the same question must agree on everything dig and
    // we share: ids are random (strip the 2-byte id), and +noedns drops
    // dig's OPT record so the bodies compare byte-for-byte.
    let our = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args([
            "craft",
            "--format",
            "raw",
            "--layer",
            "dns",
            "--dns-name=example.com",
            "--dns-type=A",
            "--dns-flags-rd",
        ])
        .output()
        .expect("spawn wrex craft");
    assert!(our.status.success());
    let our = our.stdout;
    let strip = |b: &[u8]| b[2..].to_vec();
    assert_eq!(
        strip(&query),
        strip(&our),
        "dig's query body differs from our craft\n dig: {}\nours: {}",
        hex::encode(strip(&query)),
        hex::encode(strip(&our))
    );

    // --- Reply side: our dissect of the served reply vs dig's output --
    let reply = build_reply(&query, true);
    let packet = wrex_core::dissect::dissect(&reg, &reply, "dns");
    let dns = packet.layers.iter().find(|l| l.kind == "dns").unwrap();
    assert!(packet.anomalies.is_empty(), "{:?}", packet.anomalies);
    assert_eq!(
        dns.fields.get("an.0.name"),
        Some(&Value::Str("example.com".into())),
        "compression pointer must resolve to the question name"
    );
    assert_eq!(
        dns.fields.get("an.0.rdata"),
        Some(&Value::Ipv4("93.184.216.34".parse().unwrap()))
    );
    assert_eq!(dns.fields.get("an.0.ttl"), Some(&Value::Int(300)));
}
