//! Query CLI grammar tests (assert_cmd, no sockets): usage errors (exit
//! 2) and the runtime-capability path (exit 1) all resolve before any
//! raw socket opens. Real-socket ground truth lives in `query_driver.rs`
//! (env-gated `WREX_DRIVER_TESTS=1`).
//!
//! Spawns the `wrex` binary: ignored under Miri.
#![cfg_attr(miri, ignore = "spawns the wrex binary; not Miri-safe")]

use assert_cmd::Command;

fn wrex() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wrex"))
}

fn query_err(args: &[&str]) -> (i32, String) {
    let out = wrex()
        .args(["query"])
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
fn server_required() {
    let (code, stderr) = query_err(&["example.com"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("query requires --server"), "{stderr}");

    // --server alone (no -i): accepted on every transport now (perf-
    // pass 3b: kernel sockets; -i only pins the source address) —
    // grammar errors are the only exit-2 class before sockets.
    let (code, stderr) = query_err(&["--server", "127.0.0.1", "a..b"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("label"), "{stderr}");
}

#[test]
fn grammar_errors_are_usage() {
    // bad type
    let (code, stderr) = query_err(&[
        "-i",
        "lo",
        "--server",
        "127.0.0.1",
        "--type",
        "BOGUS",
        "example.com",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown dns type"), "{stderr}");

    // bad class
    let (code, stderr) = query_err(&[
        "-i",
        "lo",
        "--server",
        "127.0.0.1",
        "--class",
        "NOPE",
        "example.com",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown dns class"), "{stderr}");

    // bad server
    let (code, stderr) = query_err(&["-i", "lo", "--server", "not-an-ip", "example.com"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("bad server"), "{stderr}");

    // bad name fails at encode (usage layer, before sockets)
    let (code, stderr) = query_err(&["-i", "lo", "--server", "127.0.0.1", "a..b"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("empty label"), "{stderr}");

    // raw/hex formats carry no reply
    let (code, stderr) = query_err(&[
        "-i",
        "lo",
        "--server",
        "127.0.0.1",
        "--format",
        "raw",
        "example.com",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("text|json|jsonl"), "{stderr}");

    // bad timeout duration
    let (code, stderr) = query_err(&[
        "-i",
        "lo",
        "--server",
        "127.0.0.1",
        "--timeout",
        "zz",
        "example.com",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("duration"), "{stderr}");
}

#[test]
fn unknown_iface_is_runtime_not_usage() {
    // unknown iface → exit 1 (table lookup happens before sockets)
    let (code, stderr) = query_err(&[
        "-i",
        "definitely-not-here",
        "--server",
        "127.0.0.1",
        "example.com",
    ]);
    assert_eq!(code, 1);
    assert!(stderr.contains("unknown iface"), "{stderr}");
}

#[test]
fn help_renders_the_query_grammar() {
    let out = wrex()
        .args(["query", "--help"])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--server"), "{stdout}");
    assert!(stdout.contains("--seed"), "{stdout}");
    assert!(stdout.contains("NXDOMAIN"), "{stdout}");
}

/// Tranche 10a: `--server` accepts either family — and since perf-
/// pass 3b every transport is a kernel socket, so no -i is demanded
/// anywhere; a v6 server without -i is past the usage gates (a dead
/// port is a runtime failure, not a usage error).
#[test]
fn v6_server_is_in_charter() {
    // A v6 literal is NOT a bad-server usage error.
    let (code, stderr) = query_err(&["-i", "lo", "--server", "::1", "a..b"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("label") && !stderr.contains("bad server"),
        "{stderr}"
    );

    // --tcp over a dead ::1 port: connect refusal is a runtime error
    // (exit 1) — proving the v6 family went past the usage gates into
    // the (now dual-family) kernel driver.
    let out = wrex()
        .args([
            "query",
            "--tcp",
            "--server",
            "::1",
            "--port",
            "1",
            "--timeout",
            "200ms",
            "example.com",
        ])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("query --tcp") || stderr.contains("no reply"),
        "{stderr}"
    );
}

// --- tranche 20 -----------------------------------------------------------

/// 20a-1: --edns/--edns-do grammar gates (the OPT record rides the
/// session's validate, exit 2 before any socket).
#[test]
fn edns_grammar_gates() {
    // A size below the RFC 6891 §6.2.5 floor is a pointed usage error.
    let (code, stderr) = query_err(&["--server", "127.0.0.1", "--edns", "100", "example.com"]);
    assert_eq!(code, 2);
    assert!(stderr.contains(">= 512"), "{stderr}");
    // --edns-do implies a legal default size (passes the gates; a dead
    // port is a runtime failure after).
    let (code, stderr) = query_err(&["--server", "127.0.0.1", "--edns-do", "a..b"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("label"), "{stderr}");
}

/// 20a-2: --reverse (dig -x) sugar grammar.
#[test]
fn reverse_grammar_gates() {
    let (code, stderr) = query_err(&["--reverse", "--server", "127.0.0.1", "not-an-ip"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("wants an IP"), "{stderr}");
    // --reverse forces PTR; an explicit other type conflicts.
    let (code, stderr) = query_err(&[
        "--reverse",
        "--server",
        "127.0.0.1",
        "--type",
        "MX",
        "192.168.1.10",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("forces the question type PTR"), "{stderr}");
    // --reverse of an IP composes the in-addr.arpa name (a dead port is
    // the runtime class — the grammar itself passes).
    let out = wrex()
        .args([
            "query",
            "--reverse",
            "--server",
            "127.0.0.1",
            "--port",
            "1",
            "--timeout",
            "200ms",
            "192.168.1.10",
        ])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1));
}

/// 20b: --mdns and --doh grammar gates.
#[test]
fn mdns_doh_grammar_gates() {
    // --mdns supplies its own server (the multicast group): no
    // --server-required usage error; the bad name fails first.
    let (code, stderr) = query_err(&["--mdns", "a..b"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("label"), "{stderr}");
    // --doh conflicts are pointed.
    for (flag, on) in [
        ("--tcp", vec!["--tcp"]),
        ("--tls", vec!["--tls"]),
        ("--server", vec!["--server", "127.0.0.1"]),
        ("--port", vec!["--port", "53"]),
        ("--mdns", vec!["--mdns"]),
    ] {
        let mut args = vec!["--doh", "http://127.0.0.1:1/dns-query"];
        args.extend(&on);
        args.push("example.com");
        let (code, stderr) = query_err(&args);
        assert_eq!(code, 2, "{flag}");
        assert!(stderr.contains("are exclusive"), "{flag}: {stderr}");
    }
    // A non-http scheme is a usage error.
    let (code, stderr) = query_err(&["--doh", "ftp://example/dns-query", "example.com"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("scheme"), "{stderr}");
    // --short rides the text format only.
    let (code, stderr) = query_err(&[
        "--doh",
        "http://127.0.0.1:1/dns-query",
        "--format",
        "json",
        "--short",
        "example.com",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("--short"), "{stderr}");
}

/// 20b: `wrex query --doh` end-to-end against a plain-socket HTTP/1.1
/// stub (the tls_stub lineage, no TLS): the POST body is the bare dns
/// query, the 200 body dissects as the reply, --short prints the
/// answer values. Spawns sockets: env-gated like the driver suites.
#[test]
fn doh_end_to_end_against_a_plain_stub() {
    if std::env::var("WREX_DRIVER_TESTS").as_deref() != Ok("1") {
        eprintln!("doh: skipping (WREX_DRIVER_TESTS unset)");
        return;
    }
    use std::io::{Read as _, Write as _};
    // The canned reply: qr/rd/ra, one A answer (93.184.216.34), the
    // owner a compression pointer to the question name.
    let reply = |query: &[u8]| {
        let mut msg = vec![
            query[0], query[1], 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        let name_end = {
            let mut at = 12usize;
            while at < query.len() && query[at] != 0 {
                at += 1 + query[at] as usize;
            }
            at + 1
        };
        msg.extend_from_slice(&query[12..name_end + 4]);
        msg.extend_from_slice(&[
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 93, 184, 216,
            34,
        ]);
        msg
    };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let url = format!("http://127.0.0.1:{}/dns-query", addr.port());
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let mut buf = [0u8; 4096];
        let n = sock.read(&mut buf).expect("read request");
        let request = String::from_utf8_lossy(&buf[..n]).to_string();
        // The stub sees a real RFC 8484 POST.
        assert!(
            request.starts_with("POST /dns-query "),
            "unexpected request: {request}"
        );
        assert!(
            request.contains("content-type: application/dns-message"),
            "{request}"
        );
        // The body (after the blank line) is the bare dns query.
        let body = request
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or_default()
            .as_bytes()
            .to_vec();
        let answer = reply(&body);
        let mut resp = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            answer.len()
        )
        .into_bytes();
        resp.extend_from_slice(&answer);
        let _ = sock.write_all(&resp);
    });
    let out = wrex()
        .args([
            "query",
            "--doh",
            &url,
            "--timeout",
            "2s",
            "--seed",
            "7",
            "--short",
            "example.com",
        ])
        .output()
        .expect("spawn wrex query --doh");
    let _ = server.join();
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.trim() == "93.184.216.34", "stdout: {stdout:?}");
}

/// 20a-2: the settable answer-record craft flags enumerate (the index-0
/// paths through the registry) and roundtrip through dissection.
#[test]
fn craft_answer_record_flags_roundtrip() {
    // A one-record answer: MX, preference 10, exchange mail.example.com
    // (rdata wire hex).
    let craft = wrex()
        .args([
            "craft",
            "--format",
            "raw",
            "--layer",
            "dns",
            "--dns-name",
            "example.com",
            "--dns-an-0-name",
            "example.com",
            "--dns-an-0-type",
            "MX",
            "--dns-an-0-rdata",
            "hex:000a046d61696c076578616d706c6503636f6d00",
        ])
        .output()
        .expect("spawn wrex craft");
    assert!(
        craft.status.success(),
        "{}",
        String::from_utf8_lossy(&craft.stderr)
    );
    let out = wrex()
        .args(["dissect", "--start", "dns", "--format", "json"])
        .write_stdin(craft.stdout.clone())
        .assert()
        .success()
        .get_output()
        .clone();
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"an.0.mx.preference\": 10"), "{json}");
    assert!(
        json.contains("\"an.0.mx.exchange\": \"mail.example.com\""),
        "{json}"
    );
    assert!(json.contains("\"an.0.type\": \"MX\""), "{json}");
}

/// 20a-1: the EDNS sugar flags enumerate on craft (the flat `edns`
/// field family) and land a typed OPT record.
#[test]
fn craft_edns_flags_land_typed_opt() {
    let craft = wrex()
        .args([
            "craft",
            "--format",
            "raw",
            "--layer",
            "dns",
            "--dns-name",
            "example.com",
            "--dns-edns",
            "1232",
            "--dns-edns_do",
            "1",
            "--dns-edns_options",
            "nsid:ab12",
        ])
        .output()
        .expect("spawn wrex craft");
    assert!(
        craft.status.success(),
        "{}",
        String::from_utf8_lossy(&craft.stderr)
    );
    let out = wrex()
        .args(["dissect", "--start", "dns", "--format", "json"])
        .write_stdin(craft.stdout.clone())
        .assert()
        .success()
        .get_output()
        .clone();
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"ar.0.udp_size\": 1232"), "{json}");
    assert!(json.contains("\"ar.0.do\": true"), "{json}");
    assert!(json.contains("\"ar.0.opt.0.code\": 3"), "{json}");
}
