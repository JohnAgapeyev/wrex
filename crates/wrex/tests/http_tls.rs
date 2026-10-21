//! TLS CLI tests (tranche 8a): `wrex http https://…` and `wrex query
//! --tls` end-to-end against the in-test rustls stub server
//! (`wrex_test::tls_stub` — plain kernel sockets, no capabilities, no
//! external network: always-on, but not Miri-safe), plus the reqwest
//! (rustls-tls) in-process differential over the same stub.
#![cfg_attr(miri, ignore = "spawns the wrex binary; not Miri-safe")]

use std::time::Duration;

use assert_cmd::Command;
use wrex_test::tls_stub::{StubRequest, TlsStub};

fn wrex() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wrex"))
}

fn tmpdir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("wrex-tls-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const OK: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nhello world";
const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

/// `wrex http https://… --format json` parsed.
fn wrex_https(stub_addr: std::net::SocketAddr, extra: &[&str]) -> serde_json::Value {
    let url = format!("https://{stub_addr}/");
    let mut cmd = wrex();
    cmd.args(["http", "--format", "json"]).arg(&url).args(extra);
    let out = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&out).expect("json stdout")
}

#[test]
fn https_end_to_end_insecure() {
    let stub: TlsStub = wrex_test::tls_stub::spawn(OK.to_vec(), 3, 2, StubRequest::HttpHead);
    let json = wrex_https(stub.addr, &["--tls-insecure"]);
    assert_eq!(json["status"], 200);
    assert_eq!(json["reason"], "OK");
    assert_eq!(json["body_hex"], hex::encode("hello world"));
    assert_eq!(json["headers"]["content-type"][0], "text/plain");
}

#[test]
fn https_fail_on_404() {
    let stub = wrex_test::tls_stub::spawn(NOT_FOUND.to_vec(), 1, 2, StubRequest::HttpHead);
    let url = format!("https://{}/", stub.addr);
    // a completed exchange is data (exit 0) …
    wrex()
        .args(["http", "--tls-insecure", &url])
        .assert()
        .success();
    // … unless --fail opts into exit 1.
    wrex()
        .args(["http", "--tls-insecure", "--fail", &url])
        .assert()
        .code(1);
}

#[test]
fn https_tls_ca_verifies_the_self_signed_cert() {
    // Verifying path: no --tls-insecure, the stub's own cert trusted
    // through a --tls-ca PEM file (the --tls-ca contract end-to-end).
    let stub = wrex_test::tls_stub::spawn(OK.to_vec(), 2, 1, StubRequest::HttpHead);
    let pem = tmpdir().join("ca.pem");
    std::fs::write(&pem, &stub.ca_pem).unwrap();
    let json = wrex_https(stub.addr, &["--tls-ca", pem.to_str().unwrap()]);
    assert_eq!(json["status"], 200);
    assert_eq!(json["body_hex"], hex::encode("hello world"));

    // … and without it (or --tls-insecure) the handshake is exit 1.
    let url = format!("https://{}/", stub.addr);
    wrex()
        .args(["http", "--format", "json", &url])
        .assert()
        .code(1);
}

#[test]
fn https_recipe_tls_knob() {
    // recipe tls_insecure: true carries the insecure verifier.
    let stub = wrex_test::tls_stub::spawn(OK.to_vec(), 1, 2, StubRequest::HttpHead);
    let recipe = tmpdir().join("req-tls.json");
    std::fs::write(
        &recipe,
        format!(
            r#"{{"method": "GET", "url": "https://{}/", "tls_insecure": true}}"#,
            stub.addr
        ),
    )
    .unwrap();
    let out = wrex()
        .args([
            "http",
            "--recipe",
            recipe.to_str().unwrap(),
            "--format",
            "raw",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(out, b"hello world");
}

#[test]
fn https_differential_vs_reqwest() {
    // The in-process oracle (reqwest, rustls-tls feature — dev-only)
    // against the same stub: status, framing-sensitive body and
    // headers of interest must agree.
    let fixtures: &[(&str, &[u8])] = &[
        (
            "content-length",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nhello world",
        ),
        (
            "chunked-with-trailer",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: 1\r\n\r\n",
        ),
        (
            "until-close",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nread to the wire end",
        ),
    ];
    for (name, wire) in fixtures {
        let stub = wrex_test::tls_stub::spawn(wire.to_vec(), 3, 2, StubRequest::HttpHead);
        let ours = wrex_https(stub.addr, &["--tls-insecure"]);

        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(10))
            .build()
            .expect("reqwest client");
        let url = format!("https://{}/", stub.addr);
        let resp = client.get(&url).send().expect("reqwest send");
        let status = resp.status().as_u16();
        let theirs_headers = resp.headers().clone();
        let theirs_body = resp.bytes().expect("reqwest body");

        assert_eq!(ours["status"], status, "{name}: status differs");
        assert_eq!(
            ours["body_hex"],
            hex::encode(&theirs_body),
            "{name}: body differs"
        );
        for key in ["content-length", "content-type", "transfer-encoding"] {
            let ours_v = ours["headers"]
                .get(key)
                .and_then(|v| v.as_array())
                .and_then(|a| a.first())
                .and_then(|v| v.as_str())
                .map(str::to_string);
            let theirs_v = theirs_headers
                .get(key)
                .map(|v| v.to_str().unwrap().to_string());
            assert_eq!(ours_v, theirs_v, "{name}: {key} differs");
        }
    }
}

#[test]
fn query_dot_end_to_end() {
    // `wrex query --tls` (RFC 7858) against a TLS-wrapped DNS stub:
    // fresh TLS connection, length-prefixed wire, id-matched reply.
    let stub = wrex_test::tls_stub::spawn(Vec::new(), 1, 1, StubRequest::DnsReply);
    let out = wrex()
        .args([
            "query",
            "--tls",
            "--server",
            "127.0.0.1",
            "--port",
            &stub.addr.port().to_string(),
            "--tls-insecure",
            "--timeout",
            "800ms",
            "example.com",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&out);
    assert!(
        stdout.contains("an.0.rdata: 93.184.216.34"),
        "typed A rdata must surface\n{stdout}"
    );
}
