//! HTTP/2 CLI tests (tranche 15 + 16): `wrex http --http-version 2`
//! over https end-to-end against the in-test rustls+ALPN h2 stub
//! (`wrex_test::h2_stub` — plain kernel sockets, no capabilities, no
//! external network: always-on, but not Miri-safe): the h2 happy
//! path, concurrent streams on one connection, the ALPN auto-downgrade
//! note, the usage gates — and (tranche 16b) cleartext **h2c**
//! prior-knowledge runs plus the `--hpack` send-side policy knob.
#![cfg_attr(miri, ignore = "spawns the wrex binary; not Miri-safe")]

use std::time::Duration;

use assert_cmd::Command;
use wrex_test::h2_stub::{AlpnPick, H2Stub};

fn wrex() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_wrex"));
    cmd.timeout(Duration::from_secs(60));
    cmd
}

fn tmpdir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("wrex-h2-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `wrex http https://… --format json` parsed.
fn wrex_h2(stub_addr: std::net::SocketAddr, extra: &[&str]) -> serde_json::Value {
    let url = format!("https://{stub_addr}/");
    let mut cmd = wrex();
    cmd.args(["http", "--format", "json"]).arg(&url).args(extra);
    let out = cmd.assert().success().get_output().stdout.clone();
    serde_json::from_slice(&out).expect("json stdout")
}

#[test]
fn h2_end_to_end_insecure() {
    let stub: H2Stub = wrex_test::h2_stub::spawn_h2(200, b"hello world", 1, AlpnPick::H2);
    let json = wrex_h2(stub.addr, &["--tls-insecure", "--http-version", "2"]);
    assert_eq!(json["status"], 200);
    assert_eq!(json["reason"], "OK");
    assert_eq!(json["version"], "HTTP/2");
    assert_eq!(json["body_hex"], hex::encode("hello world"));
    assert_eq!(json["headers"]["content-type"][0], "text/plain");
    assert_eq!(json["headers"]["content-length"][0], "11");
}

#[test]
fn h2_concurrent_streams_one_connection() {
    // conns=1: both URLs must ride one TLS connection as two
    // concurrent streams (the T15 design).
    let stub: H2Stub = wrex_test::h2_stub::spawn_h2(200, b"one", 1, AlpnPick::H2);
    let url1 = format!("https://{}/a", stub.addr);
    let url2 = format!("https://{}/b", stub.addr);
    let out = wrex()
        .args([
            "http",
            "--format",
            "json",
            "--tls-insecure",
            "--http-version",
            "2",
        ])
        .arg(&url1)
        .arg(&url2)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let arr: serde_json::Value = serde_json::from_slice(&out).expect("json array stdout");
    let arr = arr.as_array().expect("queue renders as an array");
    assert_eq!(arr.len(), 2);
    for resp in arr {
        assert_eq!(resp["status"], 200);
        assert_eq!(resp["version"], "HTTP/2");
        assert_eq!(resp["body_hex"], hex::encode("one"));
    }
}

#[test]
fn alpn_downgrade_falls_back_to_http11() {
    // The server picks http/1.1 from the offer: the client prints a
    // note and completes the exchange over 1.1 (the T15 planning
    // decision — auto-downgrade, exit 0).
    let stub: H2Stub = wrex_test::h2_stub::spawn_h2(200, b"legacy", 1, AlpnPick::Http11);
    let url = format!("https://{}/", stub.addr);
    let out = wrex()
        .args([
            "http",
            "--format",
            "json",
            "--tls-insecure",
            "--http-version",
            "2",
        ])
        .arg(&url)
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout);
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json stdout");
    assert_eq!(json["status"], 200);
    assert_eq!(json["version"], "HTTP/1.1");
    assert_eq!(json["body_hex"], hex::encode("legacy"));
    let stderr = String::from_utf8_lossy(&out.get_output().stderr);
    assert!(stderr.contains("falling back"), "note on stderr: {stderr}");
}

#[test]
fn h2c_end_to_end() {
    // Tranche 16b: cleartext prior knowledge — `http://` +
    // `--http-version 2` speaks h2 straight over the kernel TCP
    // stream (no TLS, no ALPN, no `Upgrade:` dance).
    let stub = wrex_test::h2_stub::spawn_h2c(200, b"hello world", 1);
    let url = format!("http://{}/", stub.addr);
    let out = wrex()
        .args(["http", "--format", "json", "--http-version", "2"])
        .arg(&url)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).expect("json stdout");
    assert_eq!(json["status"], 200);
    assert_eq!(json["version"], "HTTP/2");
    assert_eq!(json["body_hex"], hex::encode("hello world"));
}

#[test]
fn h2c_concurrent_streams_one_connection() {
    // conns=1: both URLs must ride one cleartext connection as two
    // concurrent streams (the T15 design transposed to h2c).
    let stub = wrex_test::h2_stub::spawn_h2c(200, b"one", 1);
    let url1 = format!("http://{}/a", stub.addr);
    let url2 = format!("http://{}/b", stub.addr);
    let out = wrex()
        .args(["http", "--format", "json", "--http-version", "2"])
        .arg(&url1)
        .arg(&url2)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let arr: serde_json::Value = serde_json::from_slice(&out).expect("json array stdout");
    let arr = arr.as_array().expect("queue renders as an array");
    assert_eq!(arr.len(), 2);
    for resp in arr {
        assert_eq!(resp["status"], 200);
        assert_eq!(resp["version"], "HTTP/2");
        assert_eq!(resp["body_hex"], hex::encode("one"));
    }
}

#[test]
fn hpack_knob_rides_both_policies() {
    // `--hpack indexed|literal` (and the recipe knob) both complete
    // end-to-end against the h2c stub — the stub never decodes the
    // client's HPACK, so the policy's wire shapes are exercised on
    // the client side only, byte-for-byte through the session.
    for policy in ["indexed", "literal"] {
        let stub = wrex_test::h2_stub::spawn_h2c(200, b"policy", 1);
        let url = format!("http://{}/", stub.addr);
        let out = wrex()
            .args(["http", "--format", "json", "--http-version", "2", "--hpack"])
            .arg(policy)
            .arg(&url)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let json: serde_json::Value = serde_json::from_slice(&out).expect("json stdout");
        assert_eq!(json["version"], "HTTP/2", "policy {policy}");
        assert_eq!(json["body_hex"], hex::encode("policy"), "policy {policy}");
    }
    // …and the recipe knob wins over the flag (a recipe with
    // `hpack: "literal"` rides without the CLI flag).
    let stub = wrex_test::h2_stub::spawn_h2c(200, b"recipe-policy", 1);
    let recipe = tmpdir().join("req-hpack.json");
    std::fs::write(
        &recipe,
        format!(
            r#"{{"method": "GET", "url": "http://{}/", "http_version": "2", "hpack": "literal"}}"#,
            stub.addr
        ),
    )
    .unwrap();
    let out = wrex()
        .args(["http", "--format", "json", "--recipe"])
        .arg(&recipe)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).expect("json stdout");
    assert_eq!(json["version"], "HTTP/2");
    assert_eq!(json["body_hex"], hex::encode("recipe-policy"));
    // a bad recipe value is a usage error (exit 2).
    let bad = tmpdir().join("req-hpack-bad.json");
    std::fs::write(
        &bad,
        format!(
            r#"{{"method": "GET", "url": "http://{}/", "hpack": "bogus"}}"#,
            stub.addr
        ),
    )
    .unwrap();
    wrex().args(["http", "--recipe"]).arg(&bad).assert().code(2);
}

#[test]
fn h2c_usage_errors() {
    // Bad `--hpack` value is a usage error; `1.1` + `--hpack` is
    // inert (not an error); a plain http 1.1 run against a dead port
    // stays a runtime failure (exit 1), never a crash.
    let stub = wrex_test::h2_stub::spawn_h2c(200, b"x", 0);
    let url = format!("http://{}/", stub.addr);
    wrex()
        .args(["http", "--http-version", "2", "--hpack", "bogus"])
        .arg(&url)
        .assert()
        .code(2);
    wrex()
        .args(["http", "--hpack", "literal"])
        .arg(&url)
        .assert()
        .code(1);
}

#[test]
fn http_version_usage_errors() {
    let stub: H2Stub = wrex_test::h2_stub::spawn_h2(200, b"x", 0, AlpnPick::H2);
    let url = format!("https://{}/", stub.addr);
    wrex()
        .args(["http", "--tls-insecure", "--http-version", "3"])
        .arg(&url)
        .assert()
        .code(2);
}

#[test]
fn h2_recipe_knobs() {
    // recipe http_version: "2" rides h2 without the CLI flag …
    let stub: H2Stub = wrex_test::h2_stub::spawn_h2(200, b"recipe", 1, AlpnPick::H2);
    let recipe = tmpdir().join("req-h2.json");
    std::fs::write(
        &recipe,
        format!(
            r#"{{"method": "GET", "url": "https://{}/", "tls_insecure": true, "http_version": "2"}}"#,
            stub.addr
        ),
    )
    .unwrap();
    let out = wrex()
        .args(["http", "--format", "json", "--recipe"])
        .arg(&recipe)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).expect("json stdout");
    assert_eq!(json["version"], "HTTP/2");
    assert_eq!(json["body_hex"], hex::encode("recipe"));

    // …and a bad value is a recipe usage error (exit 2).
    let bad = tmpdir().join("req-h2-bad.json");
    std::fs::write(
        &bad,
        format!(
            r#"{{"method": "GET", "url": "https://{}/", "http_version": "h2c"}}"#,
            stub.addr
        ),
    )
    .unwrap();
    wrex().args(["http", "--recipe"]).arg(&bad).assert().code(2);
}
