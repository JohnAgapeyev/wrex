//! HTTP CLI grammar tests (assert_cmd): usage errors (exit 2) resolve
//! before any socket; --fail semantics and formats run against a local
//! stub (plain sockets, unprivileged — always-on, but not Miri-safe).
#![cfg_attr(miri, ignore = "spawns the wrex binary; not Miri-safe")]

use std::io::{Read, Write};
use std::net::TcpListener;

use assert_cmd::Command;

fn wrex() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wrex"))
}

fn http_err(args: &[&str]) -> (i32, String) {
    let out = wrex()
        .args(["http"])
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

/// Local stub: one scripted response per connection.
fn spawn_stub(response: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for _ in 0..8 {
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };
            let mut chunk = [0u8; 4096];
            // read the request head (+ body if declared)
            let mut buf = Vec::new();
            while let Ok(n) = conn.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                let head = String::from_utf8_lossy(&buf).to_string();
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let cl: usize = head
                        .lines()
                        .find_map(|l| {
                            l.split_once(':')
                                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
                                .and_then(|(_, v)| v.trim().parse().ok())
                        })
                        .unwrap_or(0);
                    if buf.len() >= pos + 4 + cl {
                        break;
                    }
                }
            }
            let _ = conn.write_all(response);
            let _ = conn.shutdown(std::net::Shutdown::Write);
        }
    });
    port
}

#[test]
fn grammar_errors_are_usage() {
    // no URL
    let (code, stderr) = http_err(&[]);
    assert_eq!(code, 2);
    assert!(stderr.contains("http needs a URL"), "{stderr}");
    // three positionals
    let (code, stderr) = http_err(&["GET", "http://x/", "extra"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("at most"), "{stderr}");
    // unsupported scheme
    let (code, stderr) = http_err(&["ftp://example.com/"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unsupported url scheme"), "{stderr}");
    // bad header
    let (code, stderr) = http_err(&["-H", "no-colon", "http://x/"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("NAME:VALUE"), "{stderr}");
    // recipe + url conflict
    let (code, stderr) = http_err(&["--recipe", "/nonexistent.json", "http://x/"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("exclusive"), "{stderr}");
    // missing recipe file
    let (code, stderr) = http_err(&["--recipe", "/nonexistent/wrex/req.json"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("cannot read recipe"), "{stderr}");
    // bad recipe json
    let dir = std::env::temp_dir().join("wrex-http-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("bad.json");
    std::fs::write(&bad, "{ not json").unwrap();
    let (code, stderr) = http_err(&["--recipe", bad.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(stderr.contains("bad recipe"), "{stderr}");
    // hex format rejected
    let (code, stderr) = http_err(&["--format", "hex", "http://x/"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("text|json|raw"), "{stderr}");
}

#[test]
fn fail_flag_and_formats_against_stub() {
    let ok_port = spawn_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi");
    let err_port = spawn_stub(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");

    // 200 → 0; with --fail still 0
    wrex()
        .args(["http", &format!("http://127.0.0.1:{ok_port}/")])
        .assert()
        .success();
    wrex()
        .args(["http", "--fail", &format!("http://127.0.0.1:{ok_port}/")])
        .assert()
        .success();

    // 404 → 0 (data); with --fail → 1
    wrex()
        .args(["http", &format!("http://127.0.0.1:{err_port}/")])
        .assert()
        .success();
    wrex()
        .args(["http", "--fail", &format!("http://127.0.0.1:{err_port}/")])
        .assert()
        .code(1);

    // --format raw: body only, byte-exact
    let out = wrex()
        .args([
            "http",
            "--format",
            "raw",
            &format!("http://127.0.0.1:{ok_port}/"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(out, b"hi");

    // --format json carries status + body_hex
    let out = wrex()
        .args([
            "http",
            "--format",
            "json",
            &format!("http://127.0.0.1:{ok_port}/"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(json["status"], 200);
    assert_eq!(json["body_hex"], "6869");
}

#[test]
fn connect_failure_is_runtime_error() {
    // dead port: refused → exit 1 (not usage)
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    wrex()
        .args([
            "http",
            &format!("http://127.0.0.1:{port}/"),
            "--retries",
            "0",
        ])
        .assert()
        .code(1);
}

#[test]
fn recipe_full_cycle_against_stub() {
    let port = spawn_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\naye");
    let dir = std::env::temp_dir().join("wrex-http-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    let recipe = dir.join("req.json");
    std::fs::write(
        &recipe,
        format!(r#"{{"method": "GET", "url": "http://127.0.0.1:{port}/r"}}"#),
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
    assert_eq!(out, b"aye");
}

#[test]
fn help_renders_the_http_grammar() {
    let out = wrex()
        .args(["http", "--help"])
        .assert()
        .success()
        .get_output()
        .clone();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--recipe"), "{stdout}");
    assert!(stdout.contains("--fail"), "{stdout}");
    assert!(stdout.contains("--max-bytes"), "{stdout}");
}
