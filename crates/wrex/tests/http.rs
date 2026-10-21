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
    // "extra" is not a URL: the [METHOD] URL... grammar rejects it
    let (code, stderr) = http_err(&["GET", "http://x/", "extra"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("scheme"), "{stderr}");
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

// --- tranche 9a: keep-alive queues + chunked request bodies ------------------

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// A keep-alive stub: per connection, read N requests (headers+body),
/// answer each in order, then close. Counts connections.
fn spawn_keepalive_stub(
    responses: Vec<Vec<u8>>,
    expect_requests: usize,
) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let conns = Arc::new(AtomicUsize::new(0));
    let conns2 = conns.clone();
    std::thread::spawn(move || {
        let mut served = 0usize;
        for _ in 0..16 {
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };
            conns2.fetch_add(1, Ordering::SeqCst);
            let mut chunk = [0u8; 4096];
            let mut buf = Vec::new();
            let mut answered = 0usize;
            while answered < expect_requests && served < 32 {
                let n = match conn.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => return,
                };
                buf.extend_from_slice(&chunk[..n]);
                // a request is complete at the blank line (GETs, no CL)
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    buf.clear();
                    if let Some(resp) = responses.get(answered) {
                        let _ = conn.write_all(resp);
                    }
                    answered += 1;
                    served += 1;
                }
            }
            let _ = conn.shutdown(std::net::Shutdown::Write);
        }
    });
    (port, conns)
}

#[test]
fn multi_url_rides_one_keepalive_connection() {
    let (port, conns) = spawn_keepalive_stub(
        vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nnoo".to_vec(),
        ],
        2,
    );
    // Two URLs over one connection: both responses, in order.
    let out = wrex()
        .args([
            "http",
            "--format",
            "raw",
            &format!("http://127.0.0.1:{port}/a"),
            &format!("http://127.0.0.1:{port}/b"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(out, b"oknoo");
    assert_eq!(conns.load(Ordering::SeqCst), 1, "one connection expected");
}

#[test]
fn recipe_array_is_a_keepalive_queue() {
    let (port, conns) = spawn_keepalive_stub(
        vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n1".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n2".to_vec(),
        ],
        2,
    );
    let dir = std::env::temp_dir().join("wrex-http-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    let recipe = dir.join("queue.json");
    std::fs::write(
        &recipe,
        format!(
            r#"{{"requests": [
                {{"method": "GET", "url": "http://127.0.0.1:{port}/a"}},
                {{"method": "GET", "url": "http://127.0.0.1:{port}/b"}}
            ]}}"#
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
    assert_eq!(out, b"12");
    assert_eq!(conns.load(Ordering::SeqCst), 1);
    // a top-level array parses the same
    let recipe = dir.join("queue2.json");
    std::fs::write(
        &recipe,
        format!(
            r#"[
                {{"method": "GET", "url": "http://127.0.0.1:{port}/a"}},
                {{"method": "GET", "url": "http://127.0.0.1:{port}/b"}}
            ]"#
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
    assert_eq!(out, b"12");
}

#[test]
fn chunked_request_body_on_the_wire() {
    // A recording stub: assert the TX bytes carry chunked framing.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut chunk = [0u8; 4096];
        let mut buf = Vec::new();
        while let Ok(n) = conn.read(&mut chunk) {
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.windows(5).any(|w| w == b"0\r\n\r\n")
            {
                break;
            }
        }
        *seen2.lock().unwrap() = buf.clone();
        let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let _ = conn.shutdown(std::net::Shutdown::Write);
    });
    let dir = std::env::temp_dir().join("wrex-http-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    let recipe = dir.join("chunked.json");
    std::fs::write(
        &recipe,
        format!(
            r#"{{"method": "POST", "url": "http://127.0.0.1:{port}/c",
                "body_text": "0123456789", "body_framing": "chunked",
                "chunk_size": 4}}"#
        ),
    )
    .unwrap();
    wrex()
        .args(["http", "--recipe", recipe.to_str().unwrap()])
        .assert()
        .success();
    let wire = String::from_utf8(seen.lock().unwrap().clone()).unwrap();
    assert!(wire.contains("Transfer-Encoding: chunked"), "{wire}");
    assert!(
        wire.ends_with("4\r\n0123\r\n4\r\n4567\r\n2\r\n89\r\n0\r\n\r\n"),
        "{wire}"
    );
}
