//! HTTP CLI grammar tests (assert_cmd): usage errors (exit 2) resolve
//! before any socket; --fail semantics and formats run against a local
//! stub (plain sockets, unprivileged — always-on, but not Miri-safe).
#![cfg_attr(miri, ignore = "spawns the wrex binary; not Miri-safe")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

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

/// Tranche 10a: `http://[::1]:PORT/` — a bracketed v6 literal rides the
/// dual-family kernel driver end-to-end (plain sockets, unprivileged).
#[test]
fn v6_bracketed_literal_against_stub() {
    let listener = TcpListener::bind("[::1]:0").expect("bind v6 stub");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let Ok((mut conn, peer)) = listener.accept() else {
            return;
        };
        // The peer must be v6 (a dual-family driver, not a v4 fallback).
        assert!(peer.is_ipv6(), "{peer}");
        let mut buf = [0u8; 4096];
        // Read the request head (until the blank line); the client
        // holds the connection open awaiting the response, so a
        // read-to-EOF here would deadlock.
        let mut head = Vec::new();
        loop {
            let n = conn.read(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            head.extend_from_slice(&buf[..n]);
            if head.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nv6!");
        let _ = conn.shutdown(std::net::Shutdown::Write);
    });
    let out = wrex()
        .args(["http", "--format", "raw", &format!("http://[::1]:{port}/")])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(out, b"v6!");
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

// --- tranche 19a: redirects + cookies -----------------------------------------

use std::sync::Mutex;

/// A routing stub: per connection, answers any number of requests,
/// mapping the request line's path to a scripted raw response. The
/// first line of every request is recorded (method/ordering asserts).
/// Paths match by the exact first token after the method.
fn spawn_routing_stub(routes: Vec<(&'static str, Vec<u8>)>) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        for _ in 0..16 {
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };
            let mut chunk = [0u8; 8192];
            let mut buf = Vec::new();
            while let Ok(n) = conn.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                // one full request at a time (head + declared body)
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf).to_string();
                    let cl: usize = head
                        .lines()
                        .find_map(|l| {
                            l.split_once(':')
                                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
                                .and_then(|(_, v)| v.trim().parse().ok())
                        })
                        .unwrap_or(0);
                    if buf.len() < pos + 4 + cl {
                        continue;
                    }
                    let line = head.lines().next().unwrap_or_default().to_string();
                    seen2.lock().unwrap().push(line.clone());
                    let path = line.split(' ').nth(1).unwrap_or("/");
                    let path = path.split('?').next().unwrap_or(path);
                    let route = routes
                        .iter()
                        .find(|(p, _)| *p == path)
                        .map(|(_, r)| r.clone());
                    match route {
                        Some(resp) => {
                            let _ = conn.write_all(&resp);
                        }
                        None => {
                            let _ = conn
                                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
                        }
                    }
                    buf.clear();
                }
            }
        }
    });
    (port, seen)
}

fn redirect_routes() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "/start",
            b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
        ),
        (
            "/next",
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone".to_vec(),
        ),
        (
            "/loop",
            b"HTTP/1.1 302 Found\r\nLocation: /loop\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ),
        (
            "/post303",
            b"HTTP/1.1 303 See Other\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ),
        (
            "/post307",
            b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
        ),
        (
            "/set-cookie",
            b"HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Path=/\r\nSet-Cookie: b=2; Path=/\r\nContent-Length: 2\r\n\r\nok".to_vec(),
        ),
        (
            "/echo-cookie",
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nack".to_vec(),
        ),
    ]
}

#[test]
fn follow_rides_the_chain_and_reports_it() {
    let (port, _seen) = spawn_routing_stub(redirect_routes());
    let out = wrex()
        .args([
            "http",
            "-L",
            "--format",
            "raw",
            &format!("http://127.0.0.1:{port}/start"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(out, b"done");
}

#[test]
fn follow_json_carries_the_chain() {
    let (port, seen) = spawn_routing_stub(redirect_routes());
    let out = wrex()
        .args([
            "http",
            "-L",
            "--format",
            "json",
            &format!("http://127.0.0.1:{port}/start"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(json["status"], 200);
    assert_eq!(json["body_hex"], hex::encode("done"));
    assert_eq!(json["url"], format!("http://127.0.0.1:{port}/next"));
    assert_eq!(
        json["redirects"],
        serde_json::json!([
            {"url": format!("http://127.0.0.1:{port}/start"), "status": 302}
        ]),
        "{json}"
    );
    // the chain hit /start then /next, in order
    let requests = seen.lock().unwrap().clone();
    assert_eq!(
        requests,
        vec![
            "GET /start HTTP/1.1".to_string(),
            "GET /next HTTP/1.1".to_string(),
        ],
        "{requests:?}"
    );
    // plain runs (no follow) keep the T4 json shape byte-identical:
    // no url/redirects keys on a direct 200.
    let out = wrex()
        .args([
            "http",
            "--format",
            "json",
            &format!("http://127.0.0.1:{port}/next"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(json.get("url").is_none());
    assert!(json.get("redirects").is_none());
}

#[test]
fn follow_same_origin_reuses_one_connection() {
    // The keep-alive pin: a same-origin redirect chain rides ONE
    // connection (session push re-entry, not a reconnect).
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let conns = Arc::new(AtomicUsize::new(0));
    let conns2 = conns.clone();
    std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        conns2.fetch_add(1, Ordering::SeqCst);
        let mut chunk = [0u8; 4096];
        let mut served = 0;
        // answer two requests on this one connection
        while served < 2 {
            let n = match conn.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let got = &chunk[..n];
            served += got.windows(4).filter(|w| *w == b"\r\n\r\n").count();
            let resp = if served == 1 {
                &b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n"[..]
            } else {
                &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"[..]
            };
            let _ = conn.write_all(resp);
        }
        let _ = conn.shutdown(std::net::Shutdown::Write);
        // any further connection is a test failure signal (counted)
    });
    let out = wrex()
        .args([
            "http",
            "-L",
            "--format",
            "raw",
            &format!("http://127.0.0.1:{port}/start"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(out, b"ok");
    assert_eq!(conns.load(Ordering::SeqCst), 1, "one connection");
}

#[test]
fn redirect_method_rules_on_the_wire() {
    // 303 rewrites POST to a bodyless GET; 307 preserves POST + body.
    let (port, seen) = spawn_routing_stub(redirect_routes());
    wrex()
        .args([
            "http",
            "-L",
            "POST",
            "--data",
            "hello",
            &format!("http://127.0.0.1:{port}/post303"),
        ])
        .assert()
        .success();
    wrex()
        .args([
            "http",
            "-L",
            "POST",
            "--data",
            "hello",
            &format!("http://127.0.0.1:{port}/post307"),
        ])
        .assert()
        .success();
    let requests = seen.lock().unwrap().clone();
    assert_eq!(
        requests,
        vec![
            "POST /post303 HTTP/1.1".to_string(),
            "GET /next HTTP/1.1".to_string(),
            "POST /post307 HTTP/1.1".to_string(),
            "POST /next HTTP/1.1".to_string(),
        ],
        "{requests:?}"
    );
}

#[test]
fn redirect_without_follow_is_data() {
    // A 3xx without -L is a completed exchange (the curl behavior).
    let (port, _seen) = spawn_routing_stub(redirect_routes());
    let out = wrex()
        .args([
            "http",
            "--format",
            "json",
            &format!("http://127.0.0.1:{port}/start"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(json["status"], 302);
    assert!(json.get("redirects").is_none(), "no chain without -L");
}

#[test]
fn max_redirs_exceeded_is_a_runtime_error() {
    let (port, seen) = spawn_routing_stub(redirect_routes());
    let out = wrex()
        .args([
            "http",
            "-L",
            "--max-redirs",
            "2",
            &format!("http://127.0.0.1:{port}/loop"),
        ])
        .assert()
        .failure()
        .get_output()
        .clone();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("redirect budget"), "{stderr}");
    assert_eq!(seen.lock().unwrap().len(), 3, "the initial + 2 hops");
}

#[test]
fn follow_cross_origin_drops_authorization() {
    // Two stub ports: the redirect target is a different origin, so
    // Authorization must not survive the hop (curl's rule); the
    // first request carries it.
    let listener_a = TcpListener::bind("127.0.0.1:0").unwrap();
    let port_a = listener_a.local_addr().unwrap().port();
    let listener_b = TcpListener::bind("127.0.0.1:0").unwrap();
    let port_b = listener_b.local_addr().unwrap().port();
    let first_head = Arc::new(Mutex::new(String::new()));
    let hop_head = Arc::new(Mutex::new(String::new()));
    let (fa, fh) = (first_head.clone(), hop_head.clone());
    std::thread::spawn(move || {
        let (mut conn, _) = listener_a.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = conn.read(&mut buf).unwrap_or(0);
        *fa.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
        let _ = conn.write_all(
            format!("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port_b}/next\r\nContent-Length: 0\r\n\r\n")
                .as_bytes(),
        );
        let _ = conn.shutdown(std::net::Shutdown::Write);
    });
    std::thread::spawn(move || {
        let (mut conn, _) = listener_b.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = conn.read(&mut buf).unwrap_or(0);
        *fh.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
        let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx");
        let _ = conn.shutdown(std::net::Shutdown::Write);
    });
    let out = wrex()
        .args([
            "http",
            "-L",
            "--format",
            "raw",
            "-H",
            "Authorization: Bearer sekret",
            &format!("http://127.0.0.1:{port_a}/start"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(out, b"x");
    let first = first_head.lock().unwrap().clone();
    let hop = hop_head.lock().unwrap().clone();
    assert!(first.contains("authorization: Bearer sekret"), "{first}");
    assert!(
        !hop.contains("authorization"),
        "cross-origin hop must drop Authorization: {hop}"
    );
    assert!(hop.contains("GET /next"), "{hop}");
}

#[test]
fn cookie_jar_roundtrip_and_send() {
    // -c collects Set-Cookie; -b loads it and sends Cookie on the
    // next request; the jar survives round-trips (Netscape format).
    let (port, _seen) = spawn_routing_stub(redirect_routes());
    let dir = std::env::temp_dir().join("wrex-http-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    let jar = dir.join("cookies.txt");
    let _ = std::fs::remove_file(&jar);

    // collect: Set-Cookie lands in the jar
    wrex()
        .args([
            "http",
            "-c",
            jar.to_str().unwrap(),
            &format!("http://127.0.0.1:{port}/set-cookie"),
        ])
        .assert()
        .success();
    let text = std::fs::read_to_string(&jar).unwrap();
    assert!(text.contains("a\t1"), "{text}");
    assert!(text.contains("b\t2"), "{text}");

    // send: -b injects the Cookie header (the jar owns it)
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port3 = listener.local_addr().unwrap().port();
    let captured = Arc::new(Mutex::new(String::new()));
    let cap2 = captured.clone();
    std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = conn.read(&mut buf).unwrap_or(0);
        *cap2.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
        let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let _ = conn.shutdown(std::net::Shutdown::Write);
    });
    wrex()
        .args([
            "http",
            "-b",
            jar.to_str().unwrap(),
            &format!("http://127.0.0.1:{port3}/echo"),
        ])
        .assert()
        .success();
    let head = captured.lock().unwrap().clone();
    assert!(head.contains("cookie: a=1; b=2"), "{head}");
}

#[test]
fn cookie_literal_rides_verbatim() {
    // -b with a non-file value rides as a literal Cookie header
    // (curl's data form).
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured = Arc::new(Mutex::new(String::new()));
    let cap2 = captured.clone();
    std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = conn.read(&mut buf).unwrap_or(0);
        *cap2.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
        let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        let _ = conn.shutdown(std::net::Shutdown::Write);
    });
    wrex()
        .args([
            "http",
            "-b",
            "tok=abc",
            &format!("http://127.0.0.1:{port}/echo"),
        ])
        .assert()
        .success();
    let head = captured.lock().unwrap().clone();
    assert!(head.contains("cookie: tok=abc"), "{head}");
}

#[test]
fn follow_flag_grammar() {
    // --max-redirs 0 with -L: the first hop exhausts the budget.
    let (port, seen) = spawn_routing_stub(redirect_routes());
    wrex()
        .args([
            "http",
            "-L",
            "--max-redirs",
            "0",
            &format!("http://127.0.0.1:{port}/start"),
        ])
        .assert()
        .code(1);
    assert_eq!(seen.lock().unwrap().len(), 1, "no hops allowed");
}

// --- tranche 19a: auth --------------------------------------------------------

/// A full-request recording stub: captures the complete head of the
/// first request (headers included), answers with `response`.
fn spawn_capture_stub(response: &'static [u8]) -> (u16, Arc<Mutex<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let captured = Arc::new(Mutex::new(String::new()));
    let cap2 = captured.clone();
    std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = [0u8; 8192];
        let n = conn.read(&mut buf).unwrap_or(0);
        *cap2.lock().unwrap() = String::from_utf8_lossy(&buf[..n]).to_string();
        let _ = conn.write_all(response);
        let _ = conn.shutdown(std::net::Shutdown::Write);
    });
    (port, captured)
}

#[test]
fn basic_and_bearer_headers_on_the_wire() {
    let (port, head) = spawn_capture_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    wrex()
        .args([
            "http",
            "-u",
            "aladdin:opensesame",
            &format!("http://127.0.0.1:{port}/x"),
        ])
        .assert()
        .success();
    // base64("aladdin:opensesame") — the canonical pair
    assert!(
        head.lock()
            .unwrap()
            .contains("authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l"),
        "{}",
        head.lock().unwrap()
    );
    let (port, head) = spawn_capture_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    wrex()
        .args([
            "http",
            "--bearer",
            "tok123",
            &format!("http://127.0.0.1:{port}/x"),
        ])
        .assert()
        .success();
    assert!(
        head.lock()
            .unwrap()
            .contains("authorization: Bearer tok123"),
        "{}",
        head.lock().unwrap()
    );
    // an explicit -H Authorization without flags rides untouched
    let (port, head) = spawn_capture_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    wrex()
        .args([
            "http",
            "-H",
            "Authorization: Custom xyz",
            &format!("http://127.0.0.1:{port}/x"),
        ])
        .assert()
        .success();
    assert!(
        head.lock().unwrap().contains("authorization: Custom xyz"),
        "{}",
        head.lock().unwrap()
    );
}

#[test]
fn auth_flag_grammar_errors() {
    let (code, stderr) = http_err(&["-u", "a:b", "--bearer", "t", "http://x/"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("exclusive"), "{stderr}");
    let (code, stderr) = http_err(&["--digest", "http://x/"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("--digest needs --user"), "{stderr}");
}

#[test]
fn digest_401_dance_end_to_end() {
    // 401 + Digest challenge -> the SAME request re-issued with an
    // Authorization: Digest header on the SAME connection.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::<String>::new()));
    let req2 = requests.clone();
    std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = [0u8; 8192];
        let mut served = 0;
        while served < 2 {
            let n = match conn.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => break,
            };
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            if head.contains("\r\n\r\n") {
                req2.lock().unwrap().push(head.clone());
                served += 1;
                let resp: &[u8] = if served == 1 {
                    b"HTTP/1.1 401 Unauthorized\r\n\
                      WWW-Authenticate: Digest realm=\"testrealm@host.com\", qop=\"auth\", \
                      nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"aaaa\", algorithm=MD5\r\n\
                      Content-Length: 0\r\n\r\n"
                } else {
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                };
                let _ = conn.write_all(resp);
            }
        }
        let _ = conn.shutdown(std::net::Shutdown::Write);
    });
    let out = wrex()
        .args([
            "http",
            "-u",
            "Mufasa:Circle Of Life",
            "--digest",
            "--format",
            "raw",
            &format!("http://127.0.0.1:{port}/dir/index.html"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(out, b"ok");
    let reqs = requests.lock().unwrap().clone();
    assert_eq!(reqs.len(), 2, "{reqs:?}");
    assert!(
        !reqs[0].to_ascii_lowercase().contains("authorization:"),
        "no preemptive header under --digest: {}",
        reqs[0]
    );
    let auth_line = reqs[1]
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
        .expect("digest header on the re-issue");
    // The RFC 7616 §3.9.1 lineage, with the verb's deterministic
    // cnonce (md5(nonce:nc:uri:user) first 16 hex chars).
    let cnonce = {
        // md5("dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:/dir/index.html:Mufasa")[..16]
        let digest = md5_hex("dcd98b7102dd2f0e8b11d0f600bfb0c093:00000001:/dir/index.html:Mufasa");
        digest[..16].to_string()
    };
    assert!(
        auth_line.contains("Digest username=\"Mufasa\""),
        "{auth_line}"
    );
    assert!(
        auth_line.contains("realm=\"testrealm@host.com\""),
        "{auth_line}"
    );
    assert!(
        auth_line.contains("nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\""),
        "{auth_line}"
    );
    assert!(auth_line.contains("qop=auth"), "{auth_line}");
    assert!(auth_line.contains("nc=00000001"), "{auth_line}");
    assert!(
        auth_line.contains(&format!("cnonce=\"{cnonce}\"")),
        "{auth_line}"
    );
    assert!(auth_line.contains("opaque=\"aaaa\""), "{auth_line}");
    assert!(auth_line.contains("response=\""), "{auth_line}");
}

#[test]
fn digest_stubborn_401_is_data() {
    // The dance happens ONCE per URL; a second 401 stays data (exit 0
    // without --fail).
    let (port, _seen) = spawn_routing_stub(vec![(
        "/always401",
        b"HTTP/1.1 401 Unauthorized\r\n\
          WWW-Authenticate: Digest realm=\"r\", nonce=\"n\", qop=\"auth\", algorithm=MD5\r\n\
          Content-Length: 0\r\n\r\n"
            .to_vec(),
    )]);
    let out = wrex()
        .args([
            "http",
            "-u",
            "u:p",
            "--digest",
            &format!("http://127.0.0.1:{port}/always401"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(
        String::from_utf8_lossy(&out).contains("401"),
        "the final 401 renders: {out:?}"
    );
}

/// md5 hex (test-only helper over the same RustCrypto crate the
/// product uses — wrex-http's RFC vector twin).
fn md5_hex(data: &str) -> String {
    use md5::Digest as _;
    let mut h = md5::Md5::new();
    h.update(data.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

// --- tranche 19a: content-decoding + sugar + timing ---------------------------

/// The committed codec fixtures (byte-stable; generated with the
/// system gzip/zlib/brotli/zstd — the golden-corpus pattern).
fn fixture(name: &str) -> Vec<u8> {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../wrex-http/testdata/content");
    std::fs::read(format!("{dir}/{name}")).expect("committed fixture")
}

#[test]
fn compressed_decodes_all_four_codecs() {
    for (encoding, file) in [
        ("gzip", "fixture.gz"),
        ("deflate", "fixture.zz"),
        ("br", "fixture.br"),
        ("zstd", "fixture.zst"),
    ] {
        let body = fixture(file);
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: {encoding}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut response = head.into_bytes();
        response.extend_from_slice(&body);
        let (port, _seen) = spawn_routing_stub(vec![("/c", response)]);
        // --compressed: the decoded plaintext
        let out = wrex()
            .args([
                "http",
                "--compressed",
                "--format",
                "raw",
                &format!("http://127.0.0.1:{port}/c"),
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let expected = fixture(&format!("{file}.expected"));
        assert_eq!(out, expected, "{encoding} decoded");
        // without --compressed the bytes pass through verbatim (data)
        let out = wrex()
            .args([
                "http",
                "--format",
                "raw",
                &format!("http://127.0.0.1:{port}/c"),
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        assert_eq!(out, body, "{encoding} passes through without --compressed");
    }
}

#[test]
fn compressed_advertises_curls_list_and_bomb_budget() {
    // The advertisement is curl's own value, byte-exact.
    let (port, head) = spawn_capture_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    wrex()
        .args([
            "http",
            "--compressed",
            &format!("http://127.0.0.1:{port}/x"),
        ])
        .assert()
        .success();
    assert!(
        head.lock()
            .unwrap()
            .contains("accept-encoding: deflate, gzip, br, zstd"),
        "{}",
        head.lock().unwrap()
    );
    // An explicit -H Accept-Encoding wins (craft rule)
    let (port, head) = spawn_capture_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    wrex()
        .args([
            "http",
            "--compressed",
            "-H",
            "Accept-Encoding: identity",
            &format!("http://127.0.0.1:{port}/x"),
        ])
        .assert()
        .success();
    assert!(
        head.lock().unwrap().contains("accept-encoding: identity"),
        "{}",
        head.lock().unwrap()
    );
    // The bomb: 100MB-of-zeros .gz against a small budget — decoded
    // bytes count like wire bytes.
    let bomb = fixture("bomb.gz");
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
        bomb.len()
    )
    .into_bytes();
    response.extend_from_slice(&bomb);
    let (port, _seen) = spawn_routing_stub(vec![("/bomb", response)]);
    let out = wrex()
        .args([
            "http",
            "--compressed",
            "--max-bytes",
            "131072",
            &format!("http://127.0.0.1:{port}/bomb"),
        ])
        .assert()
        .failure()
        .get_output()
        .clone();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("decoded content exceeded"),
        "the decoded budget trips: {stderr}"
    );
}

#[test]
fn head_range_and_upload_sugar() {
    // -I: HEAD on the wire (and --fail stays quiet on 200)
    let (port, head) = spawn_capture_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
    wrex()
        .args(["http", "-I", &format!("http://127.0.0.1:{port}/h")])
        .assert()
        .success();
    assert!(
        head.lock().unwrap().starts_with("HEAD /h"),
        "{}",
        head.lock().unwrap()
    );
    // -r: the Range header sugar
    let (port, head) = spawn_capture_stub(b"HTTP/1.1 206 Partial\r\nContent-Length: 0\r\n\r\n");
    wrex()
        .args(["http", "-r", "10-20", &format!("http://127.0.0.1:{port}/r")])
        .assert()
        .success();
    assert!(
        head.lock().unwrap().contains("range: bytes=10-20"),
        "{}",
        head.lock().unwrap()
    );
    // bad range grammar is a usage error
    let (code, stderr) = http_err(&["-r", "a-b", "http://x/"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("bad --range"), "{stderr}");
    // -T: PUT with the file bytes as the body
    let dir = std::env::temp_dir().join("wrex-http-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    let upload = dir.join("up.bin");
    std::fs::write(&upload, b"upload body").unwrap();
    let (port, head) = spawn_capture_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    wrex()
        .args([
            "http",
            "-T",
            upload.to_str().unwrap(),
            &format!("http://127.0.0.1:{port}/u"),
        ])
        .assert()
        .success();
    let captured = head.lock().unwrap().clone();
    assert!(captured.starts_with("PUT /u"), "{captured}");
    assert!(
        captured.to_ascii_lowercase().contains("content-length: 11"),
        "{captured}"
    );
    assert!(captured.ends_with("upload body"), "{captured}");
    // -I/-T conflicts are usage errors
    let (code, _) = http_err(&["-I", "POST", "http://x/"]);
    assert_eq!(code, 2);
    let (code, _) = http_err(&["-T", upload.to_str().unwrap(), "POST", "http://x/"]);
    assert_eq!(code, 2);
    let (code, _) = http_err(&["-T", upload.to_str().unwrap(), "--data", "x", "http://x/"]);
    assert_eq!(code, 2);
}

#[test]
fn output_capture_o_and_capital_o() {
    let dir = std::env::temp_dir().join("wrex-http-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    let out_file = dir.join("cap.body");
    let _ = std::fs::remove_file(&out_file);
    let (port, _seen) = spawn_routing_stub(redirect_routes());
    // -o: the body lands in the file, stdout stays empty (raw)
    let out = wrex()
        .args([
            "http",
            "--format",
            "raw",
            "-o",
            out_file.to_str().unwrap(),
            &format!("http://127.0.0.1:{port}/next"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(
        out.is_empty(),
        "captured responses are stdout-silent: {out:?}"
    );
    assert_eq!(std::fs::read(&out_file).unwrap(), b"done");
    // -O: the remote basename in the CWD
    let cwd = dir.join("o-test");
    std::fs::create_dir_all(&cwd).unwrap();
    let _ = std::fs::remove_file(cwd.join("next"));
    let out = wrex()
        .current_dir(&cwd)
        .args([
            "http",
            "--format",
            "raw",
            "-O",
            &format!("http://127.0.0.1:{port}/next"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert!(out.is_empty());
    assert_eq!(std::fs::read(cwd.join("next")).unwrap(), b"done");
    // -o + -O conflict
    let (code, stderr) = http_err(&["-o", "a", "-O", "http://x/"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("exclusive"), "{stderr}");
}

#[test]
fn retry_on_5xx_status_class() {
    // --retry N: a completed 5xx replays the request N extra times,
    // the final 5xx stays data (exit 0 without --fail).
    let (port, seen) = spawn_routing_stub(vec![(
        "/flaky",
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 3\r\n\r\nmeh".to_vec(),
    )]);
    let out = wrex()
        .args([
            "http",
            "--format",
            "raw",
            "--retry",
            "2",
            &format!("http://127.0.0.1:{port}/flaky"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(out, b"meh");
    assert_eq!(seen.lock().unwrap().len(), 3, "1 + 2 retries");
}

#[test]
fn resolve_pin_bypasses_resolution() {
    // wrex.test does not resolve; the pin makes the connection.
    let (port, _seen) = spawn_routing_stub(redirect_routes());
    wrex()
        .args([
            "http",
            "--resolve",
            &format!("wrex.test:{port}:127.0.0.1"),
            &format!("http://wrex.test:{port}/next"),
        ])
        .assert()
        .success();
    // a portless pin matches every port of the host
    wrex()
        .args([
            "http",
            "--resolve",
            "wrex.test:127.0.0.1",
            &format!("http://wrex.test:{port}/next"),
        ])
        .assert()
        .success();
    // without the pin the name cannot resolve (runtime, not usage)
    wrex()
        .args(["http", &format!("http://wrex.test:{port}/next")])
        .assert()
        .code(1);
    // bad grammar is a usage error
    let (code, stderr) = http_err(&["--resolve", "noaddr", "http://x/"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("--resolve"), "{stderr}");
}

// --- tranche 19b: proxies -----------------------------------------------------

/// A plain-HTTP PROXY stub: accepts requests TO the proxy (absolute
/// form recorded), answers 200 "via-proxy" per request, N requests
/// per connection.
fn spawn_http_proxy_stub() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    std::thread::spawn(move || {
        for _ in 0..16 {
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };
            let mut chunk = [0u8; 4096];
            let mut buf = Vec::new();
            while let Ok(n) = conn.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf).to_string();
                    seen2.lock().unwrap().push(head.clone());
                    let _ = pos;
                    let _ =
                        conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nvia-proxy");
                    buf.clear();
                }
            }
        }
    });
    (port, seen)
}

#[test]
fn http_proxy_absolute_form_end_to_end() {
    let (proxy_port, seen) = spawn_http_proxy_stub();
    let out = wrex()
        .args([
            "http",
            "--format",
            "raw",
            "-x",
            &format!("http://127.0.0.1:{proxy_port}"),
            "http://wrex.test/a/b?q=1",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(out, b"via-proxy");
    let requests = seen.lock().unwrap().clone();
    assert_eq!(requests.len(), 1, "{requests:?}");
    assert!(
        requests[0].starts_with("GET http://wrex.test/a/b?q=1 HTTP/1.1"),
        "the proxy sees the absolute form: {}",
        requests[0]
    );
    assert!(
        requests[0].to_ascii_lowercase().contains("host: wrex.test"),
        "{}",
        requests[0]
    );
    // socks5h:// through the same stub? no — that needs a SOCKS proxy;
    // covered by the wrex-io unit suite. Bad proxy grammar is usage.
    let (code, stderr) = http_err(&["-x", "nonsense", "http://x/"]);
    assert_eq!(code, 1, "unresolvable proxy is a runtime error: {stderr}");
}

#[test]
fn proxy_credentials_ride_the_absolute_form() {
    let (proxy_port, seen) = spawn_http_proxy_stub();
    wrex()
        .args([
            "http",
            "-x",
            &format!("http://127.0.0.1:{proxy_port}"),
            "-U",
            "pu:pp",
            "http://wrex.test/x",
        ])
        .assert()
        .success();
    let requests = seen.lock().unwrap().clone();
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("proxy-authorization: basic "),
        "{}",
        requests[0]
    );
    assert!(requests[0].contains("Basic cHU6cHA="), "{}", requests[0]);
}

/// A SOCKS5 proxy stub: no-auth handshake, tunnel, then one HTTP
/// response for the tunneled request.
fn spawn_socks5_http_proxy() -> u16 {
    use std::io::Read;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for _ in 0..8 {
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };
            let mut buf = [0u8; 512];
            // greeting (3): 05 01 00
            let _ = conn.read_exact(&mut buf[..3]);
            conn.write_all(&[0x05, 0x00]).unwrap();
            // request: 4 head + ATYP-dependent tail
            let _ = conn.read_exact(&mut buf[..4]);
            let tail = match buf[3] {
                0x01 => 6,
                0x03 => {
                    let mut len = [0u8; 1];
                    let _ = conn.read_exact(&mut len);
                    len[0] as usize + 2
                }
                _ => 18,
            };
            let _ = conn.read_exact(&mut buf[..tail]);
            conn.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .unwrap();
            // the tunneled HTTP request, then one response
            let mut head = Vec::new();
            let _ = conn.set_read_timeout(Some(Duration::from_millis(500)));
            let mut chunk = [0u8; 4096];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match conn.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&chunk[..n]),
                }
            }
            if head.is_empty() {
                continue;
            }
            let _ = conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nsocks-200");
            let _ = conn.shutdown(std::net::Shutdown::Write);
        }
    });
    port
}

#[test]
fn socks5_tunnel_end_to_end() {
    // socks5h://: the proxy resolves (a fake hostname works).
    let port = spawn_socks5_http_proxy();
    let out = wrex()
        .args([
            "http",
            "--format",
            "raw",
            "-x",
            &format!("socks5h://127.0.0.1:{port}"),
            "http://wrex-socks.test/page",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(out, b"socks-200");
    // socks5://: LOCAL resolution — an IP literal works.
    let port = spawn_socks5_http_proxy();
    let out = wrex()
        .args([
            "http",
            "--format",
            "raw",
            "-x",
            &format!("socks5://127.0.0.1:{port}"),
            "http://127.0.0.1/page",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(out, b"socks-200");
}

#[test]
fn https_via_connect_tunnel_end_to_end() {
    // A CONNECT-fronted byte pump to the wrex-test TLS stub: the
    // proxy answers 200 and blindly relays both directions; wrex must
    // speak TLS to the DESTINATION through the tunnel.
    const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\ntunne";
    let stub = wrex_test::tls_stub::spawn(
        OK.to_vec(),
        3,
        1,
        wrex_test::tls_stub::StubRequest::HttpHead,
    );
    let tls_port = stub.addr.port();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = conn.read(&mut chunk).unwrap();
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let head = String::from_utf8_lossy(&buf).to_string();
        assert!(
            head.starts_with(&format!("CONNECT 127.0.0.1:{tls_port} HTTP/1.1")),
            "the CONNECT target: {head}"
        );
        conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .unwrap();
        // blind relay to the TLS stub (split streams per direction)
        let dest = std::net::TcpStream::connect(("127.0.0.1", tls_port)).unwrap();
        let dest_r = dest.try_clone().unwrap();
        let dest_w = dest.try_clone().unwrap();
        let conn_r = conn.try_clone().unwrap();
        let conn_w = conn;
        dest_r.set_read_timeout(Some(Duration::from_secs(5))).ok();
        conn_r.set_read_timeout(Some(Duration::from_secs(5))).ok();
        std::thread::scope(|s| {
            s.spawn(move || {
                let mut b = [0u8; 16384];
                let (mut src, mut snk) = (conn_r, dest_w);
                loop {
                    match src.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if snk.write_all(&b[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            s.spawn(move || {
                let mut b = [0u8; 16384];
                let (mut src, mut snk) = (dest_r, conn_w);
                loop {
                    match src.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if snk.write_all(&b[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        });
    });
    let out = wrex()
        .args([
            "http",
            "--format",
            "raw",
            "--tls-insecure",
            "-x",
            &format!("http://127.0.0.1:{proxy_port}"),
            &format!("https://127.0.0.1:{tls_port}/"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(out, b"tunne");
}

#[test]
fn include_flag_prepends_the_head_on_raw() {
    // -i: the response head rides raw output (curl -i); plain raw
    // stays body-only.
    let (port, _seen) = spawn_routing_stub(redirect_routes());
    let out = wrex()
        .args([
            "http",
            "--format",
            "raw",
            &format!("http://127.0.0.1:{port}/next"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(out, b"done", "plain raw is the body only");
    let out = wrex()
        .args([
            "http",
            "--include",
            "--format",
            "raw",
            &format!("http://127.0.0.1:{port}/next"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(
        text.to_ascii_lowercase().contains("content-length: 4\r\n"),
        "{text}"
    );
    assert!(text.ends_with("\r\n\r\ndone"), "{text}");
}

#[test]
fn timing_object_in_json() {
    let (port, _seen) = spawn_routing_stub(redirect_routes());
    let out = wrex()
        .args([
            "http",
            "--timing",
            "--format",
            "json",
            &format!("http://127.0.0.1:{port}/next"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let t = &json["timing"];
    assert!(t.is_object(), "{json}");
    assert!(t["time_connect_ms"].as_u64().is_some(), "{json}");
    assert!(t["time_starttransfer_ms"].as_u64().is_some(), "{json}");
    assert!(t["time_total_ms"].as_u64().is_some(), "{json}");
    assert!(
        t.get("time_appconnect_ms").is_some(),
        "the key is present (null on plain http): {json}"
    );
    // without --timing: no key (plain runs stay byte-identical)
    let out = wrex()
        .args([
            "http",
            "--format",
            "json",
            &format!("http://127.0.0.1:{port}/next"),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(json.get("timing").is_none());
}
