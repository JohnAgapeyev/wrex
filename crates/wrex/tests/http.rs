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
