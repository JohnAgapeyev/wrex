//! HTTP differential suite (`cargo test -- differential`): a raw stub
//! server (std TcpListener scripting raw response bytes — framing
//! fully under our control) serves each fixture three ways:
//!
//! 1. our in-process session (`HttpClientSession` + `TcpDriver`),
//! 2. reqwest (in-process oracle — note it shares httparse lineage, so
//!    it is partially self-referential; kept for breadth),
//! 3. curl (subprocess oracle, fully independent; env-gated
//!    `WREX_DIFF_CURL=1` or curl on PATH).
//!
//! Status, framing-sensitive bodies and (vs reqwest) headers must
//! agree. Sockets are plain kernel TCP: these run unprivileged
//! everywhere — but not under Miri.
#![cfg_attr(miri, ignore = "TCP sockets; not Miri-safe")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use bytes::Bytes;
use wrex_http::{HttpClientSession, HttpConfig, HttpOutcome, HttpRequestSpec};
use wrex_session::run;

fn curl_enabled() -> bool {
    (std::env::var("WREX_DIFF_CURL").as_deref() == Ok("1") || which_curl().is_some())
        && which_curl().is_some()
}

fn which_curl() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|p| p.join("curl"))
        .find(|p| p.is_file())
}

/// The stub: serves `conns` sequential connections. Per connection:
/// reads one request to completion, writes the scripted raw response
/// bytes (in the given write-sized pieces, to exercise chunk
/// boundaries on real sockets), half-closes, and drains briefly.
fn spawn_stub(response: &[u8], writes: usize, conns: usize) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let addr = listener.local_addr().expect("addr");
    let response = response.to_vec();
    std::thread::spawn(move || {
        for _ in 0..conns {
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };
            // read the request head (+ Content-Length body if declared)
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            while let Ok(n) = conn.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf).to_string();
                    let cl: usize = head
                        .lines()
                        .find_map(|l| {
                            l.split_once(':')
                                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("content-length"))
                                .and_then(|(_, v)| v.trim().parse().ok())
                        })
                        .unwrap_or(0);
                    let body_start = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
                    if buf.len() >= body_start + cl {
                        break;
                    }
                    buf.clear(); // keep reading until the whole body is here
                }
            }
            // scripted writes (chunk-boundary exercise)
            let piece = (response.len() / writes.max(1)).max(1);
            let mut off = 0;
            while off < response.len() {
                let end = (off + piece).min(response.len());
                if conn.write_all(&response[off..end]).is_err() {
                    break;
                }
                off = end;
            }
            let _ = conn.shutdown(std::net::Shutdown::Write);
            // drain so the client's close is orderly
            let _ = conn.set_read_timeout(Some(Duration::from_millis(200)));
            let _ = conn.read(&mut chunk);
        }
    });
    addr
}

/// Our side: one in-process exchange against the stub.
fn wrex_fetch(addr: std::net::SocketAddr, method: &str, path: &str) -> wrex_http::HttpResponse {
    let url = format!("http://{addr}{path}");
    let spec = HttpRequestSpec::build(method, &url, &[], Bytes::new()).expect("spec");
    let mut driver =
        wrex_io::TcpDriver::connect(addr, None, Duration::from_secs(5)).expect("connect");
    let mut session = HttpClientSession::new(
        &spec,
        HttpConfig {
            timeout: Duration::from_secs(5),
            max_bytes: 1024 * 1024,
        },
        std::time::Instant::now(),
    )
    .expect("session");
    match run(&mut session, &mut driver, &wrex_io::SystemClock)
        .expect("run")
        .into_iter()
        .next()
    {
        Some(HttpOutcome::Response(r)) => r,
        other => panic!("expected a response, got {other:?}"),
    }
}

fn reqwest_fetch(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
) -> reqwest::blocking::Response {
    let url = format!("http://{addr}{path}");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client");
    let req = match method {
        "GET" => client.get(&url),
        "HEAD" => client.head(&url),
        other => panic!("unmapped method {other}"),
    };
    req.send().expect("reqwest send")
}

const FIXTURES: &[(&str, &[u8])] = &[
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
    (
        "no-content",
        b"HTTP/1.1 204 No Content\r\n\r\n",
    ),
    (
        "not-found",
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
    ),
    (
        "informational-then-200",
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
    ),
];

#[test]
fn http_differential_vs_reqwest() {
    for (name, wire) in FIXTURES {
        for writes in [1usize, 3, 7] {
            let addr = spawn_stub(wire, writes, 2);
            let ours = wrex_fetch(addr, "GET", "/");
            let theirs = reqwest_fetch(addr, "GET", "/");
            assert_eq!(
                ours.status.as_u16(),
                theirs.status().as_u16(),
                "{name} (writes={writes}): status differs"
            );
            let theirs_headers = theirs.headers().clone();
            let theirs_body = theirs.bytes().expect("reqwest body");
            assert_eq!(
                &ours.body[..],
                &theirs_body[..],
                "{name} (writes={writes}): body differs"
            );
            // framing-sensitive header agreement
            for key in ["content-length", "content-type", "transfer-encoding"] {
                let ours_v = ours
                    .headers
                    .get(key)
                    .map(|v| v.to_str().unwrap().to_string());
                let theirs_v = theirs_headers
                    .get(key)
                    .map(|v| v.to_str().unwrap().to_string());
                assert_eq!(ours_v, theirs_v, "{name} (writes={writes}): {key} differs");
            }
        }
    }
}

#[test]
fn http_differential_vs_curl() {
    if !curl_enabled() {
        eprintln!("http_differential_vs_curl: skipping (curl not on PATH or WREX_DIFF_CURL unset)");
        return;
    }
    for (name, wire) in FIXTURES {
        let addr = spawn_stub(wire, 3, 2);
        let url = format!("http://{addr}/");
        let out = std::process::Command::new(which_curl().unwrap())
            .args(["-s", "--http1.1", "-o", "-", "-w", "\n%{http_code}", &url])
            .output()
            .expect("spawn curl");
        assert!(out.status.success(), "{name}: curl failed");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let (body, code) = stdout.rsplit_once('\n').expect("curl -w output");
        let ours = wrex_fetch(addr, "GET", "/");
        assert_eq!(
            ours.status.as_u16().to_string(),
            code,
            "{name}: status differs"
        );
        assert_eq!(&ours.body[..], body.as_bytes(), "{name}: body differs");
    }
}

#[test]
fn http_differential_head_no_body() {
    for oracle in ["reqwest", "curl"] {
        let addr = spawn_stub(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n", 2, 2);
        let ours = wrex_fetch(addr, "HEAD", "/");
        assert!(ours.body.is_empty(), "HEAD must carry no body ({oracle})");
        if oracle == "reqwest" {
            let theirs = reqwest_fetch(addr, "HEAD", "/");
            assert!(theirs.bytes().unwrap().is_empty());
        }
    }
}

// --- tranche 19a: redirect + cookie differentials vs curl ----------------------

/// A routing stub over `cargo test`'s single-response helper: serves
/// `/start` (302 → /next), `/next` (200 body), `/set` (Set-Cookie)
/// and `/echo` (200, body = the request's Cookie header value — the
/// differential oracle trick: equal bodies prove equal headers).
fn spawn_redirect_stub(conns: usize) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for _ in 0..conns {
            let Ok((mut conn, _)) = listener.accept() else {
                return;
            };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            while let Ok(n) = conn.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
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
                    if buf.len() >= pos + 4 + cl {
                        break;
                    }
                }
            }
            let head = String::from_utf8_lossy(&buf).to_string();
            let line = head.lines().next().unwrap_or_default();
            let path = line.split(' ').nth(1).unwrap_or("/");
            let cookie = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("cookie:"))
                .map(|l| l[8..].trim().to_string())
                .unwrap_or_default();
            let resp: Vec<u8> = match path {
                "/start" => {
                    b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n".to_vec()
                }
                "/next" => b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
                "/set" => {
                    b"HTTP/1.1 200 OK\r\nSet-Cookie: diff=1; Path=/\r\nContent-Length: 0\r\n\r\n"
                        .to_vec()
                }
                "/echo" => format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{cookie}",
                    cookie.len()
                )
                .into_bytes(),
                _ => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
            };
            let _ = conn.write_all(&resp);
            let _ = conn.shutdown(std::net::Shutdown::Write);
            let _ = conn.set_read_timeout(Some(Duration::from_millis(200)));
            let _ = conn.read(&mut chunk);
        }
    });
    addr
}

#[test]
fn redirect_differential_vs_curl() {
    if !curl_enabled() {
        eprintln!(
            "redirect_differential_vs_curl: skipping (curl not on PATH or WREX_DIFF_CURL unset)"
        );
        return;
    }
    let addr = spawn_redirect_stub(6);
    let url = format!("http://{addr}/start");
    // curl -L: final body + status must agree
    let out = std::process::Command::new(which_curl().unwrap())
        .args(["-s", "-L", "-o", "-", "-w", "\n%{http_code}", &url])
        .output()
        .expect("spawn curl");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let (body, code) = stdout.rsplit_once('\n').expect("curl -w output");
    assert_eq!(code, "200", "curl followed to /next");
    let ours = wrex_fetch(addr, "GET", "/next");
    assert_eq!(&ours.body[..], body.as_bytes(), "final bodies differ");
    assert_eq!(ours.status.as_u16().to_string(), code);
}

#[test]
fn cookie_differential_vs_curl() {
    if !curl_enabled() {
        eprintln!(
            "cookie_differential_vs_curl: skipping (curl not on PATH or WREX_DIFF_CURL unset)"
        );
        return;
    }
    let addr = spawn_redirect_stub(8);
    let dir = std::env::temp_dir().join("wrex-http-diff-cookies");
    std::fs::create_dir_all(&dir).unwrap();
    let curl_jar = dir.join("curl.jar");
    let wrex_jar = dir.join("wrex.jar");
    let _ = std::fs::remove_file(&curl_jar);
    let _ = std::fs::remove_file(&wrex_jar);

    // Both clients collect /set's cookie, then echo it on /echo.
    let out = std::process::Command::new(which_curl().unwrap())
        .args([
            "-s",
            "-c",
            curl_jar.to_str().unwrap(),
            &format!("http://{addr}/set"),
        ])
        .output()
        .expect("spawn curl");
    assert!(out.status.success());
    let out = std::process::Command::new(which_curl().unwrap())
        .args([
            "-s",
            "-b",
            curl_jar.to_str().unwrap(),
            &format!("http://{addr}/echo"),
        ])
        .output()
        .expect("spawn curl");
    assert!(out.status.success());
    let curl_body = out.stdout.clone();

    // wrex side, through the real binary (the jar path is a CLI
    // concern — the in-process session has no jar).
    let wrex = |args: &[&str]| {
        assert_cmd::Command::new(env!("CARGO_BIN_EXE_wrex"))
            .args(args)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    };
    wrex(&[
        "http",
        "--format",
        "raw",
        "-c",
        wrex_jar.to_str().unwrap(),
        &format!("http://{addr}/set"),
    ]);
    let wrex_body = wrex(&[
        "http",
        "--format",
        "raw",
        "-b",
        wrex_jar.to_str().unwrap(),
        &format!("http://{addr}/echo"),
    ]);
    assert_eq!(curl_body, wrex_body, "the echoed Cookie headers differ");
}

#[test]
fn recipe_replays_byte_identical() {
    let json = r#"{
        "method": "GET",
        "url": "http://example.com:8080/a?b=1",
        "headers": [["X-First", "1"], ["X-Second", "2"]],
        "timeout_ms": 1500
    }"#;
    let recipe: wrex_http::Recipe = serde_json::from_str(json).unwrap();
    let (spec, o) = recipe.into_request().unwrap();
    assert_eq!(o.timeout_ms, Some(1500));
    let wire = spec.serialize().unwrap();
    let recipe2: wrex_http::Recipe = serde_json::from_str(json).unwrap();
    assert_eq!(recipe2.into_request().unwrap().0.serialize().unwrap(), wire);
    // and the wire shape
    let text = String::from_utf8(wire.to_vec()).unwrap();
    assert!(text.starts_with("GET /a?b=1 HTTP/1.1\r\nx-first: 1\r\nx-second: 2\r\n"));
}
