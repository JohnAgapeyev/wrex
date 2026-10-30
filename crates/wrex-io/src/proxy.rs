//! Proxy tunneling (tranche 19b): SOCKS5 (RFC 1928 + the RFC 1929
//! user/password method) and the HTTP `CONNECT` tunnel (RFC 9110
//! §9.3.6), establishing a [`TcpDriver`] to the DESTINATION through a
//! proxy — the sessions above never know a proxy is in the path.
//!
//! No unsafe here (the plain `TcpStream` std paths; the handshakes are
//! tiny, deadline-bounded reads). `socks5://` resolves the destination
//! locally and sends an address ATYP; `socks5h://` sends the hostname
//! (the proxy resolves — curl's grammar).

use std::io::{Error, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::driver::DriverError;
use crate::tcp::TcpDriver;

/// One parsed proxy endpoint (the verb owns the scheme grammar).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyKind {
    /// Plain HTTP proxy: absolute-form request-targets for `http://`,
    /// `CONNECT` tunnels for `https://`.
    Http,
    /// SOCKS5 with local destination resolution (address ATYP).
    Socks5,
    /// SOCKS5 with proxy-side resolution (hostname ATYP — `socks5h`).
    Socks5Remote,
}

/// The parsed `--proxy` plan.
#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub kind: ProxyKind,
    pub proxy: SocketAddr,
    /// `--proxy-user` (Basic for CONNECT, RFC 1929 for SOCKS5).
    pub user: Option<String>,
    pub pass: Option<String>,
}

fn other(msg: impl Into<String>) -> DriverError {
    DriverError::Io {
        source: Error::other(msg.into()),
    }
}

fn timed_out() -> DriverError {
    DriverError::Io {
        source: Error::new(ErrorKind::TimedOut, "proxy handshake timed out"),
    }
}

/// Read exactly `n` bytes under the deadline (tiny handshake reads).
fn read_exact_deadline(
    stream: &mut TcpStream,
    n: usize,
    deadline: Instant,
) -> Result<Vec<u8>, DriverError> {
    let mut buf = vec![0u8; n];
    let mut got = 0;
    while got < n {
        if Instant::now() >= deadline {
            return Err(timed_out());
        }
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok();
        match stream.read(&mut buf[got..]) {
            Ok(0) => {
                return Err(other(
                    "proxy closed the connection mid-handshake".to_string(),
                ));
            }
            Ok(k) => got += k,
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => return Err(DriverError::Io { source: e }),
        }
    }
    Ok(buf)
}

/// Write it all under the deadline.
fn write_all_deadline(
    stream: &mut TcpStream,
    bytes: &[u8],
    deadline: Instant,
) -> Result<(), DriverError> {
    let mut off = 0;
    while off < bytes.len() {
        if Instant::now() >= deadline {
            return Err(timed_out());
        }
        stream
            .set_write_timeout(Some(Duration::from_millis(100)))
            .ok();
        match stream.write(&bytes[off..]) {
            Ok(0) => {
                return Err(other("proxy accepted no handshake bytes".to_string()));
            }
            Ok(n) => off += n,
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => return Err(DriverError::Io { source: e }),
        }
    }
    Ok(())
}

/// SOCKS5 (RFC 1928): method negotiation (no-auth, or RFC 1929
/// user/password when `--proxy-user` is set), then CONNECT to the
/// destination — a hostname under `Socks5Remote`, the locally
/// resolved address otherwise. Returns the ESTABLISHED driver (the
/// destination peer, named for rendering).
pub fn connect_socks5(
    cfg: &ProxyConfig,
    dest_host: &str,
    dest_port: u16,
    bind: Option<SocketAddr>,
    timeout: Duration,
) -> Result<TcpDriver, DriverError> {
    let deadline = Instant::now() + timeout;
    let mut stream = crate::tcp::tcp_connect(cfg.proxy, bind, timeout)?;
    // Method negotiation (§3): no-auth, plus RFC 1929 when credentials
    // are set.
    let greeting: &[u8] = if cfg.user.is_some() {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    write_all_deadline(&mut stream, greeting, deadline)?;
    let reply = read_exact_deadline(&mut stream, 2, deadline)?;
    if reply[0] != 0x05 {
        return Err(other(format!("socks5: bad version byte {:#x}", reply[0])));
    }
    match reply[1] {
        0x00 => {} // no auth
        0x02 => {
            // RFC 1929 §2: 1 | len(user) | user | len(pass) | pass.
            let user = cfg.user.as_deref().unwrap_or_default();
            let pass = cfg.pass.as_deref().unwrap_or_default();
            if user.len() > 255 || pass.len() > 255 {
                return Err(other(
                    "socks5: proxy credentials exceed the RFC 1929 length limit",
                ));
            }
            let mut auth = vec![0x01u8, user.len() as u8];
            auth.extend_from_slice(user.as_bytes());
            auth.push(pass.len() as u8);
            auth.extend_from_slice(pass.as_bytes());
            write_all_deadline(&mut stream, &auth, deadline)?;
            let verdict = read_exact_deadline(&mut stream, 2, deadline)?;
            if verdict[1] != 0x00 {
                return Err(other(format!(
                    "socks5: proxy rejected the credentials (status {})",
                    verdict[1]
                )));
            }
        }
        0xFF => return Err(other("socks5: proxy accepts none of the offered methods")),
        other_method => {
            return Err(other(format!(
                "socks5: proxy picked unknown method {other_method:#x}"
            )));
        }
    }
    // CONNECT request (§4): VER CMD RSV ATYP DST.ADDR DST.PORT.
    let mut req = vec![0x05u8, 0x01, 0x00];
    match cfg.kind {
        ProxyKind::Socks5Remote => {
            let host = dest_host.trim_start_matches('[').trim_end_matches(']');
            if host.len() > 255 {
                return Err(other(
                    "socks5: destination hostname exceeds the ATYP length limit",
                ));
            }
            req.push(0x03);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
        _ => {
            // Local resolution (socks5://): the first address that
            // answers (std's tuple resolver).
            let addr = (dest_host, dest_port)
                .to_socket_addrs()
                .map_err(|_| other(format!("socks5: cannot resolve `{dest_host}`")))?
                .next()
                .ok_or_else(|| other(format!("socks5: cannot resolve `{dest_host}`")))?;
            match addr.ip() {
                std::net::IpAddr::V4(v4) => {
                    req.push(0x01);
                    req.extend_from_slice(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    req.push(0x04);
                    req.extend_from_slice(&v6.octets());
                }
            }
        }
    }
    req.extend_from_slice(&dest_port.to_be_bytes());
    write_all_deadline(&mut stream, &req, deadline)?;
    // Reply (§6): VER REP RSV ATYP then BND.ADDR BND.PORT — the bound
    // address length varies with ATYP; read the 4-byte head, then the
    // variable tail.
    let head = read_exact_deadline(&mut stream, 4, deadline)?;
    if head[0] != 0x05 {
        return Err(other(format!("socks5: bad reply version {:#x}", head[0])));
    }
    if head[1] != 0x00 {
        return Err(other(format!(
            "socks5: connect failed (reply status {})",
            head[1]
        )));
    }
    let tail = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => read_exact_deadline(&mut stream, 1, deadline)?[0] as usize,
        atyp => return Err(other(format!("socks5: unknown reply ATYP {atyp:#x}"))),
    };
    let _bound = read_exact_deadline(&mut stream, tail + 2, deadline)?;
    Ok(TcpDriver::from_stream(
        stream,
        format!("{dest_host}:{dest_port}"),
    ))
}

/// The HTTP `CONNECT` tunnel (RFC 9110 §9.3.6): request the tunnel,
/// require 2xx, return the established driver (the destination peer,
/// named for rendering — the wire peer is the proxy). `basic_auth` is
/// a computed `Basic …` value for the `Proxy-Authorization` header.
pub fn connect_http_tunnel(
    cfg: &ProxyConfig,
    authority: &str,
    bind: Option<SocketAddr>,
    timeout: Duration,
    basic_auth: Option<&str>,
) -> Result<TcpDriver, DriverError> {
    let deadline = Instant::now() + timeout;
    let mut stream = crate::tcp::tcp_connect(cfg.proxy, bind, timeout)?;
    let mut req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some(basic) = basic_auth {
        req.push_str(&format!("Proxy-Authorization: {basic}\r\n"));
    }
    req.push_str("\r\n");
    write_all_deadline(&mut stream, req.as_bytes(), deadline)?;
    // Read the response head (bounded — a proxy header flood is
    // hostile data, not a request).
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8 * 1024 {
            return Err(other("http proxy: response head too long"));
        }
        if Instant::now() >= deadline {
            return Err(timed_out());
        }
        stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok();
        match stream.read(&mut byte) {
            Ok(0) => {
                return Err(other("http proxy closed before answering CONNECT"));
            }
            Ok(_) => head.push(byte[0]),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => return Err(DriverError::Io { source: e }),
        }
    }
    let head = String::from_utf8_lossy(&head).to_string();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            other(format!(
                "http proxy: unparseable CONNECT response `{}`",
                head.lines().next().unwrap_or_default()
            ))
        })?;
    if !(200..300).contains(&status) {
        return Err(other(format!(
            "http proxy: CONNECT denied (status {status})"
        )));
    }
    let dest = authority
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(authority);
    Ok(TcpDriver::from_stream(stream, dest.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// A scripted SOCKS5 proxy: asserts the greeting/method/auth/request
    /// bytes, replies per `scenario`, then (on success) echoes the
    /// tunneled bytes so the caller can speak HTTP through the tunnel.
    enum SocksScenario {
        Plain,
        AuthOk,
        AuthReject,
        ConnectFail,
    }

    fn spawn_socks5(
        scenario: SocksScenario,
    ) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let read = |conn: &mut TcpStream, n: usize| {
                let mut buf = vec![0u8; n];
                conn.read_exact(&mut buf).unwrap();
                buf
            };
            match scenario {
                SocksScenario::Plain | SocksScenario::ConnectFail => {
                    seen2.lock().unwrap().push(read(&mut conn, 3));
                    conn.write_all(&[0x05, 0x00]).unwrap();
                }
                SocksScenario::AuthOk | SocksScenario::AuthReject => {
                    seen2.lock().unwrap().push(read(&mut conn, 4));
                    conn.write_all(&[0x05, 0x02]).unwrap();
                    let auth = read(&mut conn, 2);
                    let user = read(&mut conn, auth[1] as usize);
                    let plen = read(&mut conn, 1);
                    let pass = read(&mut conn, plen[0] as usize);
                    seen2
                        .lock()
                        .unwrap()
                        .push([auth, user, plen, pass].concat());
                    let verdict = if matches!(scenario, SocksScenario::AuthOk) {
                        0x00
                    } else {
                        0x01
                    };
                    conn.write_all(&[0x01, verdict]).unwrap();
                    if !matches!(scenario, SocksScenario::AuthOk) {
                        return;
                    }
                }
            }
            // The CONNECT request (variable length: VER CMD RSV ATYP,
            // then the address + port).
            let head = read(&mut conn, 4);
            let mut req = head.clone();
            match head[3] {
                0x01 => req.extend(read(&mut conn, 4 + 2)),
                0x03 => {
                    let n = read(&mut conn, 1)[0] as usize;
                    req.push(n as u8);
                    req.extend(read(&mut conn, n + 2));
                }
                0x04 => req.extend(read(&mut conn, 16 + 2)),
                _ => unreachable!(),
            }
            seen2.lock().unwrap().push(req);
            if matches!(scenario, SocksScenario::ConnectFail) {
                conn.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .unwrap();
                return;
            }
            conn.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .unwrap();
            // The tunnel: echo (the caller asserts through-driver IO).
            let (mut r, _addr) = (conn.try_clone().unwrap(), ());
            let _ = r.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0u8; 1024];
            if let Ok(n) = r.read(&mut buf) {
                let _ = conn.write_all(&buf[..n]);
            }
        });
        (port, seen)
    }

    fn cfg(port: u16, kind: ProxyKind, user: Option<&str>, pass: Option<&str>) -> ProxyConfig {
        ProxyConfig {
            kind,
            proxy: SocketAddr::from(([127, 0, 0, 1], port)),
            user: user.map(str::to_string),
            pass: pass.map(str::to_string),
        }
    }

    const TIMEOUT: Duration = Duration::from_secs(5);

    #[test]
    fn socks5_handshake_shapes() {
        // No-auth: greeting [05 01 00], domain ATYP when remote.
        let (port, seen) = spawn_socks5(SocksScenario::Plain);
        let c = cfg(port, ProxyKind::Socks5Remote, None, None);
        let mut driver = connect_socks5(&c, "wrex.test", 8080, None, TIMEOUT).unwrap();
        let handshake = seen.lock().unwrap();
        assert_eq!(handshake[0], vec![0x05, 0x01, 0x00], "no-auth greeting");
        let req = &handshake[1];
        assert_eq!(&req[..4], &[0x05, 0x01, 0x00, 0x03], "CONNECT + ATYP 3");
        assert_eq!(req[4], b"wrex.test".len() as u8);
        assert_eq!(&req[5..14], b"wrex.test");
        assert_eq!(&req[14..], &8080u16.to_be_bytes());
        drop(handshake);
        // The tunnel carries bytes both ways.
        use crate::driver::Driver as _;
        driver.send(b"ping").unwrap();
        let frame = driver
            .recv(Instant::now() + TIMEOUT)
            .unwrap()
            .expect("echo");
        assert_eq!(&frame.bytes[..], b"ping");
    }

    #[test]
    fn socks5_local_resolution_and_auth() {
        // socks5:// resolves locally: an IP ATYP.
        let (port, seen) = spawn_socks5(SocksScenario::Plain);
        let c = cfg(port, ProxyKind::Socks5, None, None);
        connect_socks5(&c, "127.0.0.1", 9999, None, TIMEOUT).unwrap();
        let handshake = seen.lock().unwrap();
        assert_eq!(
            &handshake[1][..5],
            &[0x05, 0x01, 0x00, 0x01, 127],
            "ATYP 1 + v4"
        );
        assert_eq!(
            &handshake[1][5..],
            &[0, 0, 1, 0x27, 0x0F],
            "v4 tail + port 9999"
        );
        drop(handshake);
        // RFC 1929 auth: accepted.
        let (port, seen) = spawn_socks5(SocksScenario::AuthOk);
        let c = cfg(port, ProxyKind::Socks5Remote, Some("u"), Some("p"));
        connect_socks5(&c, "wrex.test", 80, None, TIMEOUT).unwrap();
        let handshake = seen.lock().unwrap();
        assert_eq!(
            handshake[0],
            vec![0x05, 0x02, 0x00, 0x02],
            "two methods offered"
        );
        assert_eq!(
            handshake[1],
            vec![0x01, 1, b'u', 1, b'p'],
            "RFC 1929 subnegotiation"
        );
        drop(handshake);
        // Rejected credentials: pointed error.
        let (port, _seen) = spawn_socks5(SocksScenario::AuthReject);
        let c = cfg(port, ProxyKind::Socks5Remote, Some("u"), Some("wrong"));
        let err = connect_socks5(&c, "wrex.test", 80, None, TIMEOUT)
            .map(|_| ())
            .unwrap_err();
        assert!(err.to_string().contains("rejected"), "{err}");
    }

    #[test]
    fn socks5_connect_failure_and_short_host() {
        let (port, _seen) = spawn_socks5(SocksScenario::ConnectFail);
        let c = cfg(port, ProxyKind::Socks5Remote, None, None);
        let err = connect_socks5(&c, "wrex.test", 80, None, TIMEOUT)
            .map(|_| ())
            .unwrap_err();
        assert!(err.to_string().contains("reply status 4"), "{err}");
        // socks5:// with an unresolvable host: pointed error.
        let (port, _seen) = spawn_socks5(SocksScenario::Plain);
        let c = cfg(port, ProxyKind::Socks5, None, None);
        let err = connect_socks5(&c, "no.such.host.wrex.invalid", 80, None, TIMEOUT)
            .map(|_| ())
            .unwrap_err();
        assert!(err.to_string().contains("resolve"), "{err}");
    }

    /// A scripted HTTP CONNECT proxy: records the request head, answers
    /// with `status`, then (on 2xx) echoes the tunneled bytes.
    fn spawn_connect_proxy(status: u16) -> (u16, std::sync::Arc<std::sync::Mutex<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let seen2 = seen.clone();
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
            *seen2.lock().unwrap() = String::from_utf8_lossy(&buf).to_string();
            conn.write_all(format!("HTTP/1.1 {status} x\r\nContent-Length: 0\r\n\r\n").as_bytes())
                .unwrap();
            if (200..300).contains(&status) {
                let _ = conn.set_read_timeout(Some(Duration::from_secs(2)));
                let mut echo = [0u8; 1024];
                if let Ok(n) = conn.read(&mut echo) {
                    let _ = conn.write_all(&echo[..n]);
                }
            }
        });
        (port, seen)
    }

    #[test]
    fn http_connect_tunnel_shapes() {
        let (port, seen) = spawn_connect_proxy(200);
        let c = cfg(port, ProxyKind::Http, None, None);
        let mut driver = connect_http_tunnel(&c, "wrex.test:443", None, TIMEOUT, None).unwrap();
        let head = seen.lock().unwrap().clone();
        assert!(
            head.starts_with("CONNECT wrex.test:443 HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(head.contains("Host: wrex.test:443"), "{head}");
        // The tunnel carries bytes both ways.
        use crate::driver::Driver as _;
        driver.send(b"tls-bytes").unwrap();
        let frame = driver
            .recv(Instant::now() + TIMEOUT)
            .unwrap()
            .expect("echo");
        assert_eq!(&frame.bytes[..], b"tls-bytes");
        // Proxy-Authorization rides when given.
        let (port, seen) = spawn_connect_proxy(200);
        let c = cfg(port, ProxyKind::Http, Some("u"), Some("p"));
        connect_http_tunnel(&c, "wrex.test:443", None, TIMEOUT, Some("Basic dTpw")).unwrap();
        let head = seen.lock().unwrap().clone();
        assert!(head.contains("Proxy-Authorization: Basic dTpw"), "{head}");
        // Non-2xx: pointed error.
        let (port, _seen) = spawn_connect_proxy(403);
        let c = cfg(port, ProxyKind::Http, None, None);
        let err = connect_http_tunnel(&c, "wrex.test:443", None, TIMEOUT, None)
            .map(|_| ())
            .unwrap_err();
        assert!(err.to_string().contains("status 403"), "{err}");
    }
}
