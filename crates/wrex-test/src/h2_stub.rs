//! In-test HTTP/2 stub server (tranche 15): a rustls
//! `ServerConnection` with ALPN in a std thread speaking minimal h2 —
//! the connection preface, SETTINGS exchange, then scripted HEADERS/
//! DATA responses — over a self-signed rcgen certificate (the
//! `tls_stub` pattern, extended with ALPN). Tranche 16b: the same
//! frame loop serves **cleartext prior-knowledge h2c** over a plain
//! `TcpStream` (`spawn_h2c`, no TLS, no certificate).
//!
//! Server-side h2 here is hand-rolled from fixed byte constants (the
//! RFC 7541/9113 examples — `88` = indexed `:status 200`), **not**
//! the wrex-h2 encoder: the codec's oracle stays the RFC known-answer
//! vectors, so this harness never self-confirms. Plain kernel
//! sockets, no capabilities, no external network; not Miri-safe.
//!
//! Two server picks are offered for the ALPN negotiation tests:
//! [`AlpnPick::H2`] (server picks h2 → the client session runs h2) and
//! [`AlpnPick::Http11`] (server picks http/1.1 → the client must
//! auto-downgrade and speak 1.1 on the same TLS connection).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use rustls::StreamOwned;
use rustls::pki_types::PrivateKeyDer;

/// Which ALPN protocol the server picks from the client's offer.
#[derive(Clone, Copy, Debug)]
pub enum AlpnPick {
    /// Negotiate `h2` (the tranche-15 happy path).
    H2,
    /// Negotiate `http/1.1`: the client auto-downgrades (the note
    /// path), and the stub answers plain 1.1 bytes.
    Http11,
}

/// A running h2 stub.
pub struct H2Stub {
    /// Listening address (connect here).
    pub addr: SocketAddr,
    /// The server certificate as PEM (for `--tls-ca` files).
    pub ca_pem: String,
    /// The server certificate as DER (for `ca_der` configs).
    pub ca_der: Vec<u8>,
}

/// The HTTP/2 client connection preface (RFC 9113 §3.4).
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// One SETTINGS frame (empty payload).
fn settings_frame() -> [u8; 9] {
    [0, 0, 0, 0x04, 0x00, 0, 0, 0, 0]
}

/// One frame header for a payload of `len` on `stream`.
fn head(ty: u8, flags: u8, stream: u32, len: usize) -> Vec<u8> {
    let len = len as u32;
    let stream = stream & 0x7fff_ffff;
    vec![
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        ty,
        flags,
        (stream >> 24) as u8,
        (stream >> 16) as u8,
        (stream >> 8) as u8,
        stream as u8,
    ]
}

/// HPACK block for `(:status 200, content-type: text/plain,
/// content-length: N)` — literal-without-indexing representations
/// built from fixed bytes (never the wrex-h2 encoder).
fn response_block(body_len: usize) -> Vec<u8> {
    let mut b = vec![0x88]; // indexed 8 = :status 200 (RFC 7541 A)
    // content-type: text/plain — literal without indexing, new name:
    // 0000 0000 | len 12 | "content-type" | len 10 | "text/plain"
    let name = b"content-type";
    let value = b"text/plain";
    b.push(0x00);
    b.push(name.len() as u8);
    b.extend_from_slice(name);
    b.push(value.len() as u8);
    b.extend_from_slice(value);
    // content-length: N — literal without indexing, new name.
    let name = b"content-length";
    let value = body_len.to_string().into_bytes();
    b.push(0x00);
    b.push(name.len() as u8);
    b.extend_from_slice(name);
    b.push(value.len() as u8);
    b.extend_from_slice(&value);
    b
}

/// One full HEADERS(+DATA) response for a stream. END_STREAM rides the
/// DATA frame when there is a body (the client completes on
/// HEADERS otherwise).
fn response_frames(stream: u32, body: &[u8]) -> Vec<u8> {
    let block = response_block(body.len());
    let mut out = Vec::new();
    let headers_flags = if body.is_empty() { 0x04 | 0x01 } else { 0x04 };
    out.extend(head(0x01, headers_flags, stream, block.len()));
    out.extend(block);
    if !body.is_empty() {
        out.extend(head(0x00, 0x01, stream, body.len()));
        out.extend(body);
    }
    out
}

/// Spawn an h2 stub answering `status`/`body` on every request
/// (`conns` sequential connections; each connection may carry
/// several streams — concurrency is the client's to prove).
pub fn spawn_h2(status: u16, body: &[u8], conns: usize, pick: AlpnPick) -> H2Stub {
    assert_eq!(status, 200, "the canned response block speaks 200 only");
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("rcgen self-signed cert");
    let cert_der = certified.cert.der().clone();
    let key =
        PrivateKeyDer::try_from(certified.signing_key.serialize_der()).expect("rcgen key pkcs8");
    let ca_pem = certified.cert.pem();
    let ca_der = certified.cert.der().to_vec();

    let mut server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .expect("stub server config");
    server_cfg.alpn_protocols = match pick {
        AlpnPick::H2 => vec![b"h2".to_vec()],
        AlpnPick::Http11 => vec![b"http/1.1".to_vec()],
    };
    let server_cfg = Arc::new(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let addr = listener.local_addr().expect("addr");
    let body = body.to_vec();
    std::thread::spawn(move || {
        for _ in 0..conns {
            let Ok(conn) = listener.accept() else {
                return;
            };
            serve(conn.0, server_cfg.clone(), &body, pick);
        }
    });
    H2Stub {
        addr,
        ca_pem,
        ca_der,
    }
}

/// One connection: TLS handshake with ALPN, then the picked protocol.
///
/// The handshake must be **driven before** the ALPN pick is visible
/// (`alpn_protocol` is only set once the ClientHello is processed);
/// `complete_io` also keeps any early app data (the client sends the
/// h2 preface right after its handshake) buffered in the connection
/// for the protocol phase to read.
fn serve(conn: std::net::TcpStream, cfg: Arc<rustls::ServerConfig>, body: &[u8], pick: AlpnPick) {
    // Bound every blocking op so a wedged peer can never hang the test
    // thread (the clients here always send promptly).
    let _ = conn.set_read_timeout(Some(Duration::from_secs(20)));
    let _ = conn.set_write_timeout(Some(Duration::from_secs(20)));
    let mut server = rustls::ServerConnection::new(cfg).expect("server conn");
    let mut sock = conn;
    while server.is_handshaking() {
        if server.complete_io(&mut sock).is_err() {
            return;
        }
    }
    // The server offered exactly one protocol (see `spawn_h2`): what
    // the client picked decides the wire phase.
    let use_h2 = matches!((pick, server.alpn_protocol()), (AlpnPick::H2, Some(b"h2")));
    let mut tls = StreamOwned::new(server, sock);
    if use_h2 {
        serve_h2(&mut tls, body);
    } else {
        serve_11(&mut tls, body);
    }
}

/// Plain HTTP/1.1: consume one request head, answer `200` + body.
fn serve_11(tls: &mut StreamOwned<rustls::ServerConnection, std::net::TcpStream>, body: &[u8]) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while let Ok(n) = tls.read(&mut chunk) {
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut wire = head.into_bytes();
    wire.extend_from_slice(body);
    let _ = tls.write_all(&wire);
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

/// Minimal h2: preface, SETTINGS, then one response per request
/// stream (read frames until HEADERS/DATA with END_STREAM).
/// Tranche 16b: the frame loop is transport-agnostic — TLS streams
/// and cleartext prior-knowledge sockets speak the same frames.
fn serve_h2<S: Read + Write>(io: &mut S, body: &[u8]) {
    // Consume the client preface.
    let mut pre = vec![0u8; PREFACE.len()];
    if io.read_exact(&mut pre).is_err() || pre != PREFACE {
        return;
    }
    // Client SETTINGS (empty): consume its 9-byte frame, answer ours.
    let mut frame = vec![0u8; 9];
    if io.read_exact(&mut frame).is_err() {
        return;
    }
    if io.write_all(&settings_frame()).is_err() {
        return;
    }
    // Respond to each request stream on this connection.
    loop {
        let mut header = [0u8; 9];
        if io.read_exact(&mut header).is_err() {
            return;
        }
        let ty = header[3];
        let flags = header[4];
        let stream = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
        let len = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let mut payload = vec![0u8; len];
        if !payload.is_empty() && io.read_exact(&mut payload).is_err() {
            return;
        }
        // SETTINGS from the client → ACK; PING → ACK; request frames
        // with END_STREAM → the canned response.
        match ty {
            0x04 if flags & 0x01 == 0 => {
                let ack = head(0x04, 0x01, 0, 0);
                if io.write_all(&ack).is_err() {
                    return;
                }
            }
            0x06 if flags & 0x01 == 0 => {
                let mut ack = head(0x06, 0x01, 0, 8);
                ack.extend(payload);
                if io.write_all(&ack).is_err() {
                    return;
                }
            }
            0x01 | 0x00 if flags & 0x01 != 0 => {
                let response = response_frames(stream, body);
                if io.write_all(&response).is_err() {
                    return;
                }
            }
            _ => {}
        }
        let _ = stream;
    }
}

/// A running cleartext (h2c prior-knowledge, tranche 16b) stub: plain
/// TCP, the h2 frame loop, no TLS and no certificate.
pub struct H2cStub {
    /// Listening address (connect here).
    pub addr: SocketAddr,
}

/// Spawn a cleartext h2c stub (prior knowledge, RFC 9113 §3.4: no
/// `Upgrade:`, the client sends the preface directly) answering
/// `status`/`body` on every request stream (`conns` sequential
/// connections; each connection may carry several streams).
pub fn spawn_h2c(status: u16, body: &[u8], conns: usize) -> H2cStub {
    assert_eq!(status, 200, "the canned response block speaks 200 only");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let addr = listener.local_addr().expect("addr");
    let body = body.to_vec();
    std::thread::spawn(move || {
        for _ in 0..conns {
            let Ok(conn) = listener.accept() else {
                return;
            };
            let mut sock = conn.0;
            let _ = sock.set_read_timeout(Some(Duration::from_secs(20)));
            let _ = sock.set_write_timeout(Some(Duration::from_secs(20)));
            serve_h2(&mut sock, &body);
        }
    });
    H2cStub { addr }
}
