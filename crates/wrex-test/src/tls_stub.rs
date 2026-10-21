//! In-test TLS stub server (tranche 8a): a rustls `ServerConnection` in
//! a std thread answering scripted raw bytes over a self-signed rcgen
//! certificate — the https/DoT counterpart of the raw-`TcpListener`
//! stubs in `crates/wrex/tests` (plain kernel sockets, no privileges,
//! no external network; not Miri-safe).
//!
//! The certificate is deliberately self-signed: the insecure path
//! accepts it outright, the verifying paths trust it via its own DER
//! (the `--tls-ca` contract). SANs cover both shapes the verbs
//! produce: the `127.0.0.1` IP literal (`--server`/URL host) and
//! `localhost`.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::StreamOwned;
use rustls::pki_types::PrivateKeyDer;

/// How the stub consumes one request before answering.
#[derive(Clone, Copy, Debug)]
pub enum StubRequest {
    /// Read one HTTP request head (+ a declared Content-Length body).
    HttpHead,
    /// Read one 2-byte big-endian length prefix + that many bytes
    /// (RFC 7766 / RFC 7858 DNS framing).
    LengthPrefixed2,
    /// Read one length-prefixed DNS query, then answer it: a canned
    /// A-record reply echoing the query's id + question (the
    /// `query --tcp/--tls` stubs; matching is id-based, so the reply
    /// must derive from the query).
    DnsReply,
}

/// A running TLS stub.
pub struct TlsStub {
    /// Listening address (connect here).
    pub addr: SocketAddr,
    /// The server certificate as PEM (for `--tls-ca` files).
    pub ca_pem: String,
    /// The server certificate as DER (for `ca_der` configs).
    pub ca_der: Vec<u8>,
}

/// Spawn a stub answering `response` (in `writes`-sized pieces, to
/// exercise TLS record boundaries on real sockets) on each of `conns`
/// sequential connections, then closing with `close_notify`.
pub fn spawn(response: Vec<u8>, writes: usize, conns: usize, request: StubRequest) -> TlsStub {
    // Self-signed with both IP and DNS SANs (see the module doc).
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])
            .expect("rcgen self-signed cert");
    let cert_der = certified.cert.der().clone();
    let key =
        PrivateKeyDer::try_from(certified.signing_key.serialize_der()).expect("rcgen key to pkcs8");
    let ca_pem = certified.cert.pem();
    let ca_der = certified.cert.der().to_vec();

    let server_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .expect("stub server config");
    let server_cfg = Arc::new(server_cfg);

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let addr = listener.local_addr().expect("addr");
    std::thread::spawn(move || {
        for _ in 0..conns {
            let Ok(conn) = listener.accept() else {
                return;
            };
            serve(conn.0, server_cfg.clone(), &response, writes, request);
        }
    });
    TlsStub {
        addr,
        ca_pem,
        ca_der,
    }
}

/// One connection: handshake, consume one request, write the scripted
/// response pieces, close_notify, drop.
fn serve(
    conn: TcpStream,
    cfg: Arc<rustls::ServerConfig>,
    response: &[u8],
    writes: usize,
    request: StubRequest,
) {
    // Bound every blocking op so a wedged peer can never hang the test
    // thread (the clients here always send promptly).
    let _ = conn.set_read_timeout(Some(Duration::from_secs(20)));
    let _ = conn.set_write_timeout(Some(Duration::from_secs(20)));
    let mut tls = StreamOwned::new(
        rustls::ServerConnection::new(cfg).expect("server conn"),
        conn,
    );

    // Consume one request (the clients send it in one burst), then
    // pick the outgoing payload.
    let payload: Vec<u8> = match request {
        StubRequest::HttpHead => {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            while let Ok(n) = tls.read(&mut chunk) {
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
            response.to_vec()
        }
        StubRequest::LengthPrefixed2 => {
            let mut len_buf = [0u8; 2];
            if tls.read_exact(&mut len_buf).is_err() {
                return;
            }
            let mut query = vec![0u8; u16::from_be_bytes(len_buf) as usize];
            if tls.read_exact(&mut query).is_err() {
                return;
            }
            response.to_vec()
        }
        StubRequest::DnsReply => {
            let mut len_buf = [0u8; 2];
            if tls.read_exact(&mut len_buf).is_err() {
                return;
            }
            let mut query = vec![0u8; u16::from_be_bytes(len_buf) as usize];
            if tls.read_exact(&mut query).is_err() {
                return;
            }
            let reply = dns_reply(&query);
            let mut wire = Vec::with_capacity(2 + reply.len());
            wire.extend_from_slice(&(reply.len() as u16).to_be_bytes());
            wire.extend_from_slice(&reply);
            wire
        }
    };

    // Scripted writes (record-boundary exercise).
    let piece = (payload.len() / writes.max(1)).max(1);
    let mut off = 0;
    while off < payload.len() {
        let end = (off + piece).min(payload.len());
        if tls.write_all(&payload[off..end]).is_err() {
            break;
        }
        off = end;
    }
    // Orderly TLS close: close_notify then drop (TCP FIN).
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

/// One canned A-record reply for a query: id + question echoed
/// verbatim, qr/rd/ra flags, one 93.184.216.34 answer (the raw-stub
/// helper in `crates/wrex/tests/query_driver.rs`, TLS-wrapped).
fn dns_reply(query: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&query[..2]); // echo id
    msg.extend_from_slice(&[0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    msg.extend_from_slice(&query[12..]); // echo question
    msg.extend_from_slice(&[
        0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 93, 184, 216, 34,
    ]);
    msg
}
