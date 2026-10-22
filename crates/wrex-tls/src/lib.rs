#![forbid(unsafe_code)]
//! wrex-tls: the TLS driver adapter (tranche 8a) — a rustls
//! [`ClientConnection`](rustls::ClientConnection) composed over the
//! kernel [`wrex_io::TcpDriver`], behind the frozen
//! [`wrex_io::Driver`] contract.
//!
//! This is a *driver adapter*, not a crypto stack: rustls owns every
//! cryptographic decision; this crate only moves bytes between the
//! rustls connection and the inner TCP driver under the stream
//! conventions the HTTP/1.1 and DNS/TCP sessions already speak:
//!
//! - `recv` returns **whatever plaintext arrived before the deadline**
//!   as one frame (a chunk), never blocking past it;
//! - **orderly TLS close (`close_notify`) arrives as an empty frame**
//!   (`bytes.len() == 0`), like the plain `TcpDriver`'s EOF; a TCP EOF
//!   without `close_notify` is mapped to the same empty frame (the
//!   sessions treat truncation as data either way);
//! - io and TLS protocol errors (including certificate verification
//!   failures) surface as `io::Error`s → runtime errors, exit 1.
//!
//! The handshake is driven lazily inside the first `send`/`recv` pump
//! under the caller's deadline: `send` buffers plaintext into the
//! rustls connection and flushes whatever TLS records are ready
//! (ClientHello, then the queued request once the handshake completes
//! during `recv` pumping). Callers that must know the *negotiated
//! protocol* before sending (ALPN-picked sessions, tranche 15) drive
//! [`TlsDriver::complete_handshake`] first.
//!
//! ALPN (tranche 15): [`TlsConfig::alpn_protocols`] offers protocols
//! in order; the negotiated one is exposed as
//! [`TlsDriver::alpn_protocol`] once the handshake completes (None
//! before, or when the peer offers none). Close mode: one exchange per
//! connection, unchanged from the tranche-4 contract.
//!
//! ## The insecure path
//!
//! `TlsConfig::insecure` swaps the webpki verifier for a
//! `rustls::client::danger` verifier that accepts **any** certificate
//! and any handshake signature — the `dangerous()` builder API is safe
//! code, but the semantics are deliberately unsafe-in-the-security-
//! sense: no name, chain, or validity check happens. Behind the
//! `--tls-insecure` flag, documented at every surface.

use std::io;
use std::io::{Read as _, Write as _};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::ring,
};
use thiserror::Error;

use wrex_io::driver::{Driver, DriverError, Frame};
use wrex_io::tcp::TcpDriver;

/// TLS setup/connection failures → CLI exit 1.
#[derive(Debug, Error)]
pub enum TlsError {
    /// Bad config: server name, root store, CA file.
    #[error("tls: {0}")]
    Config(String),
    /// Underlying driver failure (connect, io).
    #[error(transparent)]
    Driver(#[from] DriverError),
}

/// TLS client knobs (all fields optional-quality: the verifier is
/// rustls's own; nothing here is hand-rolled crypto).
#[derive(Clone, Debug)]
pub struct TlsConfig {
    /// SNI/server name: the URL host or `--server` value. An IP string
    /// is treated as an IP SAN (rustls parses both shapes).
    pub server_name: String,
    /// Accept any certificate (see the module doc: no checks at all).
    pub insecure: bool,
    /// Additional DER trust anchors that **complement** the system
    /// roots (the `--tls-ca FILE` contract).
    pub ca_der: Option<Vec<Vec<u8>>>,
    /// ALPN protocol identifiers to offer, in preference order
    /// (tranche 15: `["h2", "http/1.1"]` behind `wrex http
    /// --http-version 2`). Empty (the default since 8a) negotiates
    /// nothing — plain https/1.1 semantics.
    pub alpn_protocols: Vec<String>,
}

/// Load a CA bundle file for [`TlsConfig::ca_der`]: a PEM file yields
/// every `CERTIFICATE` block, anything else is taken as one raw DER
/// certificate.
pub fn load_ca_file(path: &str) -> Result<Vec<Vec<u8>>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("cannot read ca file `{path}`: {e}"))?;
    if raw.windows(10).any(|w| w == b"-----BEGIN") {
        let mut der = Vec::new();
        for cert in rustls_pemfile::certs(&mut raw.as_slice()) {
            let cert = cert.map_err(|e| format!("bad pem in `{path}`: {e}"))?;
            der.push(cert.to_vec());
        }
        if der.is_empty() {
            return Err(format!("no CERTIFICATE blocks in `{path}`"));
        }
        Ok(der)
    } else {
        // Not PEM: one raw DER certificate.
        Ok(vec![raw])
    }
}

/// The accept-anything verifier for the insecure path (see the module
/// doc): every chain verifies, every handshake signature verifies.
#[derive(Debug)]
struct AcceptAnyVerifier {
    /// Signature schemes advertised to the peer (the ring provider's
    /// full list, so any standard server signature reaches the
    /// accepting `verify_tls{12,13}_signature`).
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for AcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

/// Build the root store: system roots plus the caller's `ca_der`
/// additions (complementary, never replacing).
fn root_store(cfg: &TlsConfig) -> Result<RootCertStore, String> {
    let mut store = RootCertStore::empty();
    let mut anchors = 0usize;
    let native = rustls_native_certs::load_native_certs();
    if let Some(e) = native.errors.first() {
        return Err(format!("loading system roots: {e}"));
    }
    for der in native.certs {
        if store.add(der).is_ok() {
            anchors += 1;
        }
    }
    for der in cfg.ca_der.iter().flatten() {
        store
            .add(CertificateDer::from(der.clone()))
            .map_err(|e| format!("ca certificate: {e}"))?;
        anchors += 1;
    }
    if anchors == 0 {
        return Err("no trusted roots (system store empty and no --tls-ca)".to_string());
    }
    Ok(store)
}

/// Build the rustls client config from the wrex knobs.
fn client_config(cfg: &TlsConfig) -> Result<ClientConfig, String> {
    // ring provider (workspace pin: no aws-lc default; see Cargo.toml).
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| format!("tls provider: {e}"))?;
    let builder = if cfg.insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyVerifier {
                schemes: provider
                    .signature_verification_algorithms
                    .mapping
                    .iter()
                    .map(|(scheme, _)| *scheme)
                    .collect(),
            }))
    } else {
        builder.with_root_certificates(root_store(cfg)?)
    };
    // No client certs (mTLS is a deferral). ALPN: offered in the
    // caller's order (tranche 15); the negotiated protocol is exposed
    // on the driver (a public field on this rustls line).
    let mut config = builder.with_no_client_auth();
    config.alpn_protocols = cfg
        .alpn_protocols
        .iter()
        .map(|p| p.as_bytes().to_vec())
        .collect();
    Ok(config)
}

/// A TLS client connection over the inner [`TcpDriver`].
pub struct TlsDriver {
    conn: ClientConnection,
    inner: TcpDriver,
    peer: String,
    /// TLS close (or inner EOF) seen: further `recv` calls keep
    /// yielding the empty (EOF) frame, like `TcpDriver::closed`.
    closed: bool,
}

impl TlsDriver {
    /// Connect the inner TCP driver and wrap it in TLS. `timeout`
    /// bounds the TCP connect (the TLS handshake rides the first
    /// send/recv pump under the caller's deadline).
    pub fn connect(
        peer: SocketAddr,
        bind: Option<SocketAddr>,
        timeout: Duration,
        cfg: &TlsConfig,
    ) -> Result<Self, TlsError> {
        let inner = TcpDriver::connect(peer, bind, timeout)?;
        let server_name = ServerName::try_from(cfg.server_name.as_str())
            .map_err(|e| TlsError::Config(format!("bad server name `{}`: {e}", cfg.server_name)))?
            .to_owned();
        let conn = ClientConnection::new(
            Arc::new(client_config(cfg).map_err(TlsError::Config)?),
            server_name,
        )
        .map_err(|e| TlsError::Config(format!("tls: {e}")))?;
        Ok(Self {
            conn,
            inner,
            peer: peer.to_string(),
            closed: false,
        })
    }

    /// The connected peer address (rendering/diagnostics).
    pub fn peer(&self) -> &str {
        &self.peer
    }

    /// The negotiated ALPN protocol (tranche 15), once the handshake
    /// completes: `None` before, or when neither side offered.
    pub fn alpn_protocol(&self) -> Option<&str> {
        self.conn
            .alpn_protocol()
            .and_then(|p| std::str::from_utf8(p).ok())
    }

    /// Drive the TLS handshake to completion (or the deadline) without
    /// sending application data: flushes the ClientHello, then pumps
    /// inner-driver frames into the rustls connection until the
    /// handshake is done. Returns the negotiated ALPN protocol
    /// (tranche 15) — `None` when neither side offered one. A deadline
    /// miss is `Err(TimedOut)` (retry-grade); transport/handshake
    /// failures (verification included) are `Err` (exit-1 grade).
    pub fn complete_handshake(&mut self, deadline: Instant) -> io::Result<Option<&str>> {
        loop {
            self.flush_tls()?;
            if !self.conn.is_handshaking() {
                return Ok(self.alpn_protocol());
            }
            match self.inner.recv(deadline)? {
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "tls: handshake did not complete before the deadline",
                    ));
                }
                Some(frame) if frame.bytes.is_empty() => {
                    // Inner TCP EOF mid-handshake.
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "tls: connection closed during handshake",
                    ));
                }
                Some(frame) => {
                    self.conn.read_tls(&mut frame.bytes.as_ref())?;
                    self.conn.process_new_packets().map_err(|e| {
                        io::Error::new(io::ErrorKind::InvalidData, format!("tls: {e}"))
                    })?;
                }
            }
        }
    }

    /// Pump pending TLS records into the inner driver (bounded: the
    /// inner send is itself bounded; the cap only guards a pathological
    /// wants_write-forever loop).
    fn flush_tls(&mut self) -> io::Result<()> {
        let mut rounds = 0;
        while self.conn.wants_write() {
            rounds += 1;
            if rounds > WRITE_ROUNDS_CAP {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tls send stalled (too many pending records)",
                ));
            }
            self.conn.write_tls(&mut DriverWriter {
                driver: &mut self.inner,
            })?;
        }
        Ok(())
    }
}

/// Cap on flush rounds (see [`TlsDriver::flush_tls`]).
const WRITE_ROUNDS_CAP: u32 = 1024;

/// `io::Write` adapter: each `write` is a full, bounded `Driver::send`.
struct DriverWriter<'a> {
    driver: &'a mut TcpDriver,
}

impl io::Write for DriverWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.driver.send(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn eof_frame(peer: &str) -> Frame {
    Frame {
        bytes: Bytes::new(),
        iface: peer.to_string(),
        ts: std::time::SystemTime::now(),
    }
}

impl Driver for TlsDriver {
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        // Unbounded app-data buffering pre-handshake: one exchange per
        // connection, request-sized (the --data budget), never a stream.
        self.conn.set_buffer_limit(None);
        // Full plaintext write: `Write::write_all` semantics over the
        // buffered (possibly pre-handshake) plaintext.
        self.conn.writer().write_all(frame)?;
        // Emit whatever TLS records are ready (at minimum the
        // ClientHello); the queued plaintext follows once the peer
        // completes the handshake during `recv`.
        self.flush_tls()
    }

    fn recv(&mut self, deadline: Instant) -> io::Result<Option<Frame>> {
        let mut buf = [0u8; 16 * 1024];
        loop {
            if self.closed {
                return Ok(Some(eof_frame(&self.peer)));
            }
            // Handshake/server-side records queued for the wire first
            // (client Finished, then the buffered request).
            self.flush_tls()?;
            // Plaintext already decrypted?
            let mut reader = self.conn.reader();
            match reader.read(&mut buf) {
                Ok(0) => {
                    // Clean close_notify → the stream-EOF convention.
                    self.closed = true;
                    return Ok(Some(eof_frame(&self.peer)));
                }
                Ok(n) => {
                    return Ok(Some(Frame {
                        bytes: Bytes::copy_from_slice(&buf[..n]),
                        iface: self.peer.clone(),
                        ts: std::time::SystemTime::now(),
                    }));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // No buffered plaintext: need more TLS bytes.
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    // Inner TCP EOF without close_notify: same empty-
                    // frame convention as the plain driver (sessions
                    // read truncation as data).
                    self.closed = true;
                    return Ok(Some(eof_frame(&self.peer)));
                }
                Err(e) => return Err(e),
            }
            // Pull one TLS chunk off the inner driver before the
            // deadline and feed the rustls connection.
            match self.inner.recv(deadline)? {
                None => return Ok(None),
                Some(frame) if frame.bytes.is_empty() => {
                    // Inner orderly EOF; no close_notify (handled above
                    // via UnexpectedEof on the next pump — but reach it
                    // immediately rather than one round-trip later).
                    self.closed = true;
                    return Ok(Some(eof_frame(&self.peer)));
                }
                Some(frame) => {
                    self.conn.read_tls(&mut frame.bytes.as_ref())?;
                    self.conn.process_new_packets().map_err(|e| {
                        // TLS protocol errors (bad records, cert
                        // verification failures) are runtime failures.
                        io::Error::new(io::ErrorKind::InvalidData, format!("tls: {e}"))
                    })?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;
    use wrex_http::{HttpClientSession, HttpConfig, HttpRequestSpec};
    use wrex_test::tls_stub::{StubRequest, spawn};

    const TIMEOUT: Duration = Duration::from_secs(10);
    const RESPONSE: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nhello world";

    /// One full GET exchange through the real session runtime loop
    /// against the given stub (whose cert the verifying cfgs trust).
    fn exchange(
        stub: &wrex_test::tls_stub::TlsStub,
        cfg: &TlsConfig,
    ) -> Result<wrex_http::HttpResponse, String> {
        let spec = HttpRequestSpec::build(
            "GET",
            &format!("https://{}/", stub.addr),
            &[],
            bytes::Bytes::new(),
        )
        .map_err(|e| e.to_string())?;
        let mut driver =
            TlsDriver::connect(stub.addr, None, TIMEOUT, cfg).map_err(|e| e.to_string())?;
        let mut session = HttpClientSession::new(
            &spec,
            HttpConfig {
                timeout: TIMEOUT,
                max_bytes: 1024 * 1024,
            },
            Instant::now(),
        )
        .map_err(|e| e.to_string())?;
        let outcomes = wrex_session::run(&mut session, &mut driver, &wrex_io::SystemClock)
            .map_err(|e| format!("run: {e}"))?;
        match outcomes.into_iter().next() {
            Some(wrex_http::HttpOutcome::Response(r)) => Ok(r),
            other => Err(format!("unexpected outcome: {other:?}")),
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "TCP sockets; not Miri-safe")]
    fn insecure_get_roundtrip_and_eof() {
        let cfg = TlsConfig {
            server_name: "127.0.0.1".to_string(),
            insecure: true,
            ca_der: None,
            alpn_protocols: vec![],
        };
        let stub = spawn(RESPONSE.to_vec(), 3, 2, StubRequest::HttpHead);
        let resp = exchange(&stub, &cfg).expect("insecure exchange");
        assert_eq!(resp.status.as_u16(), 200);
        assert_eq!(&resp.body[..], b"hello world");
        assert_eq!(resp.headers.get("content-type").unwrap(), "text/plain");

        // close_notify → the empty-frame EOF convention, then sticky.
        let stub = spawn(RESPONSE.to_vec(), 1, 1, StubRequest::HttpHead);
        let mut driver = TlsDriver::connect(stub.addr, None, TIMEOUT, &cfg).expect("connect");
        driver
            .send(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .expect("send");
        let deadline = Instant::now() + TIMEOUT;
        // first frame(s): the response bytes; keep pumping until EOF
        let mut saw_eof = false;
        for _ in 0..16 {
            match driver.recv(deadline).expect("recv") {
                Some(f) if f.bytes.is_empty() => {
                    saw_eof = true;
                    break;
                }
                Some(_) => {}
                None => panic!("timed out before EOF"),
            }
        }
        assert!(saw_eof, "close_notify must arrive as an empty frame");
        // sticky EOF
        let f = driver.recv(deadline).expect("recv").expect("eof again");
        assert!(f.bytes.is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore = "TCP sockets; not Miri-safe")]
    fn ca_der_trusts_the_self_signed_cert() {
        // Verifying path with the stub's own cert as the extra root:
        // the --tls-ca contract end-to-end (system roots + additions).
        let stub = spawn(RESPONSE.to_vec(), 2, 1, StubRequest::HttpHead);
        let cfg = TlsConfig {
            server_name: "127.0.0.1".to_string(),
            insecure: false,
            ca_der: Some(vec![stub.ca_der.clone()]),
            alpn_protocols: vec![],
        };
        let resp = exchange(&stub, &cfg).expect("verifying exchange via ca_der");
        assert_eq!(resp.status.as_u16(), 200);
        assert_eq!(&resp.body[..], b"hello world");
    }

    #[test]
    #[cfg_attr(miri, ignore = "TCP sockets; not Miri-safe")]
    fn untrusted_cert_is_a_runtime_error() {
        // Verifying path with no trust for the self-signed cert: the
        // handshake failure surfaces as an io error (exit-1 grade).
        let cfg = TlsConfig {
            server_name: "127.0.0.1".to_string(),
            insecure: false,
            ca_der: None,
            alpn_protocols: vec![],
        };
        let stub = spawn(RESPONSE.to_vec(), 2, 1, StubRequest::HttpHead);
        let err = exchange(&stub, &cfg).expect_err("verification must fail");
        assert!(
            err.contains("tls:") || err.contains("run:"),
            "expected a tls runtime error, got: {err}"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "TCP sockets; not Miri-safe")]
    fn load_ca_file_reads_pem_and_der() {
        let dir = std::env::temp_dir().join("wrex-tls-test");
        std::fs::create_dir_all(&dir).unwrap();
        let stub = spawn(RESPONSE.to_vec(), 1, 1, StubRequest::HttpHead);
        // PEM: one CERTIFICATE block → one DER anchor.
        let pem = dir.join("ca.pem");
        std::fs::write(&pem, &stub.ca_pem).unwrap();
        let ders = load_ca_file(pem.to_str().unwrap()).expect("pem load");
        assert_eq!(ders.len(), 1);
        // DER: raw bytes pass through verbatim.
        let der = dir.join("ca.der");
        std::fs::write(&der, &stub.ca_der).unwrap();
        let raw = load_ca_file(der.to_str().unwrap()).expect("der load");
        assert_eq!(raw, vec![stub.ca_der.clone()]);
        // and the PEM-loaded anchor actually verifies.
        let cfg = TlsConfig {
            server_name: "127.0.0.1".to_string(),
            insecure: false,
            ca_der: Some(ders),
            alpn_protocols: vec![],
        };
        let resp = exchange(&stub, &cfg).expect("verifying exchange via --tls-ca pem");
        assert_eq!(&resp.body[..], b"hello world");
    }

    // --- tranche 15: ALPN -----------------------------------------------

    #[test]
    #[cfg_attr(miri, ignore = "TCP sockets; not Miri-safe")]
    fn alpn_negotiates_and_exposes_the_pick() {
        use wrex_test::h2_stub::{self, AlpnPick};
        // Server offers h2 only; the client offers h2 + http/1.1 → h2.
        let stub = h2_stub::spawn_h2(200, b"hello world", 1, AlpnPick::H2);
        let cfg = TlsConfig {
            server_name: "127.0.0.1".to_string(),
            insecure: true,
            ca_der: None,
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
        };
        let mut driver = TlsDriver::connect(stub.addr, None, TIMEOUT, &cfg).expect("connect");
        let negotiated = driver
            .complete_handshake(Instant::now() + TIMEOUT)
            .expect("handshake");
        assert_eq!(negotiated, Some("h2"));
        // No ALPN offered at all (the T8a shape): None either way.
        let stub = spawn(RESPONSE.to_vec(), 1, 1, StubRequest::HttpHead);
        let cfg = TlsConfig {
            server_name: "127.0.0.1".to_string(),
            insecure: true,
            ca_der: None,
            alpn_protocols: vec![],
        };
        let mut driver = TlsDriver::connect(stub.addr, None, TIMEOUT, &cfg).expect("connect");
        let negotiated = driver
            .complete_handshake(Instant::now() + TIMEOUT)
            .expect("handshake");
        assert_eq!(negotiated, None);
    }

    #[test]
    fn bad_server_name_is_a_config_error() {
        let cfg = TlsConfig {
            server_name: "not a dns name or ip \u{1}".to_string(),
            insecure: true,
            ca_der: None,
            alpn_protocols: vec![],
        };
        let stub = spawn(RESPONSE.to_vec(), 1, 1, StubRequest::HttpHead);
        let err = match TlsDriver::connect(stub.addr, None, TIMEOUT, &cfg) {
            Err(e) => e,
            Ok(_) => panic!("bad server name must not connect"),
        };
        assert!(err.to_string().contains("server name"), "{err}");
    }
}
