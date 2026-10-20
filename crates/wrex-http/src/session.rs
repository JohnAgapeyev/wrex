//! [`HttpClientSession`]: one HTTP/1.1 exchange per connection
//! (close-mode) over the frozen [`wrex_session::Session`] contract.
//!
//! The driver is a stream (the `TcpDriver` conventions): chunks in via
//! `on_frame`, **orderly EOF as an empty frame**, resets as io errors.
//! The session accumulates into one buffer and drives the parse loop
//! after every chunk: head (status + headers, 1xx skipped) → body
//! {content-length | chunked+trailers | until-close} → done.
//!
//! Determinism: the serialized request is fixed at construction, so a
//! pinned recipe replays byte-identically; `--max-bytes` bounds ALL
//! response bytes (headers included) so hostile streams cannot grow
//! the buffer without limit.

use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};

use wrex_io::Frame;
use wrex_session::{Session, SessionAction};

use crate::chunked::{ChunkHeader, parse_chunk_header};
use crate::request::HttpRequestSpec;
use crate::response::{
    HttpResponse, TrailersStep, is_informational, parse_chunk_data, parse_head, parse_trailers,
};

/// Hard cap on informational (1xx) responses before the session calls
/// the stream malformed (hostile 1xx floods must not loop forever).
const MAX_INFORMATIONALS: u32 = 8;

/// Session configuration.
#[derive(Clone, Copy, Debug)]
pub struct HttpConfig {
    /// Per-attempt exchange timeout (send + response).
    pub timeout: Duration,
    /// Response byte budget: ALL response bytes (head + body) count.
    pub max_bytes: usize,
}

/// The exchange outcome. A response — any status — is data; the other
/// variants are runtime failures the verb maps to exit 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpOutcome {
    Response(HttpResponse),
    /// Unparseable protocol bytes.
    Malformed(String),
    /// Orderly EOF before the exchange completed (fatal for
    /// length/chunked framing; success comes back as `Response` for
    /// until-close framing).
    Truncated,
    /// The `--max-bytes` budget was exceeded.
    TooLarge,
    /// The exchange deadline passed.
    Timeout,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Phase {
    /// Request not yet emitted.
    Sending,
    /// Reading status + headers.
    ReadingHead,
    /// Reading an exact-length body (bytes remaining).
    BodyLength(u64),
    /// Reading chunked data (then trailers).
    BodyChunked,
    /// Reading the trailer section (after the last chunk).
    Trailers,
    /// Reading until EOF.
    BodyUntilClose,
    Done,
}

/// The HTTP/1.1 client state machine.
pub struct HttpClientSession {
    cfg: HttpConfig,
    request: Bytes,
    now: Instant,
    deadline: Instant,
    sent: bool,
    phase: Phase,
    buf: BytesMut,
    body: BytesMut,
    /// Accumulated chunked-body bytes (budget check without cloning).
    body_len: usize,
    /// Total response bytes observed (head + body), for max_bytes.
    total_seen: usize,
    informationals: u32,
    head: Option<HttpResponse>,
    result: Option<HttpOutcome>,
}

impl HttpClientSession {
    /// Build the session and serialize the request (usage errors — bad
    /// scheme, bad headers — surface here, before any socket opens).
    pub fn new(spec: &HttpRequestSpec, cfg: HttpConfig, t0: Instant) -> Result<Self, String> {
        let request = spec.serialize()?;
        Ok(Self {
            cfg,
            request,
            now: t0,
            deadline: t0 + cfg.timeout,
            sent: false,
            phase: Phase::Sending,
            buf: BytesMut::new(),
            body: BytesMut::new(),
            body_len: 0,
            total_seen: 0,
            informationals: 0,
            head: None,
            result: None,
        })
    }

    fn finish(&mut self, outcome: HttpOutcome) {
        self.phase = Phase::Done;
        self.result = Some(outcome);
    }

    fn finish_response(&mut self) {
        let Some(head) = self.head.take() else {
            self.finish(HttpOutcome::Malformed("internal: no head".into()));
            return;
        };
        let body = std::mem::take(&mut self.body).freeze();
        self.finish(HttpOutcome::Response(HttpResponse { body, ..head }));
    }

    /// Drive the parse loop as far as the buffered bytes allow.
    fn progress(&mut self) {
        loop {
            match &self.phase {
                Phase::Sending | Phase::Done => return,
                Phase::ReadingHead => match parse_head(&self.buf) {
                    crate::response::HeadStep::NeedMore => return,
                    crate::response::HeadStep::Malformed(e) => {
                        self.finish(HttpOutcome::Malformed(e));
                        return;
                    }
                    crate::response::HeadStep::Head {
                        consumed,
                        code,
                        reason,
                        version,
                        headers,
                    } => {
                        let status = match http::StatusCode::from_u16(code) {
                            Ok(s) => s,
                            Err(_) => {
                                self.finish(HttpOutcome::Malformed(format!(
                                    "bad status code {code}"
                                )));
                                return;
                            }
                        };
                        let head = HttpResponse {
                            status,
                            reason,
                            version,
                            headers,
                            body: Bytes::new(),
                        };
                        let _ = self.buf.split_to(consumed);
                        if is_informational(code) {
                            // Skip 1xx and keep reading the real head.
                            self.informationals += 1;
                            if self.informationals > MAX_INFORMATIONALS {
                                self.finish(HttpOutcome::Malformed(
                                    "too many 1xx responses".into(),
                                ));
                                return;
                            }
                            continue;
                        }
                        self.head = Some(head);
                        // Framing decision.
                        let method = self.request_method();
                        let head = self.head.as_ref().expect("just set");
                        match head.framing(&method) {
                            crate::BodyFraming::None => {
                                self.finish_response();
                                return;
                            }
                            crate::BodyFraming::Chunked => {
                                self.phase = Phase::BodyChunked;
                                continue;
                            }
                            crate::BodyFraming::ContentLength => {
                                match head.content_length() {
                                    Some(Ok(n)) => {
                                        // Early budget check: a Content-Length
                                        // beyond the cap can never be satisfied.
                                        if n as usize > self.cfg.max_bytes {
                                            self.finish(HttpOutcome::TooLarge);
                                            return;
                                        }
                                        self.phase = Phase::BodyLength(n);
                                        continue;
                                    }
                                    Some(Err(e)) => {
                                        self.finish(HttpOutcome::Malformed(e));
                                        return;
                                    }
                                    None => unreachable!("framing said length"),
                                }
                            }
                            crate::BodyFraming::UntilClose => {
                                self.phase = Phase::BodyUntilClose;
                                return;
                            }
                        }
                    }
                },
                Phase::BodyLength(n) => {
                    let n = *n;
                    if self.buf.len() as u64 >= n {
                        let take = n as usize;
                        self.body = self.buf.split_to(take);
                        let _ = self.buf.split_to(self.buf.len()); // extra bytes ignored
                        self.finish_response();
                        return;
                    }
                    return;
                }
                Phase::BodyChunked => match parse_chunk_data(&self.buf) {
                    crate::response::ChunkStep::NeedMore => {
                        // Budget check before buffering a chunk the
                        // budget can never hold (a lying chunk size
                        // must not force unbounded buffering).
                        if let ChunkHeader::Chunk { size, .. } = parse_chunk_header(&self.buf)
                            && self.body_len.saturating_add(size as usize) > self.cfg.max_bytes
                        {
                            self.finish(HttpOutcome::TooLarge);
                        }
                        return;
                    }
                    crate::response::ChunkStep::Malformed(e) => {
                        self.finish(HttpOutcome::Malformed(e));
                        return;
                    }
                    crate::response::ChunkStep::Last { consumed } => {
                        let _ = self.buf.split_to(consumed);
                        self.phase = Phase::Trailers;
                        continue;
                    }
                    crate::response::ChunkStep::Data { consumed, size } => {
                        self.body_len += size;
                        // Copy the payload out (header + CRLF stripped).
                        self.body
                            .extend_from_slice(&self.buf[consumed - size - 2..consumed - 2]);
                        let _ = self.buf.split_to(consumed);
                        continue;
                    }
                },
                Phase::Trailers => match parse_trailers(&self.buf) {
                    TrailersStep::NeedMore => return,
                    TrailersStep::Malformed(e) => {
                        self.finish(HttpOutcome::Malformed(e));
                        return;
                    }
                    TrailersStep::Done { consumed, headers } => {
                        let _ = self.buf.split_to(consumed);
                        if let Some(head) = self.head.as_mut() {
                            for (name, value) in headers {
                                // Trailer headers merge into the map
                                // (documented); names are lowercase
                                // normalized like the head's.
                                if let (Ok(n), Ok(v)) = (
                                    http::HeaderName::from_bytes(
                                        name.to_ascii_lowercase().as_bytes(),
                                    ),
                                    http::HeaderValue::from_str(&value),
                                ) {
                                    head.headers.append(n, v);
                                }
                            }
                        }
                        self.finish_response();
                        return;
                    }
                },
                Phase::BodyUntilClose => return, // EOF converts (on_frame)
            }
        }
    }

    /// The request method is all framing needs from the request; parsed
    /// once at head time (the request line leads the serialized bytes).
    fn request_method(&self) -> http::Method {
        let line_end = self.request.iter().position(|&b| b == b' ').unwrap_or(0);
        let method = String::from_utf8_lossy(&self.request[..line_end]);
        http::Method::from_bytes(method.as_bytes()).unwrap_or(http::Method::GET)
    }
}

impl Session for HttpClientSession {
    type Output = HttpOutcome;

    fn on_frame(&mut self, frame: Frame, now: Instant) {
        self.now = now;
        if self.phase == Phase::Done {
            return; // late bytes after completion
        }
        if frame.bytes.is_empty() {
            // Orderly EOF (stream convention).
            match self.phase {
                Phase::BodyUntilClose => {
                    self.body = std::mem::take(&mut self.buf);
                    self.finish_response();
                }
                Phase::Done => {}
                _ => self.finish(HttpOutcome::Truncated),
            }
            return;
        }
        // Byte budget: every response byte counts (head + body).
        self.total_seen += frame.bytes.len();
        if self.total_seen > self.cfg.max_bytes {
            self.finish(HttpOutcome::TooLarge);
            return;
        }
        self.buf.extend_from_slice(&frame.bytes);
        self.progress();
    }

    fn on_timeout(&mut self, now: Instant) {
        self.now = now;
        if self.phase == Phase::Done {
            return;
        }
        self.finish(HttpOutcome::Timeout);
    }

    fn poll_action(&mut self) -> Option<SessionAction> {
        if self.phase == Phase::Sending {
            self.sent = true;
            self.phase = Phase::ReadingHead;
            return Some(SessionAction::Send(self.request.clone()));
        }
        None
    }

    fn next_timeout(&mut self) -> Option<Instant> {
        match self.phase {
            Phase::Done => None,
            _ => Some(self.deadline),
        }
    }

    fn poll_result(&mut self) -> Option<HttpOutcome> {
        self.result.take()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use wrex_io::{Clock as _, FakeClock, ScriptedDriver};

    const MS: Duration = Duration::from_millis(1);

    fn spec() -> HttpRequestSpec {
        HttpRequestSpec::build("GET", "http://example.com/", &[], Bytes::new()).unwrap()
    }

    fn head_spec() -> HttpRequestSpec {
        HttpRequestSpec::build("HEAD", "http://example.com/", &[], Bytes::new()).unwrap()
    }

    fn cfg() -> HttpConfig {
        HttpConfig {
            timeout: Duration::from_secs(1),
            max_bytes: 64 * 1024,
        }
    }

    fn t0() -> Instant {
        Instant::now()
    }

    fn frame(bytes: Vec<u8>) -> Frame {
        Frame {
            bytes: Bytes::from(bytes),
            iface: "tcp".into(),
            ts: std::time::SystemTime::UNIX_EPOCH,
        }
    }

    /// Drive one exchange by hand: send the request, deliver `script`
    /// chunks (an empty vec = orderly EOF per the stream convention),
    /// then fire deadlines until idle. Returns the single outcome.
    fn exchange(spec: &HttpRequestSpec, cfg: HttpConfig, script: Vec<Vec<u8>>) -> HttpOutcome {
        let mut s = HttpClientSession::new(spec, cfg, t0()).unwrap();
        while s.poll_action().is_some() {}
        let mut t = t0();
        for chunk in script {
            t += MS;
            s.on_frame(frame(chunk), t);
            while s.poll_action().is_some() {}
            if let Some(o) = s.poll_result() {
                return o;
            }
        }
        for _ in 0..10 {
            let Some(next) = s.next_timeout() else {
                break;
            };
            s.on_timeout(next);
            while s.poll_action().is_some() {}
            if let Some(o) = s.poll_result() {
                return o;
            }
        }
        match s.poll_result() {
            Some(o) => o,
            None => panic!("session produced no outcome (phase {:?})", s.phase),
        }
    }

    const SIMPLE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    const CHUNKED: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
        4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: 1\r\n\r\n";
    const UNTIL_CLOSE: &[u8] = b"HTTP/1.1 200 OK\r\n\r\nbody to the close";
    const NO_CONTENT: &[u8] = b"HTTP/1.1 204 No Content\r\n\r\n";
    const INFO_THEN_200: &[u8] =
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";

    #[test]
    fn simple_get_content_length() {
        match exchange(&spec(), cfg(), vec![SIMPLE.to_vec()]) {
            HttpOutcome::Response(r) => {
                assert_eq!(r.status, 200);
                assert_eq!(r.reason, "OK");
                assert_eq!(r.version, http::Version::HTTP_11);
                assert_eq!(&r.body[..], b"hello");
                assert_eq!(r.headers.get("content-length").unwrap(), "5");
            }
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[test]
    fn chunked_with_trailer_merges_into_headers() {
        match exchange(&spec(), cfg(), vec![CHUNKED.to_vec()]) {
            HttpOutcome::Response(r) => {
                assert_eq!(&r.body[..], b"Wikipedia");
                assert_eq!(r.headers.get("x-trailer").unwrap(), "1");
            }
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[test]
    fn until_close_eof_completes_body() {
        match exchange(&spec(), cfg(), vec![UNTIL_CLOSE.to_vec(), vec![]]) {
            HttpOutcome::Response(r) => {
                assert_eq!(r.status, 200);
                assert_eq!(&r.body[..], b"body to the close");
            }
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[test]
    fn no_body_statuses() {
        for (name, wire) in [("204", NO_CONTENT), ("404", NOT_FOUND)] {
            match exchange(&spec(), cfg(), vec![wire.to_vec()]) {
                HttpOutcome::Response(r) => {
                    assert!(r.body.is_empty(), "{name} must have no body");
                }
                other => panic!("{name}: expected a response, got {other:?}"),
            }
        }
        // HEAD: framing suppressed regardless of Content-Length.
        let head_wire = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
        match exchange(&head_spec(), cfg(), vec![head_wire.to_vec()]) {
            HttpOutcome::Response(r) => assert!(r.body.is_empty()),
            other => panic!("HEAD: expected a response, got {other:?}"),
        }
    }

    #[test]
    fn informational_skipped() {
        match exchange(&spec(), cfg(), vec![INFO_THEN_200.to_vec()]) {
            HttpOutcome::Response(r) => {
                assert_eq!(r.status, 200);
                assert_eq!(&r.body[..], b"hi");
            }
            other => panic!("expected a response, got {other:?}"),
        }
    }

    #[test]
    fn failures() {
        // truncated mid-body (Content-Length promises more than EOF delivers)
        let truncated = exchange(
            &spec(),
            cfg(),
            vec![
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfour".to_vec(),
                vec![],
            ],
        );
        assert!(matches!(truncated, HttpOutcome::Truncated), "{truncated:?}");

        // EOF mid-headers
        let eof_mid_headers = exchange(
            &spec(),
            cfg(),
            vec![b"HTTP/1.1 200 OK\r\nContent-Le".to_vec(), vec![]],
        );
        assert!(matches!(eof_mid_headers, HttpOutcome::Truncated));

        // malformed head
        let malformed = exchange(&spec(), cfg(), vec![b"utter garbage\r\n\r\n".to_vec()]);
        assert!(
            matches!(malformed, HttpOutcome::Malformed(_)),
            "{malformed:?}"
        );

        // 1xx flood
        let mut flood = Vec::new();
        for _ in 0..9 {
            flood.extend_from_slice(b"HTTP/1.1 100 Continue\r\n\r\n");
        }
        let flooded = exchange(&spec(), cfg(), vec![flood]);
        assert!(matches!(flooded, HttpOutcome::Malformed(_)), "{flooded:?}");

        // max_bytes: total response bytes (head + body) count
        let mut tiny = cfg();
        tiny.max_bytes = 8;
        assert!(matches!(
            exchange(&spec(), tiny, vec![SIMPLE.to_vec()]),
            HttpOutcome::TooLarge
        ));
        // Content-Length beyond the cap is caught before reading
        let mut mid = cfg();
        mid.max_bytes = 20;
        assert!(matches!(
            exchange(&spec(), mid, vec![SIMPLE.to_vec()]),
            HttpOutcome::TooLarge
        ));

        // timeout: nothing arrives
        assert!(matches!(
            exchange(&spec(), cfg(), vec![]),
            HttpOutcome::Timeout
        ));

        // lying chunk size beyond the cap must not force buffering
        let mut small = cfg();
        small.max_bytes = 64;
        let lie = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFF\r\n";
        assert!(matches!(
            exchange(&spec(), small, vec![lie.to_vec(), vec![]]),
            HttpOutcome::TooLarge | HttpOutcome::Truncated | HttpOutcome::Timeout
        ));
    }

    #[test]
    fn boundary_sweep_every_split_position() {
        // The parser is incremental: a response split at ANY byte
        // boundary must produce the identical outcome.
        for wire in [SIMPLE, CHUNKED, UNTIL_CLOSE, INFO_THEN_200] {
            let script = if wire.as_ptr() == UNTIL_CLOSE.as_ptr() {
                vec![wire.to_vec(), vec![]]
            } else {
                vec![wire.to_vec()]
            };
            let whole = exchange(&spec(), cfg(), script.clone());
            for i in 1..=wire.len() {
                let mut split = vec![wire[..i].to_vec(), wire[i..].to_vec()];
                if wire.as_ptr() == UNTIL_CLOSE.as_ptr() {
                    split.push(vec![]); // until-close needs the EOF
                }
                let got = exchange(&spec(), cfg(), split);
                assert_eq!(got, whole, "split at {i} diverged");
            }
        }
    }

    #[test]
    fn run_loop_end_to_end_with_scripted_driver() {
        // The real runtime loop: request reaches the "wire", chunks +
        // EOF arrive, the outcome comes back.
        let reg_clock = Arc::new(FakeClock::new());
        let t = reg_clock.now();
        let mut session = HttpClientSession::new(&spec(), cfg(), t).unwrap();
        let mut driver = ScriptedDriver::new(reg_clock.clone(), vec![SIMPLE.to_vec()]);
        let out = wrex_session::run(&mut session, &mut driver, reg_clock.as_ref()).unwrap();
        assert_eq!(out.len(), 1);
        match &out[0] {
            HttpOutcome::Response(r) => {
                assert_eq!(r.status, 200);
                assert_eq!(&r.body[..], b"hello");
            }
            other => panic!("expected a response, got {other:?}"),
        }
        // the serialized request was actually sent
        let sent = String::from_utf8(driver.sent[0].clone()).unwrap();
        assert!(sent.starts_with("GET / HTTP/1.1\r\n"));
        assert!(sent.contains("Host: example.com"));
    }
}
