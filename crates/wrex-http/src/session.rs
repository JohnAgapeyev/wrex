//! [`HttpClientSession`]: HTTP/1.1 exchanges over the frozen
//! [`wrex_session::Session`] contract.
//!
//! Two shapes share one state machine (tranche 9a):
//! - **close-mode** ([`HttpClientSession::new`], the T4 shape): one
//!   request per connection, `Connection: close` on the wire;
//! - **keep-alive** ([`HttpClientSession::with_requests`]): an ordered
//!   request queue over one connection — every request but the last
//!   carries `Connection: keep-alive`, the response's own
//!   `Connection` header (and HTTP/1.0, and until-close framing)
//!   decides whether the queue may continue, and requests that never
//!   left (or lost their transport) resolve as [`HttpOutcome::Closed`].
//!
//! The driver is a stream (the `TcpDriver` conventions): chunks in via
//! `on_frame`, **orderly EOF as an empty frame**, resets as io errors.
//! The session accumulates into one buffer and drives the parse loop
//! after every chunk: head (status + headers, 1xx skipped) → body
//! {content-length | chunked+trailers | until-close} → done, then the
//! next request or idle.
//!
//! Determinism: the serialized requests are fixed at construction, so a
//! pinned recipe queue replays byte-identically; `--max-bytes` bounds
//! ALL response bytes of an exchange (headers included) so hostile
//! streams cannot grow the buffer without limit.

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
    /// The connection ended (peer close or a failed earlier exchange)
    /// before this queued request was sent. Only keep-alive queues
    /// past the first produce it.
    Closed,
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

/// Does this completed response head allow another request on the same
/// connection? (HTTP/1.0 and an explicit `Connection: close` do not.)
fn response_keeps_alive(head: &HttpResponse) -> bool {
    if head.version == http::Version::HTTP_10 {
        return false;
    }
    match head.headers.get("connection") {
        Some(v) => {
            let v = v.to_str().unwrap_or_default().to_ascii_lowercase();
            // `close` wins when both tokens appear (RFC 9112 §9.3).
            !v.split(',').any(|t| t.trim() == "close")
        }
        // HTTP/1.1 default: persistent.
        None => true,
    }
}

/// The HTTP/1.1 client state machine: one exchange at a time over an
/// ordered request queue (a single request = close-mode).
pub struct HttpClientSession {
    now: Instant,
    /// Serialized requests + their per-exchange config, in order.
    requests: std::collections::VecDeque<(Bytes, HttpConfig)>,
    /// The active exchange's config (popped with its request).
    cur: HttpConfig,
    /// The active exchange's method (framing decisions need it).
    method: http::Method,
    deadline: Instant,
    phase: Phase,
    /// Connection unusable for the rest of the queue (peer closed, a
    /// failed exchange, or the last response landed).
    closed: bool,
    buf: BytesMut,
    body: BytesMut,
    /// Accumulated chunked-body bytes (budget check without cloning).
    body_len: usize,
    /// Total response bytes observed this exchange (head + body).
    total_seen: usize,
    informationals: u32,
    head: Option<HttpResponse>,
    results: std::collections::VecDeque<HttpOutcome>,
}

impl HttpClientSession {
    /// Build a close-mode session (one request,
    /// `Connection: close`): the T4 shape.
    pub fn new(spec: &HttpRequestSpec, cfg: HttpConfig, t0: Instant) -> Result<Self, String> {
        let request = spec.serialize()?;
        Ok(Self::from_queue(std::iter::once((request, cfg)), t0))
    }

    /// Build a keep-alive session: an ordered request queue over one
    /// connection. Every request but the last serializes with
    /// `Connection: keep-alive`; the last announces `close`.
    pub fn with_requests(
        specs: &[HttpRequestSpec],
        cfgs: &[HttpConfig],
        t0: Instant,
    ) -> Result<Self, String> {
        if specs.len() != cfgs.len() {
            return Err(format!(
                "queue mismatch: {} requests, {} configs",
                specs.len(),
                cfgs.len()
            ));
        }
        let last = specs.len().saturating_sub(1);
        let queue = specs
            .iter()
            .zip(cfgs)
            .enumerate()
            .map(|(i, (spec, cfg))| {
                let bytes = spec.serialize_connection(i < last)?;
                Ok((bytes, *cfg))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Self::from_queue(queue, t0))
    }

    fn from_queue(queue: impl IntoIterator<Item = (Bytes, HttpConfig)>, t0: Instant) -> Self {
        let requests: std::collections::VecDeque<_> = queue.into_iter().collect();
        let cur = requests.front().map(|(_, c)| *c).unwrap_or(HttpConfig {
            timeout: Duration::ZERO,
            max_bytes: 0,
        });
        let method = requests
            .front()
            .map(|(b, _)| method_of(b))
            .unwrap_or(http::Method::GET);
        let deadline = t0 + cur.timeout;
        Self {
            now: t0,
            requests,
            cur,
            method,
            deadline,
            phase: Phase::Sending,
            closed: false,
            buf: BytesMut::new(),
            body: BytesMut::new(),
            body_len: 0,
            total_seen: 0,
            informationals: 0,
            head: None,
            results: std::collections::VecDeque::new(),
        }
    }

    /// Per-exchange state for the next request on the same connection.
    fn reset_exchange(&mut self) {
        self.buf = BytesMut::new();
        self.body = BytesMut::new();
        self.body_len = 0;
        self.total_seen = 0;
        self.informationals = 0;
        self.head = None;
    }

    /// The current exchange failed terminally: record its outcome and
    /// close the queue (`Closed` per unsent request).
    fn fail_exchange(&mut self, outcome: HttpOutcome) {
        self.results.push_back(outcome);
        self.close_queue();
    }

    /// The connection is done: every still-queued request resolves
    /// `Closed`; the session goes idle after the results drain.
    fn close_queue(&mut self) {
        self.closed = true;
        for _ in 0..self.requests.len() {
            self.results.push_back(HttpOutcome::Closed);
        }
        self.requests.clear();
        self.phase = Phase::Done;
    }

    fn finish_response(&mut self) {
        let Some(head) = self.head.take() else {
            self.fail_exchange(HttpOutcome::Malformed("internal: no head".into()));
            return;
        };
        let body = std::mem::take(&mut self.body).freeze();
        let resp = HttpResponse { body, ..head };
        let reuse = !self.closed && response_keeps_alive(&resp);
        self.results.push_back(HttpOutcome::Response(resp));
        self.reset_exchange();
        if reuse && !self.requests.is_empty() {
            // Next queued request on the same connection.
            self.phase = Phase::Sending;
        } else {
            self.close_queue();
        }
    }

    /// Drive the parse loop as far as the buffered bytes allow.
    fn progress(&mut self) {
        loop {
            match &self.phase {
                Phase::Sending | Phase::Done => return,
                Phase::ReadingHead => match parse_head(&self.buf) {
                    crate::response::HeadStep::NeedMore => return,
                    crate::response::HeadStep::Malformed(e) => {
                        self.fail_exchange(HttpOutcome::Malformed(e));
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
                                self.fail_exchange(HttpOutcome::Malformed(format!(
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
                                self.fail_exchange(HttpOutcome::Malformed(
                                    "too many 1xx responses".into(),
                                ));
                                return;
                            }
                            continue;
                        }
                        self.head = Some(head);
                        // Framing decision.
                        let head = self.head.as_ref().expect("just set");
                        match head.framing(&self.method) {
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
                                        if n as usize > self.cur.max_bytes {
                                            self.fail_exchange(HttpOutcome::TooLarge);
                                            return;
                                        }
                                        self.phase = Phase::BodyLength(n);
                                        continue;
                                    }
                                    Some(Err(e)) => {
                                        self.fail_exchange(HttpOutcome::Malformed(e));
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
                            && self.body_len.saturating_add(size as usize) > self.cur.max_bytes
                        {
                            self.fail_exchange(HttpOutcome::TooLarge);
                        }
                        return;
                    }
                    crate::response::ChunkStep::Malformed(e) => {
                        self.fail_exchange(HttpOutcome::Malformed(e));
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
                        self.fail_exchange(HttpOutcome::Malformed(e));
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
}

/// The request method is all framing needs from the request; parsed
/// once per exchange from the serialized request line.
fn method_of(request: &[u8]) -> http::Method {
    let line_end = request.iter().position(|&b| b == b' ').unwrap_or(0);
    let method = String::from_utf8_lossy(&request[..line_end]);
    http::Method::from_bytes(method.as_bytes()).unwrap_or(http::Method::GET)
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
                    self.closed = true;
                    self.finish_response();
                }
                Phase::Done => {}
                Phase::Sending => {
                    // EOF between exchanges: nothing was in flight, so
                    // every still-queued request resolves Closed.
                    self.close_queue();
                }
                _ => self.fail_exchange(HttpOutcome::Truncated),
            }
            return;
        }
        // Byte budget: every response byte counts (head + body).
        self.total_seen += frame.bytes.len();
        if self.total_seen > self.cur.max_bytes {
            self.fail_exchange(HttpOutcome::TooLarge);
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
        self.fail_exchange(HttpOutcome::Timeout);
    }

    fn poll_action(&mut self) -> Option<SessionAction> {
        // Next queued request (keep-alive reuse lands here too).
        if self.phase == Phase::Sending {
            if let Some((bytes, cfg)) = self.requests.pop_front() {
                self.cur = cfg;
                self.method = method_of(&bytes);
                self.deadline = self.now + self.cur.timeout;
                self.phase = Phase::ReadingHead;
                return Some(SessionAction::Send(bytes));
            }
            // Queue empty: idle once the results drain.
            self.phase = Phase::Done;
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
        self.results.pop_front()
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

    // --- tranche 9a: keep-alive queues ------------------------------------

    fn spec_at(path: &str) -> HttpRequestSpec {
        HttpRequestSpec::build(
            "GET",
            &format!("http://example.com{path}"),
            &[],
            Bytes::new(),
        )
        .unwrap()
    }

    /// Drive a whole queue by hand: pump actions, feed `script`
    /// chunks, fire deadlines until idle. Returns every outcome in
    /// queue order.
    fn queue_outcomes(specs: &[HttpRequestSpec], script: Vec<Vec<u8>>) -> Vec<HttpOutcome> {
        let cfgs = vec![cfg(); specs.len()];
        let mut s = HttpClientSession::with_requests(specs, &cfgs, t0()).unwrap();
        let mut out = Vec::new();
        let mut t = t0();
        let mut script = script.into_iter().peekable();
        loop {
            while s.poll_action().is_some() {}
            while let Some(o) = s.poll_result() {
                out.push(o);
            }
            let Some(next) = s.next_timeout() else {
                break;
            };
            if next > t {
                t = next;
            }
            match script.next() {
                Some(chunk) => {
                    t += MS;
                    s.on_frame(frame(chunk), t);
                }
                None => s.on_timeout(t),
            }
        }
        while s.poll_action().is_some() {}
        while let Some(o) = s.poll_result() {
            out.push(o);
        }
        out
    }

    const R1: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    const R2: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nnoo";

    #[test]
    fn two_gets_ride_one_connection() {
        let specs = [spec_at("/a"), spec_at("/b")];
        let out = queue_outcomes(&specs, vec![R1.to_vec(), R2.to_vec()]);
        assert_eq!(out.len(), 2, "{out:?}");
        assert!(
            matches!(&out[0], HttpOutcome::Response(r) if r.status == 200 && &r.body[..] == b"ok")
        );
        assert!(
            matches!(&out[1], HttpOutcome::Response(r) if r.status == 404 && &r.body[..] == b"noo")
        );
    }

    #[test]
    fn keepalive_request_headers() {
        // Every request but the last announces keep-alive; the last
        // announces close.
        let specs = [spec_at("/a"), spec_at("/b"), spec_at("/c")];
        let cfgs = vec![cfg(); 3];
        let mut s = HttpClientSession::with_requests(&specs, &cfgs, t0()).unwrap();
        // Serialize-time check: drain sends up to the first (the rest
        // wait for responses), then inspect the queue tail directly.
        let mut n = 0;
        while let Some(SessionAction::Send(b)) = s.poll_action() {
            let text = String::from_utf8(b.to_vec()).unwrap();
            assert!(text.contains("Connection: keep-alive"), "{text}");
            n += 1;
            assert!(n == 1);
        }
        // The tail request (still queued) serialized with close.
        let tail = String::from_utf8(s.requests.back().unwrap().0.to_vec()).unwrap();
        assert!(tail.contains("Connection: close"), "{tail}");
    }

    #[test]
    fn connection_close_ends_the_queue() {
        // The server responds then closes: the second queued request
        // resolves Closed (it never left).
        let close = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        let specs = [spec_at("/a"), spec_at("/b")];
        let out = queue_outcomes(&specs, vec![close.to_vec(), vec![]]);
        assert_eq!(out.len(), 2, "{out:?}");
        assert!(matches!(out[0], HttpOutcome::Response(_)));
        assert!(matches!(out[1], HttpOutcome::Closed), "{out:?}");
    }

    #[test]
    fn until_close_ends_the_queue() {
        // No framing declared: the body reads to EOF, which consumes
        // the connection — the queued request resolves Closed.
        let specs = [spec_at("/a"), spec_at("/b")];
        let out = queue_outcomes(
            &specs,
            vec![b"HTTP/1.1 200 OK\r\n\r\nbody".to_vec(), vec![]],
        );
        assert_eq!(out.len(), 2);
        assert!(matches!(out[1], HttpOutcome::Closed), "{out:?}");
    }

    #[test]
    fn eof_mid_queue_is_truncated() {
        // The runtime always drains sends before reads, so an EOF after
        // response 1 arrives while request 2 is in flight: Truncated.
        // (`Closed` is for requests that never left the queue — a
        // `Connection: close` response or a failed exchange.)
        let specs = [spec_at("/a"), spec_at("/b")];
        let out = queue_outcomes(&specs, vec![R1.to_vec(), vec![]]);
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0], HttpOutcome::Response(_)));
        assert!(matches!(out[1], HttpOutcome::Truncated), "{out:?}");
    }

    #[test]
    fn timeout_fails_the_exchange_and_closes_the_queue() {
        let specs = [spec_at("/a"), spec_at("/b")];
        let out = queue_outcomes(&specs, vec![R1.to_vec()]);
        // After R1 completes, request 2 is in flight; the script runs
        // dry, so its deadline fires: Timeout, then nothing left.
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0], HttpOutcome::Response(_)));
        assert!(matches!(out[1], HttpOutcome::Timeout), "{out:?}");
    }

    #[test]
    fn queue_boundary_sweep_every_split_position() {
        // Both responses split at every boundary must produce the
        // identical outcome pair.
        let specs = [spec_at("/a"), spec_at("/b")];
        let whole = queue_outcomes(&specs, vec![R1.to_vec(), R2.to_vec()]);
        for i in 1..R1.len() {
            let got = queue_outcomes(
                &specs,
                vec![R1[..i].to_vec(), R1[i..].to_vec(), R2.to_vec()],
            );
            assert_eq!(got, whole, "split r1 at {i} diverged");
        }
        for i in 1..R2.len() {
            let got = queue_outcomes(
                &specs,
                vec![R1.to_vec(), R2[..i].to_vec(), R2[i..].to_vec()],
            );
            assert_eq!(got, whole, "split r2 at {i} diverged");
        }
    }

    #[test]
    fn run_loop_drains_a_whole_queue() {
        // The shared runtime loop over a keep-alive queue.
        let reg_clock = Arc::new(FakeClock::new());
        let t = reg_clock.now();
        let specs = [spec_at("/a"), spec_at("/b")];
        let cfgs = vec![cfg(); 2];
        let mut session = HttpClientSession::with_requests(&specs, &cfgs, t).unwrap();
        let mut driver = ScriptedDriver::new(reg_clock.clone(), vec![R1.to_vec(), R2.to_vec()]);
        let out = wrex_session::run(&mut session, &mut driver, reg_clock.as_ref()).unwrap();
        assert_eq!(out.len(), 2);
        assert!(matches!(&out[0], HttpOutcome::Response(r) if r.status == 200));
        assert!(matches!(&out[1], HttpOutcome::Response(r) if r.status == 404));
        // both requests rode the same connection, keep-alive then close
        let sent: Vec<String> = driver
            .sent
            .iter()
            .map(|b| String::from_utf8(b.clone()).unwrap())
            .collect();
        assert_eq!(sent.len(), 2);
        assert!(sent[0].contains("Connection: keep-alive"), "{:?}", sent[0]);
        assert!(sent[1].contains("Connection: close"), "{:?}", sent[1]);
    }
}
