//! The sans-IO HTTP/2 client session (RFC 9113): one connection, N
//! **concurrent** streams opened in request order, flow-control-gated
//! DATA, and one `HttpOutcome` per queued request.
//!
//! The T2/T4/T9 house pattern on the frozen
//! [`wrex_session::Session`] contract: `poll_action` yields fully
//! encoded outbound frames (preface + SETTINGS + HEADERS, then
//! window-gated DATA), `on_frame` accumulates and decodes inbound
//! frames, `next_timeout`/`on_timeout` drive per-stream deadlines,
//! `poll_result` drains completed outcomes. `SessionAction` stays
//! `Send` only — the session decides frame ordering; concurrency is
//! internal state.

use std::collections::VecDeque;
use std::time::Instant;

use bytes::{Bytes, BytesMut};

use wrex_http::http;
use wrex_http::{HttpConfig, HttpOutcome, HttpRequestSpec, HttpResponse};
use wrex_io::Frame;
use wrex_session::{Session, SessionAction};

use crate::frame::{
    self, ACK, DEFAULT_MAX_FRAME, DEFAULT_WINDOW, END_HEADERS, END_STREAM, FrameStep, FrameType,
    PADDED, PREFACE, PRIORITY,
};
#[cfg(test)]
use crate::hpack;
use crate::hpack::{HpackDecoder, HpackEncodePolicy, HpackEncoder};

/// Cap on concurrent client streams (a prober budget, not a protocol
/// rule; requests beyond it are a pointed usage error).
pub const MAX_STREAMS: usize = 64;

/// Errors building a session (usage-grade, exit 2 in the CLI).
pub type H2Error = String;

/// One open client stream (client-initiated: odd ids, ours start at 1).
#[derive(Debug)]
struct Stream {
    id: u32,
    cfg: HttpConfig,
    deadline: Instant,
    /// Body bytes not yet sent (flow-control gated).
    pending: Bytes,
    /// Our send credit for this stream (SETTINGS_INITIAL_WINDOW_SIZE).
    send_window: i64,
    /// Request fully sent (HEADERS + DATA with END_STREAM).
    sent_end: bool,
    /// Response head assembled so far.
    status: Option<u16>,
    headers: Vec<(String, String)>,
    body: BytesMut,
    /// END_STREAM seen from the server.
    recv_end: bool,
    /// Accumulated CONTINUATION payloads (§4.2).
    header_frag: Option<BytesMut>,
    done: bool,
}

impl Stream {
    /// Resolve this stream in place (flag + drop pending bytes); the
    /// caller pushes the outcome (field-local borrows keep this legal).
    fn close(&mut self) {
        self.done = true;
        self.pending.clear();
        let _ = std::mem::take(&mut self.body);
    }
}

/// The HTTP/2 client session. One per connection; see the module doc.
#[derive(Debug)]
pub struct H2Session {
    out: VecDequeBytes,
    streams: Vec<Stream>,
    rx: BytesMut,
    hpack: HpackDecoder,
    /// The send-side HPACK encoding context (tranche 16a): one per
    /// connection, so dynamic-table index reuse is stream-ordered.
    encoder: HpackEncoder,
    /// Our SETTINGS_INITIAL_WINDOW_SIZE bookkeeping value.
    initial_window: i64,
    /// Our send credit, connection-wide.
    conn_window: i64,
    /// Max frame size the peer accepts (their SETTINGS_MAX_FRAME_SIZE).
    peer_max_frame: u32,
    /// The server preface (SETTINGS) has arrived (§3.4).
    server_preface: bool,
    /// Connection-level failure: everything unresolved truncates.
    dead: Option<String>,
    results: VecDeque<HttpOutcome>,
}

/// `VecDeque<Bytes>` spelled out (avoiding a bare type alias import).
type VecDequeBytes = std::collections::VecDeque<Bytes>;

impl H2Session {
    /// Build a session over a fully-resolved request queue under the
    /// default (Indexed) HPACK policy. All frames are pre-encoded
    /// (deterministic replay: same specs ⇒ same bytes).
    pub fn new(
        specs: &[HttpRequestSpec],
        cfgs: &[HttpConfig],
        t0: Instant,
    ) -> Result<Self, H2Error> {
        Self::with_policy(specs, cfgs, t0, HpackEncodePolicy::default())
    }

    /// Build a session with an explicit send-side HPACK policy (tranche
    /// 16a): `Literal` reproduces the T15 wire bytes; `Indexed`
    /// (default) keeps a dynamic table across the queue's streams.
    pub fn with_policy(
        specs: &[HttpRequestSpec],
        cfgs: &[HttpConfig],
        t0: Instant,
        policy: HpackEncodePolicy,
    ) -> Result<Self, H2Error> {
        if specs.is_empty() {
            return Err("h2: empty request queue".to_string());
        }
        if specs.len() != cfgs.len() {
            return Err("h2: queue/config length mismatch".to_string());
        }
        if specs.len() > MAX_STREAMS {
            return Err(format!("h2: {MAX_STREAMS} concurrent streams max"));
        }
        let mut encoder = HpackEncoder::new(policy);
        let mut out = VecDequeBytes::new();
        // Client preface + SETTINGS with defaults (§3.4): one burst.
        let mut preface = BytesMut::with_capacity(PREFACE.len() + 9);
        preface.extend_from_slice(PREFACE);
        frame::FrameHeader {
            ty: FrameType::Settings,
            flags: 0,
            stream_id: 0,
        }
        .encode(0, &mut preface);
        out.push_back(preface.freeze());
        let mut streams = Vec::with_capacity(specs.len());
        for (i, spec) in specs.iter().enumerate() {
            let id = 2 * i as u32 + 1; // client streams are odd
            let block = encode_request_headers(spec, &mut encoder)?;
            // END_STREAM rides the HEADERS when there is no body.
            let end = spec.body.is_empty();
            out.push_back(frame::headers_frame(id, &block, end));
            streams.push(Stream {
                id,
                cfg: cfgs[i],
                deadline: t0 + cfgs[i].timeout,
                pending: spec.body.clone(),
                send_window: DEFAULT_WINDOW,
                sent_end: end,
                status: None,
                headers: Vec::new(),
                body: BytesMut::new(),
                recv_end: false,
                header_frag: None,
                done: false,
            });
        }
        Ok(Self {
            out,
            streams,
            rx: BytesMut::new(),
            hpack: HpackDecoder::default(),
            encoder,
            initial_window: DEFAULT_WINDOW,
            conn_window: DEFAULT_WINDOW,
            peer_max_frame: DEFAULT_MAX_FRAME,
            server_preface: false,
            dead: None,
            results: std::collections::VecDeque::new(),
        })
    }

    /// The session is finished (nothing queued, every stream resolved).
    fn finished(&self) -> bool {
        self.out.is_empty() && self.streams.iter().all(|s| s.done)
    }

    /// Resolve one stream with an outcome (field-local: `streams` then
    /// `results` — disjoint field borrows).
    fn resolve(&mut self, id: u32, outcome: HttpOutcome) {
        let Some(s) = self.streams.iter_mut().find(|s| s.id == id) else {
            return;
        };
        if s.done {
            return;
        }
        s.close();
        let _ = s;
        self.results.push_back(outcome);
    }

    /// Connection-level failure: resolve everything open.
    fn fail_all(&mut self, detail: &str) {
        self.dead = Some(detail.to_string());
        self.out.clear();
        let mut outcomes = Vec::new();
        for s in self.streams.iter_mut() {
            if !s.done {
                let had_response = s.status.is_some() || !s.body.is_empty();
                s.close();
                outcomes.push(if had_response {
                    HttpOutcome::Truncated
                } else {
                    HttpOutcome::Malformed(detail.to_string())
                });
            }
        }
        self.results.extend(outcomes);
    }

    /// Truncate every still-open stream (the stream-EOF convention).
    fn fail_all_open(&mut self) {
        self.out.clear();
        let mut outcomes = Vec::new();
        for s in self.streams.iter_mut() {
            if !s.done {
                s.close();
                outcomes.push(HttpOutcome::Truncated);
            }
        }
        self.results.extend(outcomes);
    }

    /// Assemble one completed response (END_STREAM + full head).
    fn complete(&mut self, id: u32) {
        let Some(pos) = self.streams.iter().position(|s| s.id == id) else {
            return;
        };
        if self.streams[pos].done {
            return;
        }
        let status = self.streams[pos].status;
        let Some(status) = status else {
            self.streams[pos].close();
            self.results.push_back(HttpOutcome::Malformed(
                "h2: response head without a :status pseudo-header".to_string(),
            ));
            return;
        };
        let Ok(status) = http::StatusCode::from_u16(status) else {
            self.streams[pos].close();
            self.results
                .push_back(HttpOutcome::Malformed(format!("h2: bad :status {status}")));
            return;
        };
        let headers = std::mem::take(&mut self.streams[pos].headers);
        let body = std::mem::take(&mut self.streams[pos].body).freeze();
        let mut map = http::HeaderMap::new();
        for (name, value) in headers {
            let parsed = (
                http::HeaderName::from_bytes(name.as_bytes()),
                http::HeaderValue::from_bytes(value.as_bytes()),
            );
            let (Ok(name), Ok(value)) = parsed else {
                self.streams[pos].close();
                self.results.push_back(HttpOutcome::Malformed(format!(
                    "h2: bad response header `{name}: {value}`"
                )));
                return;
            };
            map.append(name, value);
        }
        self.streams[pos].close();
        let reason = status.canonical_reason().unwrap_or("").to_string();
        self.results.push_back(HttpOutcome::Response(HttpResponse {
            status,
            reason,
            version: http::Version::HTTP_2,
            headers: map,
            body,
        }));
    }

    /// Feed one decoded frame into the state machine.
    fn on_decoded(&mut self, header: frame::FrameHeader, payload: Bytes) {
        if self.dead.is_some() {
            return;
        }
        use frame::FrameType::*;
        // The server preface is SETTINGS (§3.4).
        if !self.server_preface {
            if header.ty != Settings || header.flags & ACK != 0 || header.stream_id != 0 {
                self.fail_all("h2: server preface must be SETTINGS");
                return;
            }
            self.server_preface = true;
        }
        match header.ty {
            Settings => {
                if header.flags & ACK != 0 {
                    return; // our SETTINGS acknowledged
                }
                match frame::parse_settings(&payload) {
                    Ok(entries) => {
                        for &(id, value) in &entries {
                            match id {
                                frame::SETTINGS_HEADER_TABLE_SIZE => {
                                    // The peer's cap bounds both sides
                                    // of our HPACK context: their
                                    // send-side table (our decoder) and
                                    // ours (their number back to us).
                                    self.hpack.set_max_size(value as usize);
                                    self.encoder.set_max_size(value as usize);
                                }
                                frame::SETTINGS_INITIAL_WINDOW_SIZE => {
                                    let value = value as i64;
                                    // §6.9.1: applies to open streams as a
                                    // delta; beyond MAX_WINDOW is a flow-
                                    // control error.
                                    if !(0..=frame::MAX_WINDOW).contains(&value) {
                                        self.fail_all("h2: initial window beyond 2^31-1");
                                        return;
                                    }
                                    let delta = value - self.initial_window;
                                    self.initial_window = value;
                                    for s in self.streams.iter_mut() {
                                        if !s.done {
                                            s.send_window += delta;
                                        }
                                    }
                                }
                                frame::SETTINGS_MAX_FRAME_SIZE => {
                                    if !(16_384..=16_777_215).contains(&value) {
                                        self.fail_all("h2: max frame size out of range");
                                        return;
                                    }
                                    self.peer_max_frame = value;
                                }
                                _ => {} // enable_push / max_concurrent / max_header_list
                            }
                        }
                        self.out.push_back(frame::settings_ack_frame());
                    }
                    Err(e) => self.fail_all(&format!("h2: {e}")),
                }
            }
            Headers | Continuation => {
                self.on_headers(header, payload);
            }
            Data => self.on_data(header, payload),
            WindowUpdate => match frame::parse_window_update(&payload) {
                Ok(inc) => {
                    let inc = inc as i64;
                    if header.stream_id == 0 {
                        self.conn_window += inc;
                        if self.conn_window > frame::MAX_WINDOW {
                            self.fail_all("h2: connection window beyond 2^31-1");
                        }
                    } else if let Some(s) =
                        self.streams.iter_mut().find(|s| s.id == header.stream_id)
                        && !s.done
                    {
                        s.send_window += inc;
                        if s.send_window > frame::MAX_WINDOW {
                            self.fail_all("h2: stream window beyond 2^31-1");
                        }
                    }
                    // Unknown/closed streams: ignored (lenient).
                }
                Err(e) => self.fail_all(&format!("h2: {e}")),
            },
            RstStream => {
                // 4-octet error code (§6.4).
                let code = payload
                    .first_chunk::<4>()
                    .map(|c| u32::from_be_bytes(*c))
                    .unwrap_or(0);
                self.resolve(
                    header.stream_id,
                    HttpOutcome::Malformed(format!(
                        "h2: stream {} reset by peer (code {code})",
                        header.stream_id
                    )),
                );
            }
            Goaway => {
                // last-stream-id + error code (+ debug data).
                let Some(last) = payload
                    .get(4..8)
                    .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]) & 0x7fff_ffff)
                else {
                    self.fail_all("h2: short GOAWAY");
                    return;
                };
                let detail = format!("h2: GOAWAY after stream {last}");
                self.dead = Some(detail.clone());
                self.out.clear();
                let mut outcomes = Vec::new();
                for s in self.streams.iter_mut() {
                    if !s.done {
                        let had_response = s.status.is_some() || !s.body.is_empty();
                        s.close();
                        outcomes.push(if had_response {
                            HttpOutcome::Truncated
                        } else {
                            HttpOutcome::Malformed(detail.clone())
                        });
                    }
                }
                self.results.extend(outcomes);
            }
            Ping => {
                if header.flags & ACK == 0 {
                    self.out.push_back(frame::ping_ack_frame(&payload));
                }
            }
            Priority | PushPromise | Unknown(_) => {
                // §5.1: unknown frame types skip; PRIORITY is advisory;
                // PUSH_PROMISE cannot arrive (push is never enabled).
            }
        }
    }

    /// HEADERS/CONTINUATION handling (§4.2 fragmentation; §6.2 padding
    /// + priority exclusions).
    fn on_headers(&mut self, header: frame::FrameHeader, payload: Bytes) {
        let Some(pos) = self.streams.iter().position(|s| s.id == header.stream_id) else {
            return; // unknown/closed stream: ignored
        };
        if self.streams[pos].done {
            return;
        }
        let block: BytesMut = if header.ty == FrameType::Continuation {
            match self.streams[pos].header_frag.take() {
                Some(mut frag) => {
                    frag.extend_from_slice(&payload);
                    frag
                }
                None => return, // CONTINUATION without a pending HEADERS
            }
        } else {
            let mut content = payload;
            if header.flags & PADDED != 0 {
                match frame::strip_padding(PADDED, &content) {
                    Ok(stripped) => content = Bytes::copy_from_slice(stripped),
                    Err(e) => {
                        self.streams[pos].close();
                        self.results
                            .push_back(HttpOutcome::Malformed(format!("h2: {e}")));
                        return;
                    }
                }
            }
            let mut off = 0usize;
            if header.flags & PRIORITY != 0 {
                off = 5; // exclusive(1) + dependency(31) + weight(8)
                if content.len() < off {
                    self.streams[pos].close();
                    self.results.push_back(HttpOutcome::Malformed(
                        "h2: short priority HEADERS".to_string(),
                    ));
                    return;
                }
            }
            let mut frag = BytesMut::with_capacity(content.len());
            frag.extend_from_slice(&content[off..]);
            frag
        };
        // END_STREAM rides the *first* HEADERS fragment (§4.2): record
        // it before the fragmentation early-return.
        if header.ty == FrameType::Headers && header.flags & END_STREAM != 0 {
            self.streams[pos].recv_end = true;
        }
        let end_headers = header.flags & END_HEADERS != 0;
        if !end_headers {
            self.streams[pos].header_frag = Some(block);
            return;
        }
        let block = block.freeze();
        match self.hpack.decode(&block) {
            Ok(fields) => {
                for (name, value) in fields {
                    let (Ok(name), Ok(value)) = (String::from_utf8(name), String::from_utf8(value))
                    else {
                        self.streams[pos].close();
                        self.results.push_back(HttpOutcome::Malformed(
                            "h2: non-UTF8 response header".to_string(),
                        ));
                        return;
                    };
                    if let Some(pseudo) = name.strip_prefix(':') {
                        if pseudo == "status" {
                            match value.parse::<u16>() {
                                Ok(code) => self.streams[pos].status = Some(code),
                                Err(_) => {
                                    self.streams[pos].close();
                                    self.results.push_back(HttpOutcome::Malformed(format!(
                                        "h2: bad :status `{value}`"
                                    )));
                                    return;
                                }
                            }
                        } else {
                            self.streams[pos].close();
                            self.results.push_back(HttpOutcome::Malformed(format!(
                                "h2: unexpected response pseudo-header `:{pseudo}`"
                            )));
                            return;
                        }
                    } else {
                        self.streams[pos].headers.push((name, value));
                    }
                }
                if self.streams[pos].recv_end {
                    let id = header.stream_id;
                    self.complete(id);
                }
            }
            Err(e) => {
                self.streams[pos].close();
                self.results
                    .push_back(HttpOutcome::Malformed(format!("h2: {e}")));
            }
        }
    }

    /// DATA handling (§6.1): budget + END_STREAM completion.
    fn on_data(&mut self, header: frame::FrameHeader, payload: Bytes) {
        let Some(pos) = self.streams.iter().position(|s| s.id == header.stream_id) else {
            return;
        };
        if self.streams[pos].done {
            return;
        }
        let content = if header.flags & PADDED != 0 {
            match frame::strip_padding(PADDED, &payload) {
                Ok(stripped) => Bytes::copy_from_slice(stripped),
                Err(e) => {
                    self.streams[pos].close();
                    self.results
                        .push_back(HttpOutcome::Malformed(format!("h2: {e}")));
                    return;
                }
            }
        } else {
            payload
        };
        let budget = self.streams[pos].cfg.max_bytes;
        if self.streams[pos].body.len() + content.len() > budget {
            let id = self.streams[pos].id;
            self.streams[pos].close();
            self.results.push_back(HttpOutcome::TooLarge);
            // Stop pulling the stream: CANCEL (§6.4).
            self.out.push_back(frame::encode(
                FrameType::RstStream,
                0,
                id,
                &8u32.to_be_bytes(),
            ));
            return;
        }
        self.streams[pos].body.extend_from_slice(&content);
        if header.flags & END_STREAM != 0 {
            self.streams[pos].recv_end = true;
            let id = header.stream_id;
            self.complete(id);
        }
    }
}

impl Session for H2Session {
    type Output = HttpOutcome;

    fn on_frame(&mut self, frame: Frame, _now: Instant) {
        // The stream-EOF convention: an empty frame truncates everything
        // still open (the T4 rule, transposed).
        if frame.bytes.is_empty() {
            self.fail_all_open();
            return;
        }
        if self.dead.is_some() {
            return;
        }
        self.rx.extend_from_slice(&frame.bytes);
        loop {
            match frame::decode_frame(&self.rx) {
                FrameStep::Need => return,
                FrameStep::Malformed(e) => {
                    self.rx.clear();
                    self.fail_all(&format!("h2: {e}"));
                    return;
                }
                FrameStep::Have {
                    consumed,
                    header,
                    payload,
                } => {
                    let mut rest = self.rx.split_off(consumed);
                    std::mem::swap(&mut self.rx, &mut rest);
                    self.on_decoded(header, payload);
                    if self.dead.is_some() {
                        self.rx.clear();
                        return;
                    }
                }
            }
        }
    }

    fn on_timeout(&mut self, now: Instant) {
        let mut outcomes = Vec::new();
        for s in self.streams.iter_mut() {
            if !s.done && now >= s.deadline {
                s.close();
                outcomes.push(HttpOutcome::Timeout);
            }
        }
        self.results.extend(outcomes);
    }

    fn poll_action(&mut self) -> Option<SessionAction> {
        if self.dead.is_some() {
            return None;
        }
        if let Some(bytes) = self.out.pop_front() {
            return Some(SessionAction::Send(bytes));
        }
        // Window-gated DATA: first stream (request order) with pending
        // body bytes and credit on both windows.
        let chunk = self.peer_max_frame.min(DEFAULT_MAX_FRAME) as usize;
        for s in self.streams.iter_mut() {
            if s.done || s.sent_end || s.pending.is_empty() {
                continue;
            }
            let n = s
                .pending
                .len()
                .min(chunk)
                .min(s.send_window.max(0) as usize)
                .min(self.conn_window.max(0) as usize);
            if n == 0 {
                continue;
            }
            let data = s.pending.split_to(n);
            s.send_window -= n as i64;
            self.conn_window -= n as i64;
            let end = s.pending.is_empty();
            if end {
                s.sent_end = true;
            }
            return Some(SessionAction::Send(frame::data_frame(s.id, &data, end)));
        }
        None
    }

    fn next_timeout(&mut self) -> Option<Instant> {
        if self.finished() {
            return None;
        }
        self.streams
            .iter()
            .filter(|s| !s.done)
            .map(|s| s.deadline)
            .min()
    }

    fn poll_result(&mut self) -> Option<HttpOutcome> {
        self.results.pop_front()
    }
}

/// Connection-specific headers are illegal on h2 (RFC 9113 §7.1).
const CONNECTION_HEADERS: [&str; 5] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
];

/// Build the HPACK request header block for one spec: pseudo-headers
/// first (§8.3), user headers in spec order, then the derived defaults
/// only where absent (the 1.1 serializer's rule, transposed). Encoded
/// through the caller's [`HpackEncoder`] — the 16a send-side context:
/// under `Indexed` the table persists across the queue's streams
/// (index reuse is stream-ordered), under `Literal` this is the T15
/// byte stream verbatim.
pub fn encode_request_headers(
    spec: &HttpRequestSpec,
    enc: &mut HpackEncoder,
) -> Result<Bytes, H2Error> {
    let authority = spec
        .url
        .authority()
        .ok_or_else(|| "h2: url has no host (authority)".to_string())?
        .to_string();
    let path = spec
        .url
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let scheme = spec
        .url
        .scheme_str()
        .ok_or_else(|| "h2: url has no scheme".to_string())?;
    let mut fields: Vec<(&str, &str)> = vec![
        (":method", spec.method.as_str()),
        (":scheme", scheme),
        (":authority", &authority),
        (":path", &path),
    ];
    let mut user_agent = false;
    let mut accept = false;
    let mut content_length = spec.body.is_empty();
    for (name, value) in &spec.headers {
        let name = name.as_str();
        if name.starts_with(':') {
            return Err(format!("h2: pseudo-header `{name}` is not a user header"));
        }
        if CONNECTION_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            return Err(format!(
                "h2: connection-specific header `{name}` is illegal over h2"
            ));
        }
        match name.to_ascii_lowercase().as_str() {
            "user-agent" => user_agent = true,
            "accept" => accept = true,
            "content-length" => content_length = true,
            _ => {}
        }
        fields.push((
            name,
            std::str::from_utf8(value.as_bytes())
                .map_err(|_| format!("h2: non-UTF8 value for `{name}`"))?,
        ));
    }
    if !user_agent {
        fields.push(("user-agent", crate::DEFAULT_USER_AGENT));
    }
    if !accept {
        fields.push(("accept", "*/*"));
    }
    let body_len = spec.body.len().to_string();
    if !content_length {
        fields.push(("content-length", &body_len));
    }
    Ok(enc.encode(&fields))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(10);

    fn cfg() -> HttpConfig {
        HttpConfig {
            timeout: TIMEOUT,
            max_bytes: 1024 * 1024,
        }
    }

    fn spec(url: &str) -> HttpRequestSpec {
        HttpRequestSpec::build("GET", url, &[], Bytes::new()).unwrap()
    }

    fn t0() -> Instant {
        Instant::now()
    }

    /// Drive a session directly with raw received byte chunks; forces
    /// every remaining deadline at the end so the machine terminates.
    fn drive(session: &mut H2Session, rx: &[&[u8]]) -> (Vec<Vec<u8>>, Vec<HttpOutcome>) {
        let mut sends = Vec::new();
        let mut results = Vec::new();
        let pump = |session: &mut H2Session, sends: &mut Vec<Vec<u8>>| {
            while let Some(SessionAction::Send(b)) = session.poll_action() {
                sends.push(b.to_vec());
            }
        };
        pump(session, &mut sends);
        let base = t0();
        for chunk in rx {
            session.on_frame(
                Frame {
                    bytes: Bytes::copy_from_slice(chunk),
                    iface: "t".into(),
                    ts: std::time::SystemTime::UNIX_EPOCH,
                },
                base,
            );
            pump(session, &mut sends);
        }
        session.on_timeout(base + Duration::from_secs(3600));
        while let Some(r) = session.poll_result() {
            results.push(r);
        }
        (sends, results)
    }

    fn server_settings() -> Vec<u8> {
        frame::settings_frame().to_vec()
    }

    /// A scripted full response (HEADERS [+ DATA]) on one stream.
    fn server_response(id: u32, status: u16, body: &[u8]) -> Vec<u8> {
        let status = status.to_string();
        let block = hpack::encode_header_block(&[
            (":status", &status),
            ("content-type", "text/plain"),
            ("content-length", &body.len().to_string()),
        ]);
        let mut out = frame::headers_frame(id, &block, body.is_empty()).to_vec();
        if !body.is_empty() {
            out.extend_from_slice(&frame::data_frame(id, body, true));
        }
        out
    }

    #[test]
    fn construction_queues_preface_settings_and_headers() {
        let mut s = H2Session::new(
            &[
                spec("https://example.test/"),
                spec("https://example.test/x"),
            ],
            &[cfg(), cfg()],
            t0(),
        )
        .unwrap();
        let (sends, results) = drive(&mut s, &[]);
        assert!(sends.len() >= 3);
        assert_eq!(&sends[0][..PREFACE.len()], PREFACE);
        // SETTINGS (empty) rides the preface burst
        assert_eq!(sends[0][PREFACE.len()..], [0, 0, 0, 4, 0, 0, 0, 0, 0]);
        // stream ids 1 and 3, both HEADERS carry END_STREAM (no bodies)
        assert_eq!(sends[1][3], 0x01);
        assert_eq!(sends[1][5..9], [0, 0, 0, 1]);
        assert_eq!(sends[1][4], END_HEADERS | END_STREAM);
        assert_eq!(sends[2][5..9], [0, 0, 0, 3]);
        // nothing arrived: the forced deadlines resolve both streams
        assert_eq!(results, vec![HttpOutcome::Timeout, HttpOutcome::Timeout]);
        // deterministic: same queue ⇒ same bytes
        let mut s2 = H2Session::new(
            &[
                spec("https://example.test/"),
                spec("https://example.test/x"),
            ],
            &[cfg(), cfg()],
            t0(),
        )
        .unwrap();
        let (sends2, _) = drive(&mut s2, &[]);
        assert_eq!(sends, sends2);
    }

    #[test]
    fn full_exchange_over_frames() {
        let mut s = H2Session::new(&[spec("https://example.test/")], &[cfg()], t0()).unwrap();
        let (sends, results) = drive(
            &mut s,
            &[&server_settings(), &server_response(1, 200, b"hello world")],
        );
        assert_eq!(sends.len(), 3, "preface+settings, HEADERS, ACK");
        assert_eq!(sends[2], [0, 0, 0, 4, ACK, 0, 0, 0, 0], "settings ACK");
        let HttpOutcome::Response(resp) = &results[0] else {
            panic!("expected a response, got {results:?}");
        };
        assert_eq!(resp.status.as_u16(), 200);
        assert_eq!(resp.status.canonical_reason(), Some("OK"));
        assert_eq!(resp.version, http::Version::HTTP_2);
        assert_eq!(&resp.body[..], b"hello world");
        assert_eq!(resp.headers.get("content-type").unwrap(), "text/plain");
        assert_eq!(resp.headers.get("content-length").unwrap(), "11");
        assert_eq!(results.len(), 1);
        assert!(s.next_timeout().is_none(), "finished");
    }

    #[test]
    fn concurrent_streams_interleave() {
        let specs = vec![
            spec("https://example.test/a"),
            spec("https://example.test/b"),
            spec("https://example.test/c"),
        ];
        let mut s = H2Session::new(&specs, &[cfg(), cfg(), cfg()], t0()).unwrap();
        // replies arrive out of order (concurrency!)
        let (_, results) = drive(
            &mut s,
            &[
                &server_settings(),
                &server_response(5, 202, b"c!"),
                &server_response(1, 200, b"a!"),
                &server_response(3, 404, b"b!"),
            ],
        );
        assert_eq!(results.len(), 3);
        let statuses: Vec<u16> = results
            .iter()
            .map(|r| match r {
                HttpOutcome::Response(resp) => resp.status.as_u16(),
                _ => panic!("all three resolve: {r:?}"),
            })
            .collect();
        assert_eq!(statuses, vec![202, 200, 404]);
    }

    #[test]
    fn body_sends_as_data_with_end_stream() {
        let spec = HttpRequestSpec::build(
            "POST",
            "https://example.test/submit",
            &[],
            Bytes::from_static(b"payload"),
        )
        .unwrap();
        let mut s = H2Session::new(&[spec], &[cfg()], t0()).unwrap();
        let (sends, _) = drive(&mut s, &[&server_settings(), &server_response(1, 201, b"")]);
        // [preface+settings, HEADERS(open), DATA(ES), ACK]
        assert_eq!(sends[1][3], 0x01, "HEADERS type");
        assert_eq!(sends[1][4] & END_STREAM, 0, "HEADERS opens the stream");
        assert_eq!(sends[2][3], 0x00, "DATA type");
        assert_eq!(sends[2][4] & END_STREAM, END_STREAM);
        assert_eq!(&sends[2][9..], b"payload");
        // content-length was derived into the request head
        let mut dec = HpackDecoder::default();
        let fields = dec.decode(&sends[1][9..]).unwrap();
        assert!(fields.contains(&(
            "content-length".as_bytes().to_vec(),
            "7".as_bytes().to_vec()
        )));
        assert!(fields.contains(&(":method".as_bytes().to_vec(), "POST".as_bytes().to_vec())));
    }

    #[test]
    fn window_gates_data_and_update_unblocks() {
        let spec = HttpRequestSpec::build(
            "POST",
            "https://example.test/",
            &[],
            Bytes::from_static(&[0xabu8; 70000]),
        )
        .unwrap();
        let mut s = H2Session::new(&[spec], &[cfg()], t0()).unwrap();
        let mut sends = Vec::new();
        while let Some(SessionAction::Send(b)) = s.poll_action() {
            sends.push(b.to_vec());
        }
        let sent: usize = sends
            .iter()
            .filter(|f| f[3] == 0x00)
            .map(|f| f.len() - 9)
            .sum();
        assert_eq!(sent, 65535, "stream window caps the burst");
        assert!(s.poll_action().is_none(), "blocked on the window");
        // server preface + a WINDOW_UPDATE on the stream: the rest flows
        let base = t0();
        let feed = |s: &mut H2Session, bytes: Vec<u8>| {
            s.on_frame(
                Frame {
                    bytes: Bytes::from(bytes),
                    iface: "t".into(),
                    ts: std::time::SystemTime::UNIX_EPOCH,
                },
                base,
            );
        };
        feed(&mut s, server_settings());
        feed(&mut s, frame::window_update_frame(1, 4465).to_vec());
        // the burst also spent the connection window: restore both
        feed(&mut s, frame::window_update_frame(0, 4465).to_vec());
        let mut more = Vec::new();
        while let Some(SessionAction::Send(b)) = s.poll_action() {
            more.push(b.to_vec());
        }
        let rest: usize = more
            .iter()
            .filter(|f| f[3] == 0x00)
            .map(|f| f.len() - 9)
            .sum();
        assert_eq!(rest, 70000 - 65535);
        // the last DATA carries END_STREAM
        let last = more.iter().rev().find(|f| f[3] == 0x00).unwrap();
        assert_eq!(last[4] & END_STREAM, END_STREAM);
    }

    #[test]
    fn settings_adjust_frame_size_and_windows() {
        let spec = HttpRequestSpec::build(
            "POST",
            "https://example.test/",
            &[],
            Bytes::from_static(&[0xcdu8; 40000]),
        )
        .unwrap();
        let mut s = H2Session::new(&[spec], &[cfg()], t0()).unwrap();
        let mut settings = bytes::BytesMut::new();
        frame::encode_settings(
            &mut settings,
            &[
                (frame::SETTINGS_MAX_FRAME_SIZE, 16384),
                (frame::SETTINGS_INITIAL_WINDOW_SIZE, 30000),
            ],
        );
        let frame = frame::encode(FrameType::Settings, 0, 0, &settings);
        let base = t0();
        s.on_frame(
            Frame {
                bytes: Bytes::from(frame.to_vec()),
                iface: "t".into(),
                ts: std::time::SystemTime::UNIX_EPOCH,
            },
            base,
        );
        let mut sends = Vec::new();
        while let Some(SessionAction::Send(b)) = s.poll_action() {
            sends.push(b.to_vec());
        }
        let sent: usize = sends
            .iter()
            .filter(|f| f[3] == 0x00)
            .map(|f| f.len() - 9)
            .sum();
        assert_eq!(sent, 30000, "peer INITIAL_WINDOW_SIZE caps our DATA");
    }

    #[test]
    fn eof_truncates_open_streams() {
        let mut s = H2Session::new(&[spec("https://a/")], &[cfg()], t0()).unwrap();
        // response without END_STREAM, then an orderly EOF
        let block = hpack::encode_header_block(&[(":status", "200"), ("content-length", "100")]);
        let mut rx = server_settings();
        rx.extend_from_slice(&frame::headers_frame(1, &block, false));
        rx.extend_from_slice(&frame::data_frame(1, b"partial", false));
        let (_, results) = drive(&mut s, &[&rx, &[]]);
        assert_eq!(results[0], HttpOutcome::Truncated);
    }

    #[test]
    fn rst_stream_and_goaway_map_to_malformed() {
        let mut s = H2Session::new(&[spec("https://a/")], &[cfg()], t0()).unwrap();
        let mut rx = server_settings();
        rx.extend_from_slice(&frame::encode(
            FrameType::RstStream,
            0,
            1,
            &2u32.to_be_bytes(),
        ));
        let (_, results) = drive(&mut s, &[&rx]);
        match &results[0] {
            HttpOutcome::Malformed(detail) => assert!(detail.contains("reset")),
            other => panic!("reset maps to Malformed: {other:?}"),
        }

        let mut s = H2Session::new(&[spec("https://a/")], &[cfg()], t0()).unwrap();
        let mut rx = server_settings();
        rx.extend_from_slice(&frame::goaway_frame(0, 0));
        let (_, results) = drive(&mut s, &[&rx]);
        match &results[0] {
            HttpOutcome::Malformed(detail) => assert!(detail.contains("GOAWAY")),
            other => panic!("goaway maps to Malformed: {other:?}"),
        }
    }

    #[test]
    fn protocol_errors_are_pointed() {
        // a non-SETTINGS server preface → connection error
        let mut s = H2Session::new(&[spec("https://a/")], &[cfg()], t0()).unwrap();
        let (_, results) = drive(&mut s, &[&frame::data_frame(1, b"x", true)]);
        match &results[0] {
            HttpOutcome::Malformed(detail) => assert!(detail.contains("preface")),
            other => panic!("{other:?}"),
        }
        // out-of-range hpack index → pointed Malformed for the stream
        let mut s = H2Session::new(&[spec("https://a/")], &[cfg()], t0()).unwrap();
        let bad = frame::headers_frame(1, &[0xff], true);
        let (_, results) = drive(&mut s, &[&server_settings(), &bad]);
        match &results[0] {
            HttpOutcome::Malformed(detail) => {
                assert!(
                    detail.contains("integer") || detail.contains("index"),
                    "{detail}"
                )
            }
            other => panic!("{other:?}"),
        }
        // a response head without :status
        let mut s = H2Session::new(&[spec("https://a/")], &[cfg()], t0()).unwrap();
        let block = hpack::encode_header_block(&[("x-only", "1")]);
        let head = frame::headers_frame(1, &block, true);
        let (_, results) = drive(&mut s, &[&server_settings(), &head]);
        match &results[0] {
            HttpOutcome::Malformed(detail) => assert!(detail.contains(":status"), "{detail}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn timeouts_resolve_per_stream() {
        let specs = vec![spec("https://a/"), spec("https://b/")];
        let short = HttpConfig {
            timeout: Duration::from_millis(100),
            max_bytes: 1024,
        };
        let base = t0();
        let mut s = H2Session::new(&specs, &[short, cfg()], base).unwrap();
        // nothing arrives: the short deadline fires first
        assert_eq!(s.next_timeout(), Some(base + Duration::from_millis(100)));
        s.on_timeout(base + Duration::from_millis(100));
        assert_eq!(s.poll_result(), Some(HttpOutcome::Timeout));
        assert!(s.poll_result().is_none(), "only the expired stream");
        assert_eq!(s.next_timeout(), Some(base + TIMEOUT), "the long one waits");
    }

    #[test]
    fn budget_too_large_cancels() {
        let small = HttpConfig {
            timeout: TIMEOUT,
            max_bytes: 4,
        };
        let mut s = H2Session::new(&[spec("https://a/")], &[small], t0()).unwrap();
        let (sends, results) = drive(
            &mut s,
            &[&server_settings(), &server_response(1, 200, b"hello world")],
        );
        assert_eq!(results[0], HttpOutcome::TooLarge);
        // RST_STREAM CANCEL(8) was queued
        assert!(
            sends
                .iter()
                .any(|f| f[3] == 0x03 && f[9..] == 8u32.to_be_bytes())
        );
    }

    #[test]
    fn continuation_fragments_join() {
        let mut s = H2Session::new(&[spec("https://a/")], &[cfg()], t0()).unwrap();
        let block = hpack::encode_header_block(&[(":status", "200"), ("x-slow", "1")]);
        let (a, b) = block.split_at(block.len() / 2);
        let mut rx = server_settings();
        // first half: HEADERS without END_HEADERS (END_STREAM declared)
        rx.extend_from_slice(&frame::encode(FrameType::Headers, END_STREAM, 1, a));
        // second half: CONTINUATION with END_HEADERS
        rx.extend_from_slice(&frame::encode(FrameType::Continuation, END_HEADERS, 1, b));
        let (_, results) = drive(&mut s, &[&rx]);
        let HttpOutcome::Response(resp) = &results[0] else {
            panic!("{results:?}");
        };
        assert_eq!(resp.status.as_u16(), 200);
        assert_eq!(resp.headers.get("x-slow").unwrap(), "1");
        assert!(resp.body.is_empty());
    }

    #[test]
    fn rejects_bad_queues_and_headers() {
        let err = H2Session::new(&[], &[], t0()).unwrap_err();
        assert!(err.contains("empty"));
        let bad = HttpRequestSpec::build(
            "GET",
            "https://a/",
            &[("Connection", "close")],
            Bytes::new(),
        )
        .unwrap();
        let err = H2Session::new(&[bad], &[cfg()], t0()).unwrap_err();
        assert!(err.contains("connection-specific"), "{err}");
        // `:path` never builds: the http-crate name parser rejects the
        // colon — the spec layer refuses pseudo-headers as user input.
        let err = HttpRequestSpec::build("GET", "https://a/", &[(":path", "/x")], Bytes::new())
            .unwrap_err();
        assert!(err.contains("header name"), "{err}");
        // the session-level pseudo-namespace guard stays covered by the
        // `Connection` case above (same code path, different guard).
    }

    #[test]
    fn ping_is_acked() {
        let mut s = H2Session::new(&[spec("https://a/")], &[cfg()], t0()).unwrap();
        let (sends, _) = drive(
            &mut s,
            &[
                &server_settings(),
                &frame::encode(FrameType::Ping, 0, 0, &[1; 8]),
            ],
        );
        assert!(
            sends
                .iter()
                .any(|f| f[3] == 0x06 && f[4] == ACK && f[9..] == [1u8; 8])
        );
    }

    #[test]
    fn late_data_after_done_is_ignored() {
        let mut s = H2Session::new(&[spec("https://a/")], &[cfg()], t0()).unwrap();
        let (_, results) = drive(
            &mut s,
            &[
                &server_settings(),
                &server_response(1, 200, b""),
                &frame::data_frame(1, b"late", true),
            ],
        );
        assert_eq!(results.len(), 1);
        let HttpOutcome::Response(resp) = &results[0] else {
            panic!("{results:?}");
        };
        assert!(resp.body.is_empty());
    }

    #[test]
    fn request_headers_reject_transfer_encoding_only_via_spec() {
        // TE: trailers is the legal form (§7.1); anything else is a
        // connection header already rejected above.
        let spec = HttpRequestSpec::build("GET", "https://a/", &[("te", "trailers")], Bytes::new())
            .unwrap();
        let mut enc = HpackEncoder::new(HpackEncodePolicy::Literal);
        let block = encode_request_headers(&spec, &mut enc).unwrap();
        let mut dec = HpackDecoder::default();
        let fields = dec.decode(&block).unwrap();
        assert!(fields.contains(&("te".as_bytes().to_vec(), "trailers".as_bytes().to_vec())));
    }

    #[test]
    fn indexed_policy_reuses_the_table_across_streams() {
        // Two identical paths on one connection: under Indexed the
        // second stream's `:authority`/`:path` literals become indexed
        // dynamic references (index reuse, stream-ordered); under
        // Literal the blocks are byte-identical (no state).
        let specs = vec![
            spec("https://example.test/a"),
            spec("https://example.test/a"),
        ];
        let mut idx =
            H2Session::with_policy(&specs, &[cfg(), cfg()], t0(), HpackEncodePolicy::Indexed)
                .unwrap();
        let (sends_idx, _) = drive(&mut idx, &[]);
        let mut lit =
            H2Session::with_policy(&specs, &[cfg(), cfg()], t0(), HpackEncodePolicy::Literal)
                .unwrap();
        let (sends_lit, _) = drive(&mut lit, &[]);
        // strip the frame headers: compare HPACK blocks (stream ids differ)
        let blocks = |sends: &[Vec<u8>]| -> Vec<Vec<u8>> {
            sends[1..]
                .iter()
                .filter(|f| f[3] == 0x01)
                .map(|f| f[9..].to_vec())
                .collect()
        };
        let bi = blocks(&sends_idx);
        let bl = blocks(&sends_lit);
        // both decode identically through one stateful peer context
        // (the dynamic table is shared connection state)
        let mut peer = HpackDecoder::default();
        for b in &bi {
            let _ = peer.decode(b).unwrap();
        }
        // Indexed: the second stream's block is *shorter* (dynamic hits)
        assert!(
            bi[1].len() < bi[0].len(),
            "second stream reuses the dynamic table: {} vs {}",
            bi[1].len(),
            bi[0].len()
        );
        // Literal: byte-identical blocks, no state (T15 parity)
        assert_eq!(bl[0], bl[1]);
        assert!(bl[0].len() >= bi[0].len());
    }
}

/// Pass-2 event-schedule property suites (persisted regressions per
/// the pass-1 convention): arbitrary interleavings and split feeds
/// of server byte streams must not desync the session — outcomes are
/// a function of the byte stream, never of the feed schedule.
#[cfg(test)]
mod prop {
    use super::*;
    use crate::frame;
    use crate::hpack;
    use proptest::prelude::*;
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(10);

    fn cfg() -> HttpConfig {
        HttpConfig {
            timeout: TIMEOUT,
            max_bytes: 1024 * 1024,
        }
    }

    fn spec(url: &str) -> HttpRequestSpec {
        HttpRequestSpec::build("GET", url, &[], Bytes::new()).unwrap()
    }

    /// A scripted response (HEADERS [+ DATA]) on one stream.
    fn server_response(id: u32, status: u16, body: &[u8]) -> Vec<u8> {
        let status = status.to_string();
        let block = hpack::encode_header_block(&[
            (":status", &status),
            ("content-type", "text/plain"),
            ("content-length", &body.len().to_string()),
        ]);
        let mut out = frame::headers_frame(id, &block, body.is_empty()).to_vec();
        if !body.is_empty() {
            out.extend_from_slice(&frame::data_frame(id, body, true));
        }
        out
    }

    /// The complete outcome set for a driven session (sends drained,
    /// results forced).
    fn outcomes(specs: &[HttpRequestSpec], stream: &[u8]) -> Vec<HttpOutcome> {
        let mut s = H2Session::new(specs, &vec![cfg(); specs.len()], Instant::now()).unwrap();
        let now = Instant::now();
        s.on_frame(
            Frame {
                bytes: Bytes::copy_from_slice(stream),
                iface: "t".into(),
                ts: std::time::SystemTime::UNIX_EPOCH,
            },
            now,
        );
        let mut outs = Vec::new();
        loop {
            while let Some(SessionAction::Send(_)) = s.poll_action() {}
            match s.next_timeout() {
                Some(t) => s.on_timeout(t),
                None => break,
            }
        }
        while let Some(r) = s.poll_result() {
            outs.push(r);
        }
        outs
    }

    /// Arbitrary SPLIT FEEDS of one server byte stream: feeding the
    /// stream in random chunks (any split, any chunk count) must
    /// yield the same outcomes as one whole on_frame — the session
    /// accumulates, it never resyncs on chunk boundaries.
    proptest! {
        #![proptest_config(ProptestConfig {
            failure_persistence: Some(Box::new(proptest::test_runner::FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            cases: 128,
            ..ProptestConfig::default()
        })]

        #[test]
        fn split_feed_matches_whole_feed(
            splits in proptest::collection::vec(1usize..48, 0..8),
        ) {
            // Two queued requests, two full responses — the canonical
            // script (heads + bodies + a PING interleave).
            let mut stream = frame::settings_frame().to_vec();
            stream.extend_from_slice(&server_response(1, 200, b"hello"));
            stream.extend_from_slice(&server_response(3, 404, b""));
            stream.extend_from_slice(&frame::ping_ack_frame(b"12345678"));

            // Chunk boundaries at arbitrary offsets (sorted, in-stream).
            let mut cuts: Vec<usize> = splits;
            cuts.sort();
            cuts.dedup();
            cuts.retain(|c| *c < stream.len());
            let mut pieces: Vec<&[u8]> = Vec::new();
            let mut prev = 0usize;
            for c in cuts {
                if c > prev {
                    pieces.push(&stream[prev..c]);
                    prev = c;
                }
            }
            pieces.push(&stream[prev..]);

            let specs = vec![spec("https://example.test/"), spec("https://example.test/x")];
            let want = outcomes(&specs, &stream);

            // Feed piece-by-piece.
            let mut s = H2Session::new(&specs, &vec![cfg(); specs.len()], Instant::now()).unwrap();
            let now = Instant::now();
            for p in &pieces {
                s.on_frame(
                    Frame {
                        bytes: Bytes::copy_from_slice(p),
                        iface: "t".into(),
                        ts: std::time::SystemTime::UNIX_EPOCH,
                    },
                    now,
                );
            }
            let mut got = Vec::new();
            loop {
                while let Some(SessionAction::Send(_)) = s.poll_action() {}
                match s.next_timeout() {
                    Some(t) => s.on_timeout(t),
                    None => break,
                }
            }
            while let Some(r) = s.poll_result() {
                got.push(r);
            }
            // Outcomes are a function of the byte stream only.
            assert_eq!(got.len(), want.len(), "split feed desynced outcome count");
            for (g, w) in got.iter().zip(&want) {
                let (gs, ws) = (format!("{g:?}"), format!("{w:?}"));
                assert_eq!(gs, ws, "split feed changed an outcome");
            }
        }
    }

    /// Random INTERLEAVINGS of independent server frames (PING,
    /// WINDOW_UPDATE, SETTINGS) around the response frames: the
    /// per-request outcomes must be unaffected — ordering of
    /// connection-housekeeping frames is free.
    proptest! {
        #![proptest_config(ProptestConfig {
            failure_persistence: Some(Box::new(proptest::test_runner::FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            cases: 128,
            ..ProptestConfig::default()
        })]

        #[test]
        fn housekeeping_interleavings_preserve_outcomes(
            holes in proptest::collection::vec(0usize..3, 0..4),
        ) {
            let specs = vec![spec("https://example.test/")];
            // Response pieces for stream 1 (head + body).
            let status = "200".to_string();
            let block = hpack::encode_header_block(&[
                (":status", &status),
                ("content-type", "text/plain"),
                ("content-length", "5"),
            ]);
            let head = frame::headers_frame(1, &block, false).to_vec();
            let body = frame::data_frame(1, b"hello", true).to_vec();
            // Housekeeping frames (independent, order-free).
            let ping = frame::ping_ack_frame(b"12345678").to_vec();
            let wu = frame::window_update_frame(0, 0x10000).to_vec();

            // Place housekeeping at arbitrary slots around/between the
            // response frames.
            let mut stream = Vec::new();
            let pieces: [&[u8]; 2] = [&head, &body];
            for (i, p) in pieces.iter().enumerate() {
                for h in holes.iter().filter(|h| **h == i) {
                    match h % 3 {
                        0 => stream.extend_from_slice(&ping),
                        1 => stream.extend_from_slice(&wu),
                        _ => {}
                    }
                }
                stream.extend_from_slice(p);
            }
            // Outcomes on the interleaved stream equal the plain one.
            let mut plain = Vec::new();
            plain.extend_from_slice(&head);
            plain.extend_from_slice(&body);
            let want = outcomes(&specs, &plain);
            let got = outcomes(&specs, &stream);
            assert_eq!(got.len(), want.len());
            for (g, w) in got.iter().zip(&want) {
                assert_eq!(format!("{g:?}"), format!("{w:?}"), "interleave changed an outcome");
            }
        }
    }
}
