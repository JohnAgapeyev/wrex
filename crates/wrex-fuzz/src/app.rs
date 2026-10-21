//! [`AppSession`] (tranche 9b): one *mutated application-layer
//! request* over a kernel stream connection — the sans-IO probe unit
//! for `wrex fuzz --mode http|dns`.
//!
//! The tranche-6b [`ProberSession`](crate::ProberSession) works at
//! the L3/L4-inject level (raw sockets, 4-tuple reply matching). The
//! app modes instead ride **kernel TCP** (the
//! [`wrex_io::TcpDriver`], the T4/T8a stream conventions): a mutation
//! that breaks transport framing costs the probe its connection, not
//! the run. No userspace TCP stack is involved — the twice-deferred
//! T4/T6 item stays deferred; mutating TCP state *and* continuing to
//! an application exchange is the only case that would need it.
//!
//! Per probe (one fresh connection, mirroring `query --tcp`):
//! - **send** the (baseline or mutated) request bytes;
//! - **read** whatever the peer sends until **orderly EOF** (an empty
//!   frame, the `TcpDriver` convention) — those bytes are the reply;
//! - **record** the finding: `Reply` (with the response bytes, budget
//!   capped) or `Silence` on timeout. A connect failure is silence
//!   too (verb-side: the attempt still counts).
//!
//! The session is transport-agnostic: it never opens sockets or reads
//! clocks; the verb drives it under [`wrex_session::run`] or tests
//! under `FakeClock` + `ScriptedDriver`.

use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use wrex_io::Frame;
use wrex_session::{Session, SessionAction};

/// Hard response budget (mirrors the `wrex http` default): a hostile
/// stream must not grow the buffer without limit.
pub const DEFAULT_MAX_BYTES: usize = 64 * 1024 * 1024;

/// One app-layer probe exchange's configuration.
#[derive(Clone, Copy, Debug)]
pub struct AppConfig {
    /// Per-probe exchange timeout (send + response).
    pub timeout: Duration,
    /// Response byte budget (head + body, the whole stream).
    pub max_bytes: usize,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_bytes: DEFAULT_MAX_BYTES,
        }
    }
}

/// The probe outcome: the response bytes (EOF-delimited) or silence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppOutcome {
    /// The peer answered and closed; the recorded bytes are the reply.
    Reply(Bytes),
    /// No complete answer within the attempt timeout.
    Silence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Request not yet emitted.
    Sending,
    /// Reading the response stream.
    Reading,
    Done,
}

/// One mutated request over one stream connection.
pub struct AppSession {
    cfg: AppConfig,
    request: Bytes,
    now: Instant,
    deadline: Instant,
    sent: bool,
    phase: Phase,
    response: BytesMut,
    result: Option<AppOutcome>,
}

impl AppSession {
    /// Build the session for one probe (usage errors never occur
    /// here — the request bytes are pre-serialized verb-side).
    pub fn new(request: Bytes, cfg: AppConfig, t0: Instant) -> Self {
        Self {
            cfg,
            request,
            now: t0,
            deadline: t0 + cfg.timeout,
            sent: false,
            phase: Phase::Sending,
            response: BytesMut::new(),
            result: None,
        }
    }

    fn finish(&mut self, outcome: AppOutcome) {
        self.phase = Phase::Done;
        self.result = Some(outcome);
    }
}

impl Session for AppSession {
    type Output = AppOutcome;

    fn on_frame(&mut self, frame: Frame, now: Instant) {
        self.now = now;
        if self.phase == Phase::Done {
            return; // late bytes after completion
        }
        if frame.bytes.is_empty() {
            // Orderly EOF: whatever arrived is the reply.
            let bytes = std::mem::take(&mut self.response).freeze();
            self.finish(AppOutcome::Reply(bytes));
            return;
        }
        // Byte budget: the whole response stream counts. A chunk that
        // overruns the cap keeps what fits, then the reply resolves.
        let room = self.cfg.max_bytes.saturating_sub(self.response.len());
        if frame.bytes.len() > room {
            self.response.extend_from_slice(&frame.bytes[..room]);
            let bytes = std::mem::take(&mut self.response).freeze();
            self.finish(AppOutcome::Reply(bytes));
            return;
        }
        self.response.extend_from_slice(&frame.bytes);
    }

    fn on_timeout(&mut self, now: Instant) {
        self.now = now;
        if self.phase == Phase::Done {
            return;
        }
        self.finish(AppOutcome::Silence);
    }

    fn poll_action(&mut self) -> Option<SessionAction> {
        if !self.sent && self.phase == Phase::Sending {
            self.sent = true;
            self.deadline = self.now + self.cfg.timeout;
            self.phase = Phase::Reading;
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

    fn poll_result(&mut self) -> Option<AppOutcome> {
        self.result.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use wrex_io::{Clock as _, FakeClock, ScriptedDriver};

    const MS: Duration = Duration::from_millis(1);

    fn cfg() -> AppConfig {
        AppConfig {
            timeout: Duration::from_secs(1),
            max_bytes: 4096,
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

    /// Drive one probe: send, feed `script` chunks (empty = EOF),
    /// fire deadlines until idle.
    fn probe(request: &[u8], cfg: AppConfig, script: Vec<Vec<u8>>) -> AppOutcome {
        let mut s = AppSession::new(Bytes::copy_from_slice(request), cfg, t0());
        let mut t = t0();
        while s.poll_action().is_some() {}
        for chunk in script {
            t += MS;
            s.on_frame(frame(chunk), t);
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
        panic!("no outcome (phase {:?})", s.phase)
    }

    #[test]
    fn reply_collects_until_eof() {
        let out = probe(
            b"GET / HTTP/1.1\r\n",
            cfg(),
            vec![b"HTTP/1.1 200".to_vec(), b" OK\r\nhello".to_vec(), vec![]],
        );
        assert_eq!(
            out,
            AppOutcome::Reply(Bytes::from_static(b"HTTP/1.1 200 OK\r\nhello"))
        );
    }

    #[test]
    fn silence_on_timeout() {
        // Nothing arrives: the deadline fires.
        assert_eq!(probe(b"q", cfg(), vec![]), AppOutcome::Silence);
    }

    #[test]
    fn budget_cap_stops_collection() {
        let mut tiny = cfg();
        tiny.max_bytes = 8;
        let out = probe(b"q", tiny, vec![b"0123456789abcdef".to_vec()]);
        let AppOutcome::Reply(bytes) = out else {
            panic!("expected a capped reply");
        };
        assert_eq!(&bytes[..], b"01234567");
    }

    #[test]
    fn run_loop_end_to_end_with_scripted_driver() {
        let reg_clock = Arc::new(FakeClock::new());
        let t = reg_clock.now();
        let mut session = AppSession::new(Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n"), cfg(), t);
        let mut driver = ScriptedDriver::new(
            reg_clock.clone(),
            vec![b"HTTP/1.1 200 OK\r\n".to_vec(), vec![]],
        );
        let out = wrex_session::run(&mut session, &mut driver, reg_clock.as_ref()).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0],
            AppOutcome::Reply(Bytes::from_static(b"HTTP/1.1 200 OK\r\n"))
        );
        // the request reached the "wire"
        assert_eq!(driver.sent[0], b"GET / HTTP/1.1\r\n\r\n".to_vec());
    }
}
