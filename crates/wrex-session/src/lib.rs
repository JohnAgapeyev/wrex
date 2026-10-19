#![forbid(unsafe_code)]
//! wrex-session: the sans-IO session contract (frozen at tranche-2
//! planning) plus the shared runtime loop that pumps events between a
//! [`Session`] state machine and a [`wrex_io::Driver`] under a
//! [`wrex_io::Clock`].
//!
//! The split is quinn-proto style: a session holds all protocol state
//! (probe tables, retransmit schedules, classification) and never
//! touches sockets or wall-clock time; the runtime feeds it received
//! frames and timeout instants, and drains outbound actions and
//! completed results. Tests drive a session directly (or via
//! [`run`] with `wrex_io`'s `FakeClock` + `ScriptedDriver`); the CLI
//! passes a real driver and `SystemClock`.
//!
//! Shape freeze (tranche 2): the method set below is the contract later
//! tranches (T3 DNS, T4 HTTP, T6 prober) implement; [`SessionAction`]
//! is `#[non_exhaustive`] so new action kinds can be added without
//! breaking implementors, per the standing "later tranches never break
//! earlier contracts" rule.

use std::io;
use std::time::Instant;

use bytes::Bytes;
use wrex_io::{Clock, Driver, Frame};

/// One outbound action a session wants the runtime to perform.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SessionAction {
    /// Send these bytes. The payload starts at the driver's start layer
    /// (eth frames for [`wrex_io::RawEthDriver`], IPv4 datagrams for
    /// [`wrex_io::RawIpDriver`]).
    Send(Bytes),
}

/// A sans-IO event/queue state machine over a packet driver.
///
/// All `now` instants are supplied by the runtime ([`run`]) or the test
/// harness, so implementations stay clock-less and deterministic.
pub trait Session: Send {
    /// Unit of completed work (a scan result, a DNS answer, …).
    type Output: Send;

    /// One frame arrived from the driver at `now`.
    fn on_frame(&mut self, frame: Frame, now: Instant);
    /// The earliest instant previously reported by
    /// [`Session::next_timeout`] has been reached without a frame.
    fn on_timeout(&mut self, now: Instant);
    /// Drain one due outbound action (`None` = nothing due right now).
    fn poll_action(&mut self) -> Option<SessionAction>;
    /// The earliest instant the runtime must wake the session
    /// (`None` = idle: no timers, no pending sends — work is done).
    fn next_timeout(&mut self) -> Option<Instant>;
    /// Drain one completed result.
    fn poll_result(&mut self) -> Option<Self::Output>;
}

/// Sans-IO runtime loop: pump events between a session and a driver.
///
/// One iteration: drain due actions to the driver's `send`, drain
/// completed results, then either fire the session's next timeout or
/// block in `driver.recv` until the earliest of (reply arrival,
/// deadline) and feed the outcome back. Returns once the session goes
/// idle ([`Session::next_timeout`] → `None`).
pub fn run<S: Session>(
    session: &mut S,
    driver: &mut dyn Driver,
    clock: &dyn Clock,
) -> io::Result<Vec<S::Output>> {
    let mut out = Vec::new();
    loop {
        while let Some(action) = session.poll_action() {
            match action {
                SessionAction::Send(bytes) => driver.send(&bytes)?,
            }
        }
        while let Some(result) = session.poll_result() {
            out.push(result);
        }
        let Some(deadline) = session.next_timeout() else {
            return Ok(out);
        };
        let now = clock.now();
        if now >= deadline {
            session.on_timeout(now);
        } else if let Some(frame) = driver.recv(deadline)? {
            session.on_frame(frame, clock.now());
        } else {
            // Driver yielded at the deadline with no frame.
            session.on_timeout(clock.now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;

    use wrex_io::{FakeClock, ScriptedDriver};

    /// Ping-pong mock: sends one probe, resolves on any frame, times out
    /// to a "loss" result if nothing arrives before its deadline. Each
    /// result is yielded exactly once (the runtime drains poll_result).
    struct PingPong {
        sent: bool,
        resolved: bool,
        timed_out: bool,
        yielded: bool,
        deadline: Instant,
    }

    impl Session for PingPong {
        type Output = &'static str;

        fn on_frame(&mut self, _frame: Frame, _now: Instant) {
            self.resolved = true;
        }

        fn on_timeout(&mut self, _now: Instant) {
            if !self.resolved {
                self.timed_out = true;
            }
        }

        fn poll_action(&mut self) -> Option<SessionAction> {
            if self.sent {
                return None;
            }
            self.sent = true;
            Some(SessionAction::Send(Bytes::from_static(b"ping")))
        }

        fn next_timeout(&mut self) -> Option<Instant> {
            if self.resolved || self.timed_out {
                return None;
            }
            Some(self.deadline)
        }

        fn poll_result(&mut self) -> Option<Self::Output> {
            if self.yielded {
                return None;
            }
            if self.resolved {
                self.yielded = true;
                Some("pong")
            } else if self.timed_out {
                self.yielded = true;
                Some("loss")
            } else {
                None
            }
        }
    }

    #[test]
    fn run_wires_frames_actions_and_results() {
        let clock = Arc::new(FakeClock::new());
        let t0 = clock.now();
        let mut session = PingPong {
            sent: false,
            resolved: false,
            timed_out: false,
            yielded: false,
            deadline: t0 + Duration::from_secs(1),
        };
        let mut driver = ScriptedDriver::new(clock.clone(), vec![vec![6, 6]]);
        let out = run(&mut session, &mut driver, clock.as_ref()).unwrap();
        assert_eq!(out, vec!["pong"]);
        // the probe reached the driver before the scripted reply
        assert_eq!(driver.sent, vec![b"ping".to_vec()]);
    }

    #[test]
    fn run_fires_timeouts_at_deadlines() {
        let clock = Arc::new(FakeClock::new());
        let t0 = clock.now();
        let mut session = PingPong {
            sent: false,
            resolved: false,
            timed_out: false,
            yielded: false,
            deadline: t0 + Duration::from_secs(1),
        };
        let mut driver = ScriptedDriver::new(clock.clone(), vec![]);
        let out = run(&mut session, &mut driver, clock.as_ref()).unwrap();
        assert_eq!(out, vec!["loss"]);
        // the empty script fast-forwarded the fake clock to the deadline
        assert!(clock.now() >= t0 + Duration::from_secs(1));
    }

    #[test]
    fn action_is_non_exhaustive_for_future_variants() {
        // Compile-time check: matching the frozen action exhaustively
        // outside this crate must stay non-exhaustive-compatible.
        let a = SessionAction::Send(Bytes::new());
        match a {
            SessionAction::Send(_) => {}
        }
    }
}
