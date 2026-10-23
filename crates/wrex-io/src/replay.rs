//! Deterministic replay/fake drivers and manual-advance clock for tests and
//! later tranches. No sockets, no real time.

use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use crate::driver::{Driver, Frame};

/// Manual-advance clock: `advance()` moves `now()` forward;
/// `fast_forward_to` jumps it to an instant (test doubles only).
///
/// Microsecond resolution (tranche 2: scan retransmit schedules need
/// sub-ms precision under fast test runs).
pub struct FakeClock {
    offset_us: std::sync::atomic::AtomicU64,
    base: Instant,
}

impl Default for FakeClock {
    fn default() -> Self {
        Self {
            offset_us: std::sync::atomic::AtomicU64::new(0),
            base: Instant::now(),
        }
    }
}

impl FakeClock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance the clock (microsecond resolution, saturating).
    pub fn advance(&self, d: Duration) {
        self.offset_us.fetch_add(
            d.as_micros().min(u64::MAX as u128) as u64,
            std::sync::atomic::Ordering::SeqCst,
        );
    }

    fn offset_us(&self) -> u64 {
        self.offset_us.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl crate::Clock for FakeClock {
    fn now(&self) -> Instant {
        self.base + Duration::from_micros(self.offset_us())
    }

    fn fast_forward(&self, t: Instant) {
        // Jump to `t` if it is in the future (never backwards): a driver
        // whose script is exhausted hands the runtime a deterministic
        // timeout this way instead of sleeping.
        let target_us = t.saturating_duration_since(self.base).as_micros() as u64;
        let mut cur = self.offset_us();
        while target_us > cur {
            match self.offset_us.compare_exchange(
                cur,
                target_us,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            ) {
                Ok(_) => return,
                Err(actual) => cur = actual,
            }
        }
    }
}

/// Scripted driver: yields the given frame payloads (in order) on `recv`,
/// then times out — fast-forwarding the shared clock to the deadline so
/// the sans-IO runtime loop observes timeouts deterministically. `send`
/// records into `sent`.
///
/// Clock-aware (tranche 2): constructed over an `Arc<dyn Clock>` so an
/// exhausted script and the runtime agree on time without sleeping.
pub struct ScriptedDriver {
    clock: Arc<dyn crate::Clock>,
    scripted: std::collections::VecDeque<Bytes>,
    /// Frames passed to `send` (bytes only, for assertions).
    pub sent: Vec<Vec<u8>>,
}

impl ScriptedDriver {
    pub fn new(clock: Arc<dyn crate::Clock>, frames: Vec<Vec<u8>>) -> Self {
        Self {
            clock,
            scripted: frames.into_iter().map(Bytes::from).collect(),
            sent: Vec::new(),
        }
    }

    pub fn remaining(&self) -> usize {
        self.scripted.len()
    }

    fn pop(&mut self) -> Option<Frame> {
        let bytes = self.scripted.pop_front()?;
        // Frame timestamps are unused by the sans-IO sessions (events
        // carry `now` separately); epoch keeps them deterministic.
        Some(Frame {
            bytes,
            iface: "scripted".to_string(),
            ts: UNIX_EPOCH,
        })
    }
}

impl Driver for ScriptedDriver {
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        self.sent.push(frame.to_vec());
        Ok(())
    }

    fn recv(&mut self, deadline: Instant) -> io::Result<Option<Frame>> {
        if self.clock.now() >= deadline {
            return Ok(None);
        }
        match self.pop() {
            Some(frame) => Ok(Some(frame)),
            // Nothing more will ever arrive: hand the runtime the
            // timeout at the scheduled instant (deterministic).
            None => {
                self.clock.fast_forward(deadline);
                Ok(None)
            }
        }
    }
}

/// Scripted driver WITHOUT a clock: yields the given frames (in order) on
/// `recv`, then times out. `send` records into `sent`.
///
/// Kept for the tranche-1 tests; new code prefers [`ScriptedDriver`].
pub struct ReplayDriver {
    scripted: std::collections::VecDeque<Frame>,
    /// Frames passed to `send` (bytes only, for assertions).
    pub sent: Vec<Vec<u8>>,
}

impl ReplayDriver {
    pub fn new(frames: Vec<Frame>) -> Self {
        Self {
            scripted: frames.into(),
            sent: Vec::new(),
        }
    }

    pub fn remaining(&self) -> usize {
        self.scripted.len()
    }
}

impl Driver for ReplayDriver {
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        self.sent.push(frame.to_vec());
        Ok(())
    }

    fn recv(&mut self, _deadline: Instant) -> io::Result<Option<Frame>> {
        Ok(self.scripted.pop_front())
    }
}

/// Convenience: build a frame for [`ReplayDriver`] (unix epoch ts).
pub fn fake_frame(iface: &str, bytes: &[u8]) -> Frame {
    Frame {
        bytes: Bytes::copy_from_slice(bytes),
        iface: iface.to_string(),
        ts: SystemTime::UNIX_EPOCH,
    }
}

pub const fn epoch_ts() -> SystemTime {
    UNIX_EPOCH
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Clock;

    #[test]
    fn fake_clock_advances() {
        let c = FakeClock::new();
        let t0 = c.now();
        c.advance(Duration::from_millis(500));
        let t1 = c.now();
        assert_eq!(t1 - t0, Duration::from_millis(500));
    }

    #[test]
    fn fake_clock_is_microsecond() {
        let c = FakeClock::new();
        let t0 = c.now();
        c.advance(Duration::from_micros(1500));
        // not rounded down to whole milliseconds
        assert_eq!(c.now() - t0, Duration::from_micros(1500));
    }

    #[test]
    fn fast_forward_moves_forward_only() {
        let c = FakeClock::new();
        let t0 = c.now();
        c.fast_forward(t0 + Duration::from_millis(300));
        assert_eq!(c.now(), t0 + Duration::from_millis(300));
        // backwards is a no-op
        c.fast_forward(t0);
        assert_eq!(c.now(), t0 + Duration::from_millis(300));
    }

    #[test]
    fn replay_yields_then_times_out() {
        let f1 = fake_frame("lo", &[1, 2]);
        let f2 = fake_frame("lo", &[3]);
        let mut d = ReplayDriver::new(vec![f1, f2]);
        let deadline = Instant::now() + Duration::from_secs(1);
        let a = d.recv(deadline).unwrap().unwrap();
        assert_eq!(&a.bytes[..], &[1, 2]);
        let b = d.recv(deadline).unwrap().unwrap();
        assert_eq!(&b.bytes[..], &[3]);
        assert!(d.recv(deadline).unwrap().is_none());
        assert_eq!(d.remaining(), 0);
    }

    #[test]
    fn replay_records_sends() {
        let mut d = ReplayDriver::new(vec![]);
        d.send(&[9, 9]).unwrap();
        assert_eq!(d.sent, vec![vec![9, 9]]);
    }

    #[test]
    fn scripted_pops_then_fast_forwards() {
        let clock = Arc::new(FakeClock::new());
        let mut d = ScriptedDriver::new(clock.clone(), vec![vec![1], vec![2]]);
        let deadline = clock.now() + Duration::from_secs(1);
        assert_eq!(d.recv(deadline).unwrap().unwrap().bytes[..], [1]);
        assert_eq!(d.recv(deadline).unwrap().unwrap().bytes[..], [2]);
        // exhausted: recv hands back None AND moves time to the deadline
        assert!(d.recv(deadline).unwrap().is_none());
        assert_eq!(clock.now(), deadline);
        assert_eq!(d.remaining(), 0);
    }

    #[test]
    fn scripted_records_sends() {
        let clock = Arc::new(FakeClock::new());
        let mut d = ScriptedDriver::new(clock, vec![]);
        d.send(&[7, 7]).unwrap();
        assert_eq!(d.sent, vec![vec![7, 7]]);
    }
}
