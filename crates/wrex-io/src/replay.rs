//! Deterministic replay/fake drivers and manual-advance clock for tests and
//! later tranches. No sockets, no real time.

use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use crate::driver::{Driver, Frame};

/// Manual-advance clock: `advance()` moves `now()` forward.
pub struct FakeClock {
    offset_ms: std::sync::atomic::AtomicU64,
    base: Instant,
}

impl Default for FakeClock {
    fn default() -> Self {
        Self {
            offset_ms: std::sync::atomic::AtomicU64::new(0),
            base: Instant::now(),
        }
    }
}

impl FakeClock {
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance the clock (millisecond resolution).
    pub fn advance(&self, d: Duration) {
        self.offset_ms.fetch_add(
            d.as_millis().min(u64::MAX as u128) as u64,
            std::sync::atomic::Ordering::SeqCst,
        );
    }
}

impl crate::Clock for FakeClock {
    fn now(&self) -> Instant {
        self.base + Duration::from_millis(self.offset_ms.load(std::sync::atomic::Ordering::SeqCst))
    }
}

/// Scripted driver: yields the given frames (in order) on `recv`, then
/// times out. `send` records into `sent`.
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

pub fn epoch_ts() -> SystemTime {
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
}
