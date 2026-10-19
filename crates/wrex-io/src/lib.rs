//! wrex-io: Clock, Driver, Linux AF_PACKET raw Ethernet + raw IP drivers,
//! replay/scripted drivers, interface table.
//!
//! This is the ONLY crate in the workspace permitted to contain `unsafe`;
//! every block carries a `// SAFETY:` comment.

pub mod driver;
pub mod iface;
pub mod replay;
pub mod rng;

pub(crate) mod rx;

pub use driver::{Driver, DriverError, Frame, RawEthDriver, RawIpDriver};
pub use iface::{IfEntry, IfTable};
pub use replay::{FakeClock, ReplayDriver, ScriptedDriver};
pub use rng::Rng;

use std::time::Instant;

/// Time source abstraction (sans-IO).
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;

    /// Jump time forward to `t` (test doubles only). No-op on real
    /// clocks; added at tranche 2 so a driver with an exhausted script
    /// can hand the runtime a deterministic timeout instead of
    /// sleeping real time. Defaulted: existing clocks stay source-
    /// compatible.
    fn fast_forward(&self, _t: Instant) {}
}

/// Real system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn system_clock_ticks() {
        use super::Clock;
        let c = super::SystemClock;
        assert!(c.now() <= c.now());
    }
}
