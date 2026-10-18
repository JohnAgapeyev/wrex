//! wrex-io: Clock, Driver, Linux AF_PACKET raw driver, replay driver,
//! interface table.
//!
//! This is the ONLY crate in the workspace permitted to contain `unsafe`;
//! every block carries a `// SAFETY:` comment.

pub mod driver;
pub mod iface;
pub mod replay;

pub use driver::{Driver, DriverError, Frame, RawEthDriver};
pub use iface::{IfEntry, IfTable};
pub use replay::{FakeClock, ReplayDriver};

use std::time::Instant;

/// Time source abstraction (sans-IO).
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
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
