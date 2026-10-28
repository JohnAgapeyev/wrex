#![forbid(unsafe_code)]
//! wrex-scan: scan orchestration as a sans-IO [`wrex_session::Session`]
//! state machine plus the grammar/schedule machinery around it.
//!
//! Layout:
//! - [`config`]: `ScanConfig`, [`ScanMode`](config::ScanMode), defaults
//!   (rate, retries, timeout, concurrency) and the top-100 TCP list.
//! - [`target`]: target and port grammar (IPv4, CIDR, ranges, lists).
//! - [`packet`]: probe/follow-up packet builders over the wrex-core
//!   encode engine.
//! - [`report`]: [`ScanResult`](report::ScanResult) classification types.
//! - [`session`]: [`ScanSession`](session::ScanSession) — the probe
//!   table, retransmit state machine, reply matching and classification.
//!
//! The session never touches sockets or clocks: the CLI runs it under
//! [`wrex_session::run`] with a [`wrex_io::RawIpDriver`] and
//! [`wrex_io::SystemClock`]; tests drive it directly or under
//! [`wrex_io::FakeClock`] + [`wrex_io::ScriptedDriver`].

pub mod config;
pub mod packet;
pub mod report;
pub mod session;
pub mod target;

pub use config::{DEFAULT_INTERVAL, DEFAULT_TCP_PORTS, ScanConfig, ScanMode};
pub use report::ScanResult;
pub use session::ScanSession;
pub use target::{Family, ScanAddr};

/// Seeded jitter source (moved to `wrex-io` at tranche 3; re-exported
/// for source compatibility).
pub use wrex_io::Rng;
