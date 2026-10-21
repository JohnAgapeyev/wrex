#![forbid(unsafe_code)]
//! wrex-fuzz: the tranche-6b stateful prober — a recording
//! [`wrex_session::Session`] state machine that sends *mutated* probes
//! (built with [`wrex_mut`]) at targets over a raw-IP driver, matches
//! replies per probe, and emits a findings table (one
//! [`Finding`] per probe) for offline differential analysis — plus,
//! since tranche 9b, the **application-layer** modes (`--mode
//! http|dns`): mutated request bytes over the *kernel* `TcpDriver`
//! ([`AppSession`], one fresh connection per probe), closing the
//! tranche-6 gap without any userspace TCP stack.
//!
//! The prober never talks to sockets or clocks: the CLI runs it under
//! [`wrex_session::run`] with a [`wrex_io::RawIpDriver`] (kernel TCP is
//! out of charter — the userspace stack stays deferred); tests drive
//! it under `FakeClock` + `ScriptedDriver` like the scan session.
//!
//! Semantics per probe:
//!
//! - **send** the (baseline or mutated) probe bytes at its scheduled
//!   instant (pacing + seeded jitter), at most `--concurrent` in
//!   flight; retransmissions repeat the *same* bytes;
//! - **match** replies against the in-flight table by 4-tuple
//!   (tcp/udp) or echo id (icmp) — the key is derived from the
//!   *post-mutation* dissection, so a mutation that moved the
//!   identity still matches its own replies; cross-talk resolves
//!   nothing;
//! - **record** the outcome: a matching reply (with reply bytes), an
//!   ICMP-unreachable attribution (code quoted), or silence after
//!   exhaustion — every finding carries the exact probe bytes, so
//!   anything interesting replays with `wrex send`/`wrex replay`.

pub mod app;
pub mod config;
pub mod diff;
pub mod report;
pub mod session;

pub use app::{AppConfig, AppOutcome, AppSession};
pub use config::{DEFAULT_ROUNDS, FuzzConfig, ProbeMode};
pub use diff::{Delta, DiffEntry, FindingRecord, Side, diff_findings, parse_findings};
pub use report::{Finding, Outcome};
pub use session::ProberSession;
