#![forbid(unsafe_code)]
//! wrex-dns: `wrex query` orchestration — one seeded DNS question over
//! a raw UDP datagram, answered (or not) over the frozen
//! [`wrex_session::Session`] contract.
//!
//! The [`DnsSession`] never touches sockets or clocks: the CLI runs it
//! under [`wrex_session::run`] with a [`wrex_io::RawIpDriver`] and
//! [`wrex_io::SystemClock`]; tests drive it directly or under
//! [`wrex_io::FakeClock`] + [`wrex_io::ScriptedDriver`]. Query identity
//! (source port + 16-bit dns id) comes from the seeded
//! [`wrex_io::Rng`]: a pinned `--seed` reproduces a byte-identical
//! query.

mod session;

pub use session::{DnsReply, DnsSession, QueryConfig};
pub use wrex_proto_dns::types;
