#![forbid(unsafe_code)]
//! wrex-dns: `wrex query` orchestration — one seeded DNS question over
//! a kernel transport (UDP datagrams or RFC 7766 TCP streams, TLS for
//! DoT), answered (or not) over the frozen
//! [`wrex_session::Session`] contract.
//!
//! Perf-pass 3b: the default UDP path rides a kernel socket
//! ([`DnsUdpSession`] + [`wrex_io::UdpDriver`], the dig-style
//! transport) — arbitrary L3/L4 crafting stays in the craft/send
//! verbs. The sessions never touch sockets or clocks: the CLI runs
//! them under [`wrex_session::run`] with the matching driver and
//! [`wrex_io::SystemClock`]; tests drive them directly or under
//! [`wrex_io::FakeClock`] + [`wrex_io::ScriptedDriver`]. Query
//! identity (the 16-bit dns id + source port draw) comes from the
//! seeded [`wrex_io::Rng`]: a pinned `--seed` reproduces a
//! byte-identical query.

mod session;
mod tcp;
mod udp;

pub use session::{QueryConfig, build_tcp_query};
pub use tcp::{DnsTcpReply, DnsTcpSession};
pub use udp::{DnsReply, DnsUdpSession};
pub use wrex_proto_dns::types;
