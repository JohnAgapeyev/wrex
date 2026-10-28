//! Kernel UDP client driver (perf-pass 3b): a `std::net::UdpSocket`
//! behind the [`Driver`] trait — the dig-style transport for `wrex
//! query`'s default mode, after the raw-IP + AF_PACKET tap path
//! measured ~15–19ms of fixed cost per invocation (the perf-diff
//! dns/udp row: any AF_PACKET socket's protocol-hook add/remove waits
//! on an RCU grace period — ~14ms bind + ~4ms close on 32 CPUs; a
//! kernel UDP socket costs microseconds).
//!
//! ## Datagram framing on the stream-ish trait
//!
//! - `send` writes one datagram (the connected-socket form — no
//!   per-call address, the peer was fixed at [`UdpDriver::connect`]);
//! - `recv` returns ONE datagram before `deadline` (`Ok(None)` on
//!   timeout). The `connect(2)` filter makes the kernel demux by
//!   4-tuple — cross-talk from other sources never surfaces; a
//!   wrong-id datagram from the peer itself is still possible (stale
//!   replies), and sessions keep matching application-layer ids.
//! - ICMP unreachable surfacing as `ECONNREFUSED` on the socket is
//!   swallowed: the reply the session waits for never follows one, so
//!   the attempt runs to its timeout and the verb reports "no reply"
//!   (the raw path's UX — an unreach was just a non-matching frame).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::time::Instant;

use bytes::Bytes;

use crate::driver::{Driver, DriverError, Frame};

/// Kernel UDP client socket: optional local bind, `connect(2)` to the
/// peer.
pub struct UdpDriver {
    sock: UdpSocket,
    peer: String,
}

impl UdpDriver {
    /// Bind locally (optional), then connect to `peer` — a connected
    /// UDP socket receives only the peer's replies. A taken bind port
    /// (the seeded source port can collide) falls back to the
    /// kernel's ephemeral pick on the same address: the transport
    /// port is a convenience, never a failure, and the seeded DNS
    /// message bytes stay identical either way.
    pub fn connect(peer: SocketAddr, bind: Option<SocketAddr>) -> Result<Self, DriverError> {
        let unspecified = match peer {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let sock = match bind {
            Some(local) => UdpSocket::bind(local)
                .or_else(|_| UdpSocket::bind(SocketAddr::new(local.ip(), 0)))
                .map_err(|e| DriverError::Io { source: e })?,
            None => UdpSocket::bind(unspecified).map_err(|e| DriverError::Io { source: e })?,
        };
        sock.connect(peer)
            .map_err(|e| DriverError::Io { source: e })?;
        Ok(Self {
            sock,
            peer: peer.to_string(),
        })
    }

    /// The connected peer address (rendering/diagnostics).
    pub fn peer(&self) -> &str {
        &self.peer
    }
}

impl Driver for UdpDriver {
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        self.sock.send(frame).map(|_| ())
    }

    fn recv(&mut self, deadline: Instant) -> io::Result<Option<Frame>> {
        let mut pfd = libc::pollfd {
            fd: self.sock.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let timeout_ms = (deadline - now).as_millis().min(u32::MAX as u128) as u32;
            // SAFETY: `poll` writes into `pfd` (stack-local, owned
            // here) and reads only its size argument; `fd` is valid.
            let ready = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, timeout_ms as i32) };
            if ready < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(err);
            }
            if ready == 0 {
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                continue;
            }
            // One datagram per recv (the 64KiB DNS-class ceiling; the
            // kernel truncates anything larger and reports it).
            let mut buf = vec![0u8; 64 * 1024];
            match self.sock.recv_from(&mut buf) {
                Ok((n, _)) => {
                    buf.truncate(n);
                    return Ok(Some(Frame {
                        bytes: Bytes::from(buf),
                        iface: self.peer.clone(),
                        ts: std::time::SystemTime::now(),
                    }));
                }
                Err(e)
                    if e.raw_os_error() == Some(libc::EINTR)
                        || e.raw_os_error() == Some(libc::ECONNREFUSED)
                        || e.kind() == io::ErrorKind::WouldBlock =>
                {
                    // EINTR: try again. ECONNREFUSED: an ICMP
                    // unreachable for an earlier datagram — the reply
                    // this session waits for never follows one, keep
                    // the attempt running to its timeout. WouldBlock:
                    // a spurious wakeup raced the drain.
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}
