//! Shared AF_PACKET receive path (Linux): poll + `recvfrom` with a
//! `sockaddr_ll` so the driver can see `sll_pkttype` and skip its own
//! outgoing copies (the tranche-1 TODO: loopback and locally-routed
//! frames otherwise come back as phantom duplicates).
//!
//! Tranche 1 used plain `recv`; the pkttype filter is a tranche-2 fix
//! shared by [`crate::driver::RawEthDriver`] and
//! [`crate::driver::RawIpDriver`].

use std::io;
use std::time::Instant;

#[cfg(test)]
use std::time::Duration;

/// Receive buffer headroom: Ethernet MTU + jumbo margin (16 KiB, the
/// tranche-1 recv sizing).
const RX_BUF: usize = 16 * 1024;

/// Open an `AF_PACKET`/`SOCK_RAW` socket bound to `ifindex` for protocol
/// `protocol_be` (ethertype in network byte order, e.g.
/// `htons(ETH_P_ALL)` or `htons(ETH_P_IP)`).
///
/// The receive buffer is grown first (best-effort, see
/// [`TAP_RCVBUF_BYTES`]): the kernel default
/// (`net.core.rmem_default`, typically 212992 ≈ 222 frames at the
/// ~960-byte `skb` truesize of a small frame) silently DROPS the tail
/// of any reply burst that outpaces the drain loop — a 256-probe
/// in-flight scan lost exactly 34 replies (256 − 222) and every loss
/// paid the double 1s timeout, the perf-diff scan finding.
///
/// SAFETY: caller owns the returned descriptor; `close` releases it.
pub(crate) unsafe fn open_packet_socket(ifindex: i32, protocol_be: u16) -> io::Result<i32> {
    // SAFETY: `socket` is a simple libc syscall with integer args.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, protocol_be as i32) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `setsockopt` reads `size`; `fd` is a valid descriptor
    // owned by this function.
    let size = TAP_RCVBUF_BYTES;
    let forced = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUFFORCE,
            &size as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    } == 0;
    if !forced {
        // SO_RCVBUFFORCE needs CAP_NET_ADMIN; plain SO_RCVBUF is capped
        // by net.core.rmem_max — best-effort either way, never fail the
        // open over a buffer knob (the kernel default still works, just
        // drop-prone under bursts).
        // SAFETY: as above.
        let _ = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
    }
    let sockaddr = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: protocol_be,
        sll_ifindex: ifindex,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    // SAFETY: `bind` reads `sockaddr`; `fd` is a valid descriptor owned
    // by this function.
    let ret = unsafe {
        libc::bind(
            fd,
            &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        // SAFETY: releasing our own descriptor; no double-close.
        unsafe { libc::close(fd) };
        return Err(err);
    }
    Ok(fd)
}

/// Tap receive-buffer request: ~8 MiB ≈ 8000 frames of headroom —
/// covers a `--concurrent`-bounded burst window (both directions land
/// on the tap on loopback) many times over.
const TAP_RCVBUF_BYTES: libc::c_int = 8 * 1024 * 1024;

/// One received frame's bytes plus its `sll_pkttype`.
#[derive(Debug)]
pub(crate) struct RxFrame {
    pub bytes: Vec<u8>,
    /// `PACKET_HOST`, `PACKET_OUTGOING`, … as reported by the kernel.
    pub pkttype: u8,
}

/// Receive one frame before `deadline` (`Ok(None)` on timeout), polling
/// with the deadline as the poll timeout so partial waits are honored.
///
/// Does NOT skip outgoing copies; callers decide (both current drivers
/// skip them — kept explicit so the eth driver could someday opt out).
pub(crate) fn recv_raw(fd: i32, deadline: Instant) -> io::Result<Option<RxFrame>> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        let remaining = deadline - now;
        let timeout_ms = remaining.as_millis().min(u32::MAX as u128) as u32;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `poll` writes into `pfd` (stack-local, owned here) and
        // reads only its size argument; `fd` is valid.
        let ready = unsafe {
            libc::poll(
                &mut pfd as *mut libc::pollfd,
                1,
                timeout_ms.min(i32::MAX as u32) as i32,
            )
        };
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if ready == 0 {
            // poll(2) may round down to 0ms for sub-ms remainders; only
            // treat as timeout if the deadline has actually passed.
            if Instant::now() >= deadline {
                return Ok(None);
            }
            continue;
        }
        let mut buf = vec![0u8; RX_BUF];
        // SAFETY: `sockaddr_ll` is an all-POD struct — zeroing it is
        // a valid, defined instance (recvfrom overwrites the tail).
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut alen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        // SAFETY: `recvfrom` writes at most `buf.len()` bytes into `buf`
        // and `sockaddr_ll`-sized metadata into `addr`; `fd` is valid.
        let n = unsafe {
            libc::recvfrom(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut addr as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                &mut alen,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            continue;
        }
        buf.truncate(n as usize);
        return Ok(Some(RxFrame {
            bytes: buf,
            pkttype: addr.sll_pkttype,
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    /// recv_raw is the raw-syscall core both drivers sit on; these tests
    /// exercise its loop logic (poll/recv, truncation, deadline) without
    /// CAP_NET_RAW by using a plain UDP socket as the descriptor.
    #[cfg_attr(miri, ignore = "libc socket syscalls; not Miri-safe")]
    #[test]
    fn recv_raw_reads_and_truncates_a_datagram() {
        // A bound UDP socket: send ourselves one datagram, then recv_raw
        // must return exactly its bytes (not the 16 KiB buffer).
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let dst = sock.local_addr().expect("local addr");
        sock.connect(dst).expect("connect");
        sock.send(b"wrex-rx-probe").expect("send");
        let fd = sock.as_raw_fd();
        let deadline = Instant::now() + Duration::from_secs(5);
        let frame = recv_raw(fd, deadline)
            .expect("recv_raw io")
            .expect("the datagram must arrive");
        assert_eq!(frame.bytes, b"wrex-rx-probe");
        // Self-addressed UDP: the kernel wrote a sockaddr_in, so the
        // pkttype byte (past its 16 bytes) reads back zeroed.
        assert_eq!(frame.pkttype, 0);
    }

    #[cfg_attr(miri, ignore = "libc socket syscalls; not Miri-safe")]
    #[test]
    fn recv_raw_times_out_cleanly_at_the_deadline() {
        // A bound socket nobody sends to: poll must hit the deadline and
        // the loop must exit Ok(None) — never a spurious error.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
        let fd = sock.as_raw_fd();
        let deadline = Instant::now() + Duration::from_millis(50);
        let got = recv_raw(fd, deadline).expect("recv_raw io");
        assert!(got.is_none(), "quiet socket must time out: {got:?}");
        // The deadline is honored even when already in the past.
        let got = recv_raw(fd, Instant::now()).expect("recv_raw io");
        assert!(got.is_none(), "past deadline must not read: {got:?}");
    }

    #[cfg_attr(miri, ignore = "libc socket syscalls; not Miri-safe")]
    #[test]
    fn open_packet_socket_rejects_a_bogus_ifindex() {
        // Unprivileged: socket() itself fails EPERM. Under root (CI): the
        // bind to ifindex -1 fails EINVAL. Either way: Err, and the fd
        // must not leak (verified implicitly — no descriptor exhaustion).
        let eth_p_all = u16::to_be(libc::ETH_P_ALL as u16);
        // SAFETY: the callee owns its descriptor (never leaks: it
        // closes on bind failure); we assert only the Err shape.
        let got = unsafe { open_packet_socket(-1, eth_p_all) };
        assert!(got.is_err(), "bogus ifindex must not open: {got:?}");
    }
}
