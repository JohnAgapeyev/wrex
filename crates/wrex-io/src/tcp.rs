//! Kernel TCP client driver (tranche 4): a `std::net::TcpStream`
//! behind the [`Driver`] trait, with optional source-address binding,
//! deadline-bounded reads and a stream-close convention.
//!
//! Tranche 10a: both address families speak. `connect` accepts any
//! `SocketAddr` — `AF_INET` for v4, `AF_INET6` for v6 — with the same
//! stream conventions, source bind and deadline handling either way.
//!
//! ## Stream framing on a datagram trait
//!
//! [`Driver`] was shaped by packet drivers; a stream needs two
//! conventions, documented here as the contract for stream sessions:
//!
//! - `recv` returns **whatever bytes arrived before the deadline** as one
//!   frame (a chunk), never blocking past it;
//! - **orderly EOF arrives as an empty frame** (`bytes.len() == 0`).
//!   Real data chunks are never empty, so sessions read zero-length
//!   frames as "connection closed". A reset surfaces as an `io::Error`
//!   (connection reset), matching curl's behavior of failing the
//!   exchange.
//!
//! `send` writes everything (bounded write loop; requests are small).
//! Connect (with timeout and optional local bind) happens in
//! [`TcpDriver::connect`], driver-side, like the raw drivers' `open`.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::driver::{Driver, DriverError, Frame};

/// Hard cap on a single `send` (headers+body well under this; a cap
/// only exists so a wedged peer cannot hang the runtime forever).
const SEND_CAP: Duration = Duration::from_secs(30);

/// Kernel TCP client connection.
pub struct TcpDriver {
    stream: TcpStream,
    peer: String,
    /// Orderly EOF seen: further `recv` calls keep yielding the empty
    /// (EOF) frame; sessions must go idle on the first one.
    closed: bool,
}

impl TcpDriver {
    /// Connect to `peer`, optionally binding the local address first
    /// (`bind` with port 0 picks an ephemeral port; a nonzero port +
    /// `SO_REUSEADDR` gives deterministic source ports). `timeout`
    /// bounds the connect attempt.
    pub fn connect(
        peer: SocketAddr,
        bind: Option<SocketAddr>,
        timeout: Duration,
    ) -> Result<Self, DriverError> {
        let stream = tcp_connect(peer, bind, timeout)?;
        Ok(Self {
            stream,
            peer: peer.to_string(),
            closed: false,
        })
    }

    /// Wrap an ESTABLISHED stream (the proxy handshakes in
    /// [`crate::proxy`] pre-establish the wire and hand the stream
    /// over; `peer` names the DESTINATION for rendering).
    pub fn from_stream(stream: TcpStream, peer: impl Into<String>) -> Self {
        Self {
            stream,
            peer: peer.into(),
            closed: false,
        }
    }

    /// The connected peer address (rendering/diagnostics).
    pub fn peer(&self) -> &str {
        &self.peer
    }

    /// Poll for readability, then read one chunk. `Ok(None)` on
    /// timeout; an empty frame on orderly EOF.
    fn read_chunk(&mut self, deadline: Instant) -> io::Result<Option<Frame>> {
        if self.closed {
            return Ok(Some(eof_frame(&self.peer)));
        }
        let mut pfd = libc::pollfd {
            fd: self.stream.as_raw_fd(),
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
            if pfd.revents & (libc::POLLERR | libc::POLLHUP) != 0 && pfd.revents & libc::POLLIN == 0
            {
                // Hangup/error without readable data: read() below
                // surfaces the precise outcome (EOF or reset).
            }
            let mut buf = [0u8; 16 * 1024];
            // SAFETY: `read` writes at most `buf.len()` bytes into
            // `buf`; `fd` is valid and owned by `Self`.
            let n = unsafe {
                libc::read(
                    self.stream.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
                    _ => return Err(err),
                }
            }
            if n == 0 {
                self.closed = true;
                return Ok(Some(eof_frame(&self.peer)));
            }
            let chunk = Bytes::copy_from_slice(&buf[..n as usize]);
            return Ok(Some(Frame {
                bytes: chunk,
                iface: self.peer.clone(),
                ts: std::time::SystemTime::now(),
            }));
        }
    }
}

fn eof_frame(peer: &str) -> Frame {
    Frame {
        bytes: Bytes::new(),
        iface: peer.to_string(),
        ts: std::time::SystemTime::now(),
    }
}

impl Driver for TcpDriver {
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        let start = Instant::now();
        let mut written = 0usize;
        while written < frame.len() {
            // SAFETY: `write` reads only `frame[written..]`'s bytes;
            // `fd` is valid and owned by `Self`.
            let n = unsafe {
                libc::write(
                    self.stream.as_raw_fd(),
                    frame[written..].as_ptr() as *const libc::c_void,
                    frame.len() - written,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::EAGAIN) => {
                        if start.elapsed() > SEND_CAP {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "tcp send stalled",
                            ));
                        }
                        let mut pfd = libc::pollfd {
                            fd: self.stream.as_raw_fd(),
                            events: libc::POLLOUT,
                            revents: 0,
                        };
                        // SAFETY: `poll` writes into `pfd` (owned here).
                        let ready = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 1000) };
                        if ready < 0 {
                            let err = io::Error::last_os_error();
                            if err.raw_os_error() != Some(libc::EINTR) {
                                return Err(err);
                            }
                        }
                        continue;
                    }
                    _ => return Err(err),
                }
            }
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "tcp send wrote zero bytes",
                ));
            }
            written += n as usize;
        }
        Ok(())
    }

    fn recv(&mut self, deadline: Instant) -> io::Result<Option<Frame>> {
        self.read_chunk(deadline)
    }
}

/// Fill a `sockaddr_storage` with `addr` (either family), returning the
/// sockaddr length for the family (`bind`/`connect` check it against
/// the family field).
///
/// # Safety
///
/// SAFETY contract: `dst` must point to a live, fully-sized
/// `sockaddr_storage`; each arm writes only that family's sockaddr
/// layout, which is `<=` the storage's size.
unsafe fn fill_sockaddr(dst: &mut libc::sockaddr_storage, addr: SocketAddr) -> libc::socklen_t {
    // SAFETY: the caller contract above holds — `dst` is a live,
    // fully-sized storage; each arm writes only `size_of`-bounded
    // family layouts inside it and returns the exact family length.
    unsafe {
        match addr {
            SocketAddr::V4(a) => {
                let sa = (dst as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in>();
                (*sa).sin_family = libc::AF_INET as u16;
                (*sa).sin_port = a.port().to_be();
                (*sa).sin_addr = libc::in_addr {
                    s_addr: u32::from(*a.ip()).to_be(),
                };
                (*sa).sin_zero = [0; 8];
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
            }
            SocketAddr::V6(a) => {
                let sa = (dst as *mut libc::sockaddr_storage).cast::<libc::sockaddr_in6>();
                (*sa).sin6_family = libc::AF_INET6 as u16;
                (*sa).sin6_port = a.port().to_be();
                (*sa).sin6_flowinfo = 0;
                (*sa).sin6_addr = libc::in6_addr {
                    s6_addr: a.ip().octets(),
                };
                (*sa).sin6_scope_id = a.scope_id();
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
            }
        }
    }
}

/// Connect with a local bind and a bounded, nonblocking connect.
///
/// Uses the raw path (rather than `TcpStream::connect_timeout`) because
/// std offers no way to choose the local address for a client socket —
/// `--source-port` determinism needs `bind(2)`.
///
/// Tranche 10a: both families. The bind address must share the peer's
/// family (a v4 bind under a v6 connect is a pointed error).
pub(crate) fn tcp_connect(
    peer: SocketAddr,
    bind: Option<SocketAddr>,
    timeout: Duration,
) -> Result<TcpStream, DriverError> {
    if let Some(bind) = bind.as_ref().filter(|b| b.is_ipv4() != peer.is_ipv4()) {
        return Err(DriverError::Io {
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "bind address family mismatch: cannot bind {bind} for a {} peer",
                    if peer.is_ipv4() { "ipv4" } else { "ipv6" }
                ),
            ),
        });
    }
    let af: i32 = if peer.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: `socket` is a simple libc syscall with integer args.
    let fd = unsafe {
        libc::socket(
            af,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(DriverError::Io {
            source: io::Error::last_os_error(),
        });
    }

    let bail = |fd: i32, err: io::Error| -> DriverError {
        // SAFETY: releasing our own descriptor; no double-close.
        unsafe { libc::close(fd) };
        DriverError::Io { source: err }
    };

    if let Some(local) = bind {
        // Deterministic --source-port reuse: TIME_WAIT sockets must not
        // break redials.
        let one: libc::c_int = 1;
        // SAFETY: `setsockopt` reads `one`; `fd` is valid and owned here.
        let ret = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &one as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(bail(fd, io::Error::last_os_error()));
        }
        // SAFETY: all-POD struct — zeroing is a valid instance;
        // fill_sockaddr's caller contract holds (live, fully-sized).
        let mut sockaddr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        // SAFETY: fill_sockaddr contract (see fn docs) holds.
        let len = unsafe { fill_sockaddr(&mut sockaddr, local) };
        // SAFETY: `bind` reads `sockaddr` (filled for `local`'s family,
        // matching the socket's); `fd` is valid and owned here.
        let ret = unsafe {
            libc::bind(
                fd,
                &sockaddr as *const libc::sockaddr_storage as *const libc::sockaddr,
                len,
            )
        };
        if ret < 0 {
            return Err(bail(fd, io::Error::last_os_error()));
        }
    }

    // SAFETY: all-POD struct — zeroing is a valid instance;
    // fill_sockaddr's caller contract holds (live, fully-sized).
    let mut sockaddr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    // SAFETY: fill_sockaddr contract (see fn docs) holds.
    let len = unsafe { fill_sockaddr(&mut sockaddr, peer) };
    // SAFETY: `connect` reads `sockaddr` (filled for `peer`'s family);
    // `fd` is valid and owned here.
    let ret = unsafe {
        libc::connect(
            fd,
            &sockaddr as *const libc::sockaddr_storage as *const libc::sockaddr,
            len,
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(bail(fd, err));
        }
        // Nonblocking connect in flight: wait for POLLOUT or timeout.
        let deadline = Instant::now() + timeout;
        loop {
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLOUT,
                revents: 0,
            };
            // SAFETY: `poll` writes into `pfd` (stack-local, owned).
            let ready = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 250) };
            if ready < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(bail(fd, err));
            }
            if ready == 0 {
                if Instant::now() >= deadline {
                    return Err(bail(
                        fd,
                        io::Error::new(io::ErrorKind::TimedOut, "tcp connect timed out"),
                    ));
                }
                continue;
            }
            break;
        }
        // Connect result surfaces through SO_ERROR.
        let mut so_err: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: `getsockopt` writes into `so_err`; `fd` is valid.
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_err as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        if ret < 0 {
            return Err(bail(fd, io::Error::last_os_error()));
        }
        if so_err != 0 {
            return Err(bail(fd, io::Error::from_raw_os_error(so_err)));
        }
    }

    // Keep the socket nonblocking: `recv` polls before reading.
    // SAFETY: `from_raw_fd` hands the owned descriptor to std; no
    // double-close (we never touch `fd` again).
    Ok(unsafe { TcpStream::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    /// Plain sockets, no capabilities: these run everywhere (but not
    /// under Miri — no TCP shims there).
    #[test]
    #[cfg_attr(miri, ignore = "TCP sockets; not Miri-safe")]
    fn echo_roundtrip_and_eof() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = conn.read(&mut buf).unwrap();
            conn.write_all(&buf[..n]).unwrap();
            conn.shutdown(std::net::Shutdown::Write).unwrap();
        });

        let mut driver = TcpDriver::connect(addr, None, Duration::from_secs(5)).expect("connect");
        driver.send(b"ping").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let frame = driver.recv(deadline).unwrap().expect("chunk");
        assert_eq!(&frame.bytes[..], b"ping");
        // next read: orderly EOF as an empty frame
        let frame = driver.recv(deadline).unwrap().expect("eof frame");
        assert!(frame.bytes.is_empty(), "EOF must be an empty frame");
        // repeated recv after EOF keeps yielding the empty frame
        let frame = driver.recv(deadline).unwrap().expect("eof frame");
        assert!(frame.bytes.is_empty());
        server.join().unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore = "TCP sockets; not Miri-safe")]
    fn refused_maps_to_io_error() {
        // bind then drop: nothing listens here
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let err = match TcpDriver::connect(addr, None, Duration::from_secs(2)) {
            Ok(_) => panic!("connect must fail on a dead port"),
            Err(e) => e,
        };
        assert!(matches!(err, DriverError::Io { .. }), "{err}");
    }

    #[test]
    #[cfg_attr(miri, ignore = "TCP sockets; not Miri-safe")]
    fn recv_times_out_at_deadline() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _server = std::thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_secs(30));
            drop(conn);
        });
        let mut driver = TcpDriver::connect(addr, None, Duration::from_secs(5)).unwrap();
        driver.send(b"hello?").unwrap();
        let deadline = Instant::now() + Duration::from_millis(100);
        assert!(driver.recv(deadline).unwrap().is_none(), "timeout");
    }

    #[test]
    #[cfg_attr(miri, ignore = "TCP sockets; not Miri-safe")]
    fn source_port_bind_holds() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (conn, _) = listener.accept().unwrap();
            drop(conn);
        });
        let bind = SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 42424);
        let driver = TcpDriver::connect(addr, Some(bind), Duration::from_secs(5)).unwrap();
        assert_eq!(
            driver.stream.local_addr().unwrap().port(),
            42424,
            "--source-port must hold"
        );
        server.join().unwrap();
    }

    /// Tranche 10a: the same stream conventions over v6 (`::1`).
    #[test]
    #[cfg_attr(miri, ignore = "TCP sockets; not Miri-safe")]
    fn echo_roundtrip_and_eof_v6() {
        let listener = std::net::TcpListener::bind("[::1]:0").unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.is_ipv6());
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = conn.read(&mut buf).unwrap();
            conn.write_all(&buf[..n]).unwrap();
            conn.shutdown(std::net::Shutdown::Write).unwrap();
        });

        let mut driver = TcpDriver::connect(addr, None, Duration::from_secs(5)).expect("connect");
        driver.send(b"ping6").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let frame = driver.recv(deadline).unwrap().expect("chunk");
        assert_eq!(&frame.bytes[..], b"ping6");
        let frame = driver.recv(deadline).unwrap().expect("eof frame");
        assert!(frame.bytes.is_empty(), "EOF must be an empty frame");
        server.join().unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore = "TCP sockets; not Miri-safe")]
    fn refused_maps_to_io_error_v6() {
        let listener = std::net::TcpListener::bind("[::1]:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let err = match TcpDriver::connect(addr, None, Duration::from_secs(2)) {
            Ok(_) => panic!("connect must fail on a dead v6 port"),
            Err(e) => e,
        };
        assert!(matches!(err, DriverError::Io { .. }), "{err}");
    }

    /// A v4 bind under a v6 peer (and vice versa) is a pointed error,
    /// not a kernel EINVAL.
    #[test]
    fn bind_family_mismatch_is_rejected_up_front() {
        let v4_peer: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let v6_bind: SocketAddr = "[::1]:12345".parse().unwrap();
        let err = match TcpDriver::connect(v4_peer, Some(v6_bind), Duration::from_secs(1)) {
            Ok(_) => panic!("family mismatch must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("family mismatch"), "{err}");
    }

    /// `fill_sockaddr` writes the right layout per family (unit-level;
    /// no sockets).
    #[test]
    fn sockaddr_fill_per_family() {
        // SAFETY: all-POD struct — zeroing is a valid instance; the
        // fill contract holds (live, fully-sized storage).
        let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        // SAFETY: fill_sockaddr contract (see fn docs) holds.
        let len = unsafe { fill_sockaddr(&mut sa, "127.0.0.1:443".parse::<SocketAddr>().unwrap()) };
        assert_eq!(len as usize, std::mem::size_of::<libc::sockaddr_in>());
        // SAFETY: the storage holds a filled sockaddr_in (the len
        // assert above); reads stay inside that layout.
        unsafe {
            let p = (&sa as *const libc::sockaddr_storage).cast::<libc::sockaddr_in>();
            assert_eq!((*p).sin_family, libc::AF_INET as u16);
            let v4 = &*p;
            assert_eq!(v4.sin_port, 443u16.to_be());
            assert_eq!(
                v4.sin_addr.s_addr,
                u32::from(std::net::Ipv4Addr::LOCALHOST).to_be()
            );
        }

        // SAFETY: all-POD struct — zeroing is a valid instance; the
        // fill contract holds (live, fully-sized storage).
        let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        // SAFETY: fill_sockaddr contract (see fn docs) holds.
        let len =
            unsafe { fill_sockaddr(&mut sa, "[2001:db8::1]:853".parse::<SocketAddr>().unwrap()) };
        assert_eq!(len as usize, std::mem::size_of::<libc::sockaddr_in6>());
        // SAFETY: the storage holds a filled sockaddr_in6 (the len
        // assert above); reads stay inside that layout.
        unsafe {
            let p = (&sa as *const libc::sockaddr_storage).cast::<libc::sockaddr_in6>();
            assert_eq!((*p).sin6_family, libc::AF_INET6 as u16);
            let v6 = &*p;
            assert_eq!(v6.sin6_port, 853u16.to_be());
            assert_eq!(
                v6.sin6_addr.s6_addr,
                "2001:db8::1"
                    .parse::<std::net::Ipv6Addr>()
                    .unwrap()
                    .octets()
            );
        }
    }
}
