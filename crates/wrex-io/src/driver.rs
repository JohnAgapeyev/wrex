//! Raw Ethernet drivers: send/recv over Linux `AF_PACKET`, plus the
//! driver-level error type.

use std::io;
use std::time::{Duration, Instant};

use bytes::Bytes;
use thiserror::Error;

use crate::iface::IfTable;

/// One captured/sent frame with its origin interface and timestamp.
#[derive(Clone, Debug)]
pub struct Frame {
    pub bytes: Bytes,
    pub iface: String,
    pub ts: std::time::SystemTime,
}

/// Driver failures → CLI exit 1.
#[derive(Debug, Error)]
pub enum DriverError {
    #[error("permission denied: {hint}")]
    PermissionDenied { hint: String },
    #[error("interface `{wanted}` not found (available: {available})")]
    IfaceNotFound { wanted: String, available: String },
    #[error("raw sockets unsupported on this platform")]
    UnsupportedPlatform,
    #[error("io error: {source}")]
    Io { source: io::Error },
}

pub const PERMISSION_HINT: &str =
    "raw sockets require CAP_NET_RAW: run as root or `sudo setcap cap_net_raw+ep $(which wrex)`";

/// Send/recv contract for packet drivers (sans-IO; `wrex scan` in T2 builds
/// on this).
pub trait Driver: Send {
    /// Send one raw frame.
    fn send(&mut self, frame: &[u8]) -> io::Result<()>;
    /// Receive one frame before `deadline`; `Ok(None)` on timeout.
    fn recv(&mut self, deadline: Instant) -> io::Result<Option<Frame>>;
}

/// Linux `AF_PACKET` raw Ethernet driver: `socket(AF_PACKET, SOCK_RAW,
/// htons(ETH_P_ALL))` bound to `iface`, optional promiscuous mode.
///
/// Non-Linux builds compile this type (so callers can name it) but `open`
/// returns [`DriverError::UnsupportedPlatform`].
pub struct RawEthDriver {
    #[cfg(target_os = "linux")]
    fd: i32,
    #[cfg(target_os = "linux")]
    iface: String,
    #[cfg(not(target_os = "linux"))]
    _unsupported: (),
}

impl RawEthDriver {
    #[cfg(target_os = "linux")]
    pub fn open(iface: &str, promisc: bool, iftable: &IfTable) -> Result<Self, DriverError> {
        use std::ffi::CString;
        let _iface_c = CString::new(iface).map_err(|e| DriverError::Io {
            source: io::Error::other(e),
        })?;

        let entry = iftable
            .get(iface)
            .ok_or_else(|| DriverError::IfaceNotFound {
                wanted: iface.to_string(),
                available: iftable.names().join(", "),
            })?;
        let ifindex = entry.ifindex;

        // socket(2): AF_PACKET + SOCK_RAW requires CAP_NET_RAW.
        // SAFETY: `socket` is a simple libc syscall with integer args.
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                libc::htons(libc::ETH_P_ALL as u16) as i32,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            return Err(match err.raw_os_error() {
                Some(libc::EPERM) | Some(libc::EACCES) => DriverError::PermissionDenied {
                    hint: PERMISSION_HINT.to_string(),
                },
                _ => DriverError::Io { source: err },
            });
        }

        if promisc {
            // SAFETY: `setsockopt` writes into a stack-local `packet_mreq`;
            // `fd` is a valid descriptor owned by this function.
            let mut mreq = libc::packet_mreq {
                mr_ifindex: ifindex,
                mr_type: libc::PACKET_MR_PROMISC as u16,
                mr_alen: 0,
                mr_address: [0; 8],
            };
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_PACKET,
                    libc::PACKET_ADD_MEMBERSHIP,
                    &mut mreq as *mut libc::packet_mreq as *mut libc::c_void,
                    std::mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                let err = io::Error::last_os_error();
                // SAFETY: `close` releases the descriptor; no double-close:
                // `fd` is moved into no one else.
                unsafe { libc::close(fd) };
                return Err(DriverError::Io { source: err });
            }
        }

        // Bind to the interface via sockaddr_ll.
        let sockaddr = libc::sockaddr_ll {
            sll_family: libc::AF_PACKET as u16,
            sll_protocol: libc::htons(libc::ETH_P_ALL as u16),
            sll_ifindex: ifindex,
            sll_hatype: 0,
            sll_pkttype: 0,
            sll_halen: 0,
            sll_addr: [0; 8],
        };
        // SAFETY: `bind` reads `sockaddr`; `fd` is valid and owned here;
        // `CString` is NUL-terminated by construction... (not used; sockaddr
        // is a fixed struct).
        // (iface name is not needed beyond ifindex for bind)
        let ret = unsafe {
            libc::bind(
                fd,
                &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            // SAFETY: releasing our own descriptor; no aliasing.
            unsafe { libc::close(fd) };
            return Err(DriverError::Io { source: err });
        }

        Ok(Self {
            fd,
            iface: iface.to_string(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn open(_iface: &str, _promisc: bool, _iftable: &IfTable) -> Result<Self, DriverError> {
        Err(DriverError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
impl Driver for RawEthDriver {
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        // SAFETY: `sendto` reads only `frame`'s bytes for `frame.len()`;
        // `self.fd` is a valid descriptor owned by `Self`.
        let n = unsafe {
            libc::sendto(
                self.fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                std::ptr::null(),
                0,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENOBUFS) {
                // Single retry per plan (short-lived buffer pressure).
                // SAFETY: same as above.
                let n2 = unsafe {
                    libc::sendto(
                        self.fd,
                        frame.as_ptr() as *const libc::c_void,
                        frame.len(),
                        0,
                        std::ptr::null(),
                        0,
                    )
                };
                if n2 < 0 {
                    return Err(io::Error::last_os_error());
                }
                return Ok(());
            }
            return Err(err);
        }
        Ok(())
    }

    fn recv(&mut self, deadline: Instant) -> io::Result<Option<Frame>> {
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let remaining = deadline - now;
            let timeout_ms = remaining.as_millis().min(u32::MAX as u128) as u32;
            let mut pfd = libc::pollfd {
                fd: self.fd,
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
                // poll(2) may round down to 0ms for sub-ms remainders; treat
                // as timeout only if the deadline has actually passed.
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                continue;
            }
            // Frame buffer: Ethernet MTU headroom (plan: jumbo-safe 16 KiB).
            let mut buf = vec![0u8; 16 * 1024];
            // SAFETY: `recv` writes at most `buf.len()` bytes into `buf`;
            // `fd` is valid and owned by `Self`.
            let n =
                unsafe { libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
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
            // TODO(tranche-2): sll_pkttype filtering (loopback copies) via
            // recvmsg; plain recv is sufficient for tranche 1.
            return Ok(Some(Frame {
                bytes: Bytes::from(buf),
                iface: self.iface.clone(),
                ts: std::time::SystemTime::now(),
            }));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for RawEthDriver {
    fn drop(&mut self) {
        // SAFETY: `self.fd` is a valid descriptor uniquely owned by `Self`;
        // closing it here releases the resource exactly once.
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(target_os = "linux")]
pub fn poll_timeout_for(deadline: Instant) -> u32 {
    let remaining = deadline.saturating_duration_since(Instant::now());
    remaining.as_millis().min(u32::MAX as u128) as u32
}

// Silence dead-code warnings for the helper on non-test builds.
#[allow(dead_code)]
fn _unused_duration(_d: Duration) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_render() {
        let e = DriverError::PermissionDenied {
            hint: PERMISSION_HINT.to_string(),
        };
        assert!(e.to_string().contains("CAP_NET_RAW"), "{e}");
        let e = DriverError::IfaceNotFound {
            wanted: "eth9".into(),
            available: "lo, eth0".into(),
        };
        assert!(e.to_string().contains("eth9"), "{e}");
        assert!(e.to_string().contains("lo, eth0"), "{e}");
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn unsupported_platform() {
        let t = IfTable::from_sysfs(std::path::Path::new("/nonexistent")).unwrap_or_default();
        assert!(matches!(
            RawEthDriver::open("lo", false, &t),
            Err(DriverError::UnsupportedPlatform)
        ));
    }

    // Real-socket behavior is exercised by env-gated integration tests
    // (`WREX_DRIVER_TESTS=1`) in crates/wrex/tests.
    #[cfg(target_os = "linux")]
    #[test]
    fn iface_not_found_maps_error() {
        let t = IfTable::from_sysfs(std::path::Path::new("/nonexistent")).unwrap_or_default();
        let r = RawEthDriver::open("definitely-not-here", false, &t);
        match r {
            Err(DriverError::IfaceNotFound { .. }) => {}
            Err(DriverError::PermissionDenied { .. }) => {
                // sandboxed CI may lack CAP_NET_RAW: acceptable
            }
            Err(e) => panic!("expected iface-not-found or permission, got {e}"),
            Ok(_) => panic!("open should not succeed with an unknown iface"),
        }
    }
}
