//! Raw drivers: Linux `AF_PACKET` send/recv for Ethernet frames and
//! `AF_INET`/`AF_PACKET` send/recv for IPv4 datagrams, plus the
//! driver-level error type.
//!
//! The receive paths are shared (`crate::rx`): poll + `recvfrom` with a
//! `sockaddr_ll`, skipping our own outgoing copies (`sll_pkttype ==
//! PACKET_OUTGOING`) — resolving the tranche-1 loopback-duplicate TODO
//! for both drivers at once.

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
///
/// `send`/`recv` payloads start at the driver's start layer: Ethernet
/// frames for [`RawEthDriver`], IPv4 datagrams for [`RawIpDriver`].
pub trait Driver: Send {
    /// Send one raw frame.
    fn send(&mut self, frame: &[u8]) -> io::Result<()>;
    /// Receive one frame before `deadline`; `Ok(None)` on timeout.
    fn recv(&mut self, deadline: Instant) -> io::Result<Option<Frame>>;
}

/// Map an `EPERM`/`EACCES` errno to the hinted error, else `Io`.
fn map_socket_err(err: io::Error) -> DriverError {
    match err.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => DriverError::PermissionDenied {
            hint: PERMISSION_HINT.to_string(),
        },
        _ => DriverError::Io { source: err },
    }
}

/// Resolve `iface` against `iftable`, mapping the not-found case.
fn resolve_iface<'t>(
    iface: &str,
    iftable: &'t IfTable,
) -> Result<&'t crate::iface::IfEntry, DriverError> {
    iftable
        .get(iface)
        .ok_or_else(|| DriverError::IfaceNotFound {
            wanted: iface.to_string(),
            available: iftable.names().join(", "),
        })
}

// ---------------------------------------------------------------------------
// RawEthDriver
// ---------------------------------------------------------------------------

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

        let entry = resolve_iface(iface, iftable)?;
        let ifindex = entry.ifindex;

        // socket(2): AF_PACKET + SOCK_RAW requires CAP_NET_RAW.
        // SAFETY: `open_packet_socket` owns its descriptor until Ok.
        let fd =
            unsafe { crate::rx::open_packet_socket(ifindex, libc::htons(libc::ETH_P_ALL as u16)) }
                .map_err(map_socket_err)?;

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
            // SAFETY: `fd` is a valid descriptor owned by `Self`.
            let Some(rx) = crate::rx::recv_raw(self.fd, deadline)? else {
                return Ok(None);
            };
            // Loopback and locally-routed frames come back as outgoing
            // copies; skip them (tranche-2 fix; the ingress copy is what
            // a listener should see).
            if rx.pkttype == libc::PACKET_OUTGOING {
                continue;
            }
            return Ok(Some(Frame {
                bytes: Bytes::from(rx.bytes),
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

// ---------------------------------------------------------------------------
// RawIpDriver
// ---------------------------------------------------------------------------

/// Linux raw-IP driver: kernel-routed IPv4 send, `AF_PACKET` receive.
///
/// - **Send** (`send`): `socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` with
///   `IP_HDRINCL`; the payload is a full IPv4 datagram (the destination
///   is taken from its header for routing) and the kernel handles
///   routing, ARP/next-hop resolution and fragmentation — that is what
///   makes scanning off-link targets work without a route engine.
/// - **Receive** (`recv`): an `AF_PACKET` socket bound to `iface` with
///   `ETH_P_IP`, yielding the IPv4 datagram (Ethernet header stripped,
///   outgoing copies skipped).
///
/// Non-Linux builds compile this type but `open` returns
/// [`DriverError::UnsupportedPlatform`].
pub struct RawIpDriver {
    #[cfg(target_os = "linux")]
    tx_fd: i32,
    #[cfg(target_os = "linux")]
    rx_fd: i32,
    #[cfg(target_os = "linux")]
    iface: String,
    #[cfg(not(target_os = "linux"))]
    _unsupported: (),
}

/// EtherType for IPv4 (Ethernet II).
const ETHERTYPE_IPV4: u16 = 0x0800;

impl RawIpDriver {
    #[cfg(target_os = "linux")]
    pub fn open(iface: &str, iftable: &IfTable) -> Result<Self, DriverError> {
        use std::ffi::CString;
        let _iface_c = CString::new(iface).map_err(|e| DriverError::Io {
            source: io::Error::other(e),
        })?;

        let entry = resolve_iface(iface, iftable)?;
        let ifindex = entry.ifindex;

        // TX: AF_INET raw socket; IP_HDRINCL hands the full header to us.
        // SAFETY: `socket` is a simple libc syscall with integer args.
        let tx_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
        if tx_fd < 0 {
            return Err(map_socket_err(io::Error::last_os_error()));
        }
        // SAFETY: `setsockopt` reads `one`; `tx_fd` is valid and owned here.
        let one: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                tx_fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &one as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            // SAFETY: releasing our own descriptor; no double-close.
            unsafe { libc::close(tx_fd) };
            return Err(DriverError::Io { source: err });
        }

        // RX: AF_PACKET on the same iface, IPv4 only.
        // SAFETY: `open_packet_socket` owns its descriptor until Ok.
        let rx_fd =
            match unsafe { crate::rx::open_packet_socket(ifindex, libc::htons(ETHERTYPE_IPV4)) } {
                Ok(fd) => fd,
                Err(err) => {
                    // SAFETY: releasing our own descriptor; no double-close.
                    unsafe { libc::close(tx_fd) };
                    return Err(map_socket_err(err));
                }
            };

        Ok(Self {
            tx_fd,
            rx_fd,
            iface: iface.to_string(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn open(_iface: &str, _iftable: &IfTable) -> Result<Self, DriverError> {
        Err(DriverError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
impl Driver for RawIpDriver {
    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        if frame.len() < 20 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "raw-ip send needs a full IPv4 datagram (>= 20 bytes)",
            ));
        }
        // Destination for sendto(2): the kernel routes on it (the header
        // destination matches for our packets).
        let dst = u32::from_be_bytes([frame[16], frame[17], frame[18], frame[19]]);
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 0, // raw sockets ignore the port
            sin_addr: libc::in_addr {
                s_addr: dst.to_be(),
            },
            sin_zero: [0; 8],
        };
        // SAFETY: `sendto` reads `frame`'s bytes and `addr` (owned here);
        // `self.tx_fd` is a valid descriptor owned by `Self`.
        let n = unsafe {
            libc::sendto(
                self.tx_fd,
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn recv(&mut self, deadline: Instant) -> io::Result<Option<Frame>> {
        loop {
            // SAFETY: `self.rx_fd` is a valid descriptor owned by `Self`.
            let Some(rx) = crate::rx::recv_raw(self.rx_fd, deadline)? else {
                return Ok(None);
            };
            // Skip our own egress copies (kernel-injected sends on `lo`
            // appear as outgoing before the stack processes them).
            if rx.pkttype == libc::PACKET_OUTGOING {
                continue;
            }
            // Strip the Ethernet header: frames start at IPv4 for this
            // driver (bound ETH_P_IP, but verify the ethertype).
            let bytes = rx.bytes;
            if bytes.len() < 14 {
                continue; // runt
            }
            if u16::from_be_bytes([bytes[12], bytes[13]]) != ETHERTYPE_IPV4 {
                continue;
            }
            return Ok(Some(Frame {
                bytes: Bytes::from(bytes[14..].to_vec()),
                iface: self.iface.clone(),
                ts: std::time::SystemTime::now(),
            }));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for RawIpDriver {
    fn drop(&mut self) {
        // SAFETY: both descriptors are valid and uniquely owned by `Self`;
        // closing them here releases each resource exactly once.
        unsafe {
            libc::close(self.tx_fd);
            libc::close(self.rx_fd);
        }
    }
}

// ---------------------------------------------------------------------------
// RawIpv6Driver
// ---------------------------------------------------------------------------

/// EtherType for IPv6 (Ethernet II).
const ETHERTYPE_IPV6: u16 = 0x86dd;

/// Linux raw-IPv6 driver (tranche 7b): `AF_PACKET` frame injection for
/// send, `AF_PACKET` receive bound to `ETH_P_IPV6`.
///
/// Per the T7a-pass decision there is no `IPV6_HDRINCL` (the kernel
/// rejects full v6 headers on `AF_INET6` raw sockets), so **send**
/// synthesizes a full Ethernet frame (`dst` = interface MAC, `src` =
/// interface MAC, ethertype `0x86dd`) and injects it through the same
/// `AF_PACKET` socket — the local stack processes it like ingress. This
/// is the `lo`/on-link contract; off-link next-hop (NDP) resolution is
/// a deliberate deferral.
///
/// - **Receive** (`recv`): the same `AF_PACKET` socket bound to
///   `ETH_P_IPV6`, yielding the IPv6 datagram (Ethernet header stripped,
///   ethertype verified, outgoing copies skipped).
///
/// Non-Linux builds compile this type but `open` returns
/// [`DriverError::UnsupportedPlatform`].
pub struct RawIpv6Driver {
    #[cfg(target_os = "linux")]
    fd: i32,
    #[cfg(target_os = "linux")]
    iface: String,
    #[cfg(target_os = "linux")]
    mac: [u8; 6],
    #[cfg(not(target_os = "linux"))]
    _unsupported: (),
}

impl RawIpv6Driver {
    #[cfg(target_os = "linux")]
    pub fn open(iface: &str, iftable: &IfTable) -> Result<Self, DriverError> {
        use std::ffi::CString;
        let _iface_c = CString::new(iface).map_err(|e| DriverError::Io {
            source: io::Error::other(e),
        })?;

        let entry = resolve_iface(iface, iftable)?;
        let ifindex = entry.ifindex;

        // One AF_PACKET socket: SOCK_RAW bound to ETH_P_IPV6 serves both
        // directions (TX injects full frames; the protocol filter is the
        // RX side).
        // SAFETY: `open_packet_socket` owns its descriptor until Ok.
        let fd = unsafe { crate::rx::open_packet_socket(ifindex, libc::htons(ETHERTYPE_IPV6)) }
            .map_err(map_socket_err)?;

        Ok(Self {
            fd,
            iface: iface.to_string(),
            mac: entry.mac,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn open(_iface: &str, _iftable: &IfTable) -> Result<Self, DriverError> {
        Err(DriverError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
impl Driver for RawIpv6Driver {
    fn send(&mut self, datagram: &[u8]) -> io::Result<()> {
        if datagram.len() < 40 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "raw-ipv6 send needs a full IPv6 datagram (>= 40 bytes)",
            ));
        }
        // Synthesize the Ethernet header (version nibble already 6 in the
        // datagram; ethertype 0x86dd). dst/src = the interface MAC: the
        // injected frame is processed by the local stack like ingress on
        // that interface (the lo/on-link contract; off-link NDP
        // resolution is a deferral).
        let mac = self.mac;
        let mut frame = Vec::with_capacity(14 + datagram.len());
        frame.extend_from_slice(&mac);
        frame.extend_from_slice(&mac);
        frame.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        frame.extend_from_slice(datagram);
        // SAFETY: `sendto` reads only `frame`'s bytes; `self.fd` is a
        // valid descriptor owned by `Self`.
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
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn recv(&mut self, deadline: Instant) -> io::Result<Option<Frame>> {
        loop {
            // SAFETY: `fd` is a valid descriptor owned by `Self`.
            let Some(rx) = crate::rx::recv_raw(self.fd, deadline)? else {
                return Ok(None);
            };
            // Skip our own egress copies (kernel-injected sends on `lo`
            // appear as outgoing before the stack processes them).
            if rx.pkttype == libc::PACKET_OUTGOING {
                continue;
            }
            let bytes = rx.bytes;
            if bytes.len() < 14 {
                continue; // runt
            }
            if u16::from_be_bytes([bytes[12], bytes[13]]) != ETHERTYPE_IPV6 {
                continue;
            }
            return Ok(Some(Frame {
                bytes: Bytes::from(bytes[14..].to_vec()),
                iface: self.iface.clone(),
                ts: std::time::SystemTime::now(),
            }));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for RawIpv6Driver {
    fn drop(&mut self) {
        // SAFETY: the descriptor is valid and uniquely owned by `Self`;
        // closing it here releases the resource exactly once.
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(target_os = "linux")]
pub fn poll_timeout_for(deadline: Instant) -> u32 {
    let remaining = deadline.saturating_duration_since(Instant::now());
    remaining.as_millis().min(u32::MAX as u128) as u32
}

// Silence dead-code warnings for the helpers on non-test builds.
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
        assert!(matches!(
            RawIpDriver::open("lo", &t),
            Err(DriverError::UnsupportedPlatform)
        ));
        assert!(matches!(
            RawIpv6Driver::open("lo", &t),
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
        let r = RawIpDriver::open("definitely-not-here2", &t);
        match r {
            Err(DriverError::IfaceNotFound { .. }) => {}
            Err(DriverError::PermissionDenied { .. }) => {}
            Err(e) => panic!("expected iface-not-found or permission, got {e}"),
            Ok(_) => panic!("open should not succeed with an unknown iface"),
        }
        let r = RawIpv6Driver::open("definitely-not-here3", &t);
        match r {
            Err(DriverError::IfaceNotFound { .. }) => {}
            Err(DriverError::PermissionDenied { .. }) => {}
            Err(e) => panic!("expected iface-not-found or permission, got {e}"),
            Ok(_) => panic!("open should not succeed with an unknown iface"),
        }
    }
}
