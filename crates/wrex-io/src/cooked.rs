//! Linux cooked-capture driver (tranche 23a): the `capture -i any`
//! receive path — `AF_PACKET`/`SOCK_DGRAM` bound to `ifindex 0` (any
//! interface), with a 16-byte Linux SLL (v1) pseudo-header synthesized
//! from each frame's `sockaddr_ll` (the libpcap trick): pkttype/hatype/
//! halen from the kernel metadata, the 8-byte address region, the
//! ethertype from `sll_protocol`. The stored pcap carries
//! `LINKTYPE_LINUX_SLL`, so the file is what `tcpdump -i any` would
//! have written (the committed fixtures agree byte-for-byte).
//!
//! Receive only: cooked capture is a tap view, there is no wire to send
//! on (`-i any` is not an interface) — `send` stays pointedly
//! unsupported (the `Driver` contract's `send` returns `EOPNOTSUPP`).
//!
//! SAFETY: this module is in wrex-io, the only crate permitted `unsafe`;
//! every block carries a `// SAFETY:` comment.

use bytes::Bytes;
use std::io;
use std::time::Instant;

use crate::driver::{Driver, DriverError, Frame};
use crate::iface::IfTable;

/// Resolve `any` → ifindex 0; a real name → its index.
pub(crate) fn cooked_ifindex(iface: &str, iftable: &IfTable) -> Result<i32, DriverError> {
    if iface == "any" {
        return Ok(0);
    }
    let entry = iftable
        .get(iface)
        .ok_or_else(|| DriverError::IfaceNotFound {
            wanted: iface.to_string(),
            available: iftable.names().join(", "),
        })?;
    Ok(entry.ifindex)
}

/// The Linux cooked-capture (SLL v1) driver.
///
/// Non-Linux builds compile this type but `open` returns an error
/// (Linux `AF_PACKET`; needs CAP_NET_RAW like every packet socket).
pub struct CookedDriver {
    fd: i32,
    iface: String,
}

/// The synthesized SLL v1 header length.
pub const SLL_HEADER_LEN: usize = 16;

impl CookedDriver {
    /// Open the cooked tap on `iface` (`any` = every interface, ifindex 0).
    /// Promiscuous mode is per-interface and has no meaning on `any` —
    /// it is silently ignored (the tcpdump behavior).
    pub fn open(iface: &str, _promisc: bool, iftable: &IfTable) -> Result<Self, DriverError> {
        let ifindex = cooked_ifindex(iface, iftable)?;
        // SOCK_DGRAM: the kernel strips the link-layer header and hands
        // us a cooked (SLL) view. socket(2): AF_PACKET needs CAP_NET_RAW
        // for both socket types.
        // SAFETY: `open_packet_socket_type` owns its descriptor until Ok.
        let fd = unsafe {
            crate::rx::open_packet_socket_typed(
                ifindex,
                libc::htons(libc::ETH_P_ALL as u16),
                libc::SOCK_DGRAM,
            )
        }
        .map_err(map_cooked_err)?;
        Ok(Self {
            fd,
            iface: iface.to_string(),
        })
    }
}

/// The env gate for the privileged socket ground truth (the driver-tests
/// precedent: raw sockets need CAP_NET_RAW).
pub const DRIVER_TESTS_ENV: &str = "WREX_DRIVER_TESTS";

fn map_cooked_err(err: io::Error) -> DriverError {
    match err.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => DriverError::PermissionDenied {
            hint: "cooked capture (AF_PACKET) requires CAP_NET_RAW".to_string(),
        },
        _ => DriverError::Io { source: err },
    }
}

/// Synthesize the SLL v1 header from a `sockaddr_ll` (libpcap's own
/// mapping, pinned against the committed `tcpdump -i any` fixtures).
pub(crate) fn synthesize_sll(addr: &libc::sockaddr_ll) -> [u8; SLL_HEADER_LEN] {
    let mut hdr = [0u8; SLL_HEADER_LEN];
    // pkttype/hatype/halen: u16 big-endian (network order).
    hdr[0..2].copy_from_slice(&(addr.sll_pkttype as u16).to_be_bytes());
    hdr[2..4].copy_from_slice(&addr.sll_hatype.to_be_bytes());
    hdr[4..6].copy_from_slice(&(addr.sll_halen as u16).to_be_bytes());
    hdr[6..14].copy_from_slice(&addr.sll_addr);
    // The encapsulated ethertype: the kernel hands `sll_protocol` in
    // network order already (same bytes, whatever the host endianness).
    hdr[14..16].copy_from_slice(&addr.sll_protocol.to_ne_bytes());
    hdr
}

impl Driver for CookedDriver {
    fn send(&mut self, _frame: &[u8]) -> io::Result<()> {
        // `-i any` is a tap view over many interfaces, not a wire —
        // pointedly unsupported (send through a real interface).
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }

    fn recv(&mut self, deadline: Instant) -> io::Result<Option<Frame>> {
        loop {
            // SAFETY: `fd` is a valid descriptor owned by `Self`.
            let Some(rx) = crate::rx::recv_raw_with_addr(self.fd, deadline)? else {
                return Ok(None);
            };
            // Outgoing copies (loopback + locally-routed) are phantom
            // duplicates on a tap; skip them (the eth driver's rule).
            if rx.addr.sll_pkttype == libc::PACKET_OUTGOING {
                continue;
            }
            let sll = synthesize_sll(&rx.addr);
            let mut bytes = Vec::with_capacity(sll.len() + rx.bytes.len());
            bytes.extend_from_slice(&sll);
            bytes.extend_from_slice(&rx.bytes);
            return Ok(Some(Frame {
                bytes: Bytes::from(bytes),
                iface: self.iface.clone(),
                ts: std::time::SystemTime::now(),
            }));
        }
    }
}

impl Drop for CookedDriver {
    fn drop(&mut self) {
        // SAFETY: `self.fd` is a valid descriptor uniquely owned by
        // `Self`; closing it here releases the resource exactly once.
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iface::IfTable;

    /// The synthesized header pinned against the committed tcpdump
    /// `tcpdump -i any` fixture bytes (pkttype outgoing=4, hatype ether=1,
    /// halen 6, the veth MAC + 2 pad, protocol 0x86dd).
    #[test]
    fn sll_synthesis_matches_fixture() {
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_pkttype = 4;
        addr.sll_hatype = 1;
        addr.sll_halen = 6;
        addr.sll_addr = [0xa6, 0xb8, 0x9e, 0x11, 0xf7, 0x85, 0, 0];
        addr.sll_protocol = u16::to_be(0x86dd);
        let hdr = synthesize_sll(&addr);
        assert_eq!(
            hdr,
            [
                0x00, 0x04, 0x00, 0x01, 0x00, 0x06, 0xa6, 0xb8, 0x9e, 0x11, 0xf7, 0x85, 0x00, 0x00,
                0x86, 0xdd
            ]
        );
    }

    /// Unprivileged: `open` must fail EPERM/permission (the same gate as
    /// every packet socket); under the env gate (sudo CI) it must succeed
    /// on `any` and produce dissectable SLL frames.
    #[cfg_attr(miri, ignore = "libc socket syscalls; not Miri-safe")]
    #[test]
    fn cooked_open_privilege_gate() {
        let table = IfTable::from_system().expect("reading interfaces");
        let gated = std::env::var(DRIVER_TESTS_ENV).is_ok_and(|v| v == "1");
        match CookedDriver::open("any", false, &table) {
            Ok(_drv) => {
                // The open is the contract here (capability + ifindex 0
                // bind); the recv mechanics are pinned by the env-gated
                // capture roundtrip — a quiet-tap assert here races the
                // parallel socket suites sharing `lo`.
                assert!(gated, "cooked open on `any` should need the env gate");
            }
            Err(e) => {
                assert!(!gated, "gated run must open: {e}");
                assert!(
                    matches!(e, DriverError::PermissionDenied { .. }),
                    "ungated open must fail on permissions, got: {e}"
                );
            }
        }
    }

    /// `any` resolves to ifindex 0 without touching the table.
    #[test]
    fn any_resolves_to_zero() {
        let table = IfTable::from_system().expect("reading interfaces");
        assert_eq!(cooked_ifindex("any", &table).unwrap(), 0);
        assert!(cooked_ifindex("no-such-iface", &table).is_err());
    }
}
