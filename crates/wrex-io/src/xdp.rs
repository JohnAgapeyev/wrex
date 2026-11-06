//! Kernel eBPF plumbing (tranche 23b): the raw `bpf(2)` loader (maps,
//! programs), the netlink XDP attach, and the AF_XDP socket (XSK) —
//! the compiled-datapath's userspace half. ADR-0005 records the loader
//! decision: hand-rolled `bpf()` syscalls over aya (the generated
//! programs are plain instruction streams — no ELF, no relocations —
//! so the loader is a handful of structs, and the committed deviation
//! from the roadmap's aya recommendation rides the "the codegen owns
//! the semantics, the loader is plumbing" line).
//!
//! SAFETY: this module is in wrex-io, the only crate permitted
//! `unsafe`; every block carries a `// SAFETY:` comment.

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use bytes::Bytes;

use crate::driver::{Driver, DriverError, Frame};

// --- bpf(2) plumbing --------------------------------------------------------

/// `SYS_bpf` (321 x86_64, 280 aarch64).
#[cfg(target_arch = "x86_64")]
const SYS_BPF: libc::c_long = 321;
#[cfg(target_arch = "aarch64")]
const SYS_BPF: libc::c_long = 280;

/// linux/bpf.h command ids.
const BPF_MAP_CREATE: libc::c_int = 0;
const BPF_MAP_UPDATE_ELEM: libc::c_int = 2;
const BPF_PROG_LOAD: libc::c_int = 5;

/// `enum bpf_map_type` — values COPIED FROM /usr/include/linux/bpf.h
/// (count the enum, never trust memory: the tranche's live runs
/// caught a hand-marshaled 42 for the XSKMAP — an unregistered type
/// on every kernel — behind an EINVAL the kernel story initially
/// took the blame for; the header says 17).
pub const BPF_MAP_TYPE_HASH: u32 = 1;
pub const BPF_MAP_TYPE_XSKMAP: u32 = 17;
/// `enum bpf_prog_type`: XDP = 6.
pub const BPF_PROG_TYPE_XDP: u32 = 6;

/// The `bpf_attr` union as a byte buffer — every command writes its
/// documented `include/uapi/linux/bpf.h` offsets (no struct-packing
/// guesswork, no libc dependency on the union).
#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct BpfAttr([u8; 128]);

impl BpfAttr {
    fn zeroed() -> Self {
        Self([0; 128])
    }
    fn u32_at(&mut self, off: usize, v: u32) {
        self.0[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn u64_at(&mut self, off: usize, v: u64) {
        self.0[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }
}

fn bpf_sys(cmd: libc::c_int, attr: &BpfAttr) -> io::Result<libc::c_long> {
    // SAFETY: `syscall` reads `attr` for `size_of::<BpfAttr>()` bytes
    // — plain integer arguments, no userspace pointers the kernel
    // writes through.
    let ret = unsafe { libc::syscall(SYS_BPF, cmd, attr as *const BpfAttr, 128) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ret)
}

/// A created map (owns its fd).
pub struct BpfMap {
    fd: i32,
}

impl BpfMap {
    /// `BPF_MAP_CREATE` (map_type @0, key_size @4, value_size @8,
    /// max_entries @12).
    pub fn create(kind: u32, key_size: u32, value_size: u32, max_entries: u32) -> io::Result<Self> {
        let mut attr = BpfAttr::zeroed();
        attr.u32_at(0, kind);
        attr.u32_at(4, key_size);
        attr.u32_at(8, value_size);
        attr.u32_at(12, max_entries);
        let fd = bpf_sys(BPF_MAP_CREATE, &attr)?;
        Ok(Self { fd: fd as i32 })
    }

    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// `BPF_MAP_UPDATE_ELEM` (map_fd @0, key ptr @8, value ptr @16,
    /// flags @24).
    pub fn update(&self, key: &[u8], value: &[u8]) -> io::Result<()> {
        let mut attr = BpfAttr::zeroed();
        attr.u32_at(0, self.fd as u32);
        attr.u64_at(8, key.as_ptr() as u64);
        attr.u64_at(16, value.as_ptr() as u64);
        attr.u32_at(24, 0);
        bpf_sys(BPF_MAP_UPDATE_ELEM, &attr)?;
        Ok(())
    }
}

impl Drop for BpfMap {
    fn drop(&mut self) {
        // SAFETY: uniquely owned descriptor; close releases it once.
        unsafe { libc::close(self.fd) };
    }
}

/// A loaded program (owns its fd).
pub struct BpfProgram {
    fd: i32,
}

impl BpfProgram {
    /// `BPF_PROG_LOAD` for an XDP program. The compiled stream's
    /// LD_IMM64 pseudo-fd references (the map INDEX) are rewritten to
    /// the real fds here — the loader's one relocation duty.
    pub fn load_xdp(insns: &[u64], map_fds: &[i32]) -> io::Result<Self> {
        let mut owned: Vec<u64> = insns.to_vec();
        let mut i = 0;
        while i + 1 < owned.len() {
            let raw = owned[i];
            let src = ((raw >> 12) & 0xf) as u8;
            if (raw & 0xff) == 0x18 && src == 1 {
                // LD_IMM64 | BPF_PSEUDO_MAP_FD: imm carries the map index.
                let idx = ((raw >> 32) & 0xffff_ffff) as usize;
                let fd = map_fds
                    .get(idx)
                    .copied()
                    .ok_or_else(|| io::Error::other("program references an unprovided map"))?;
                owned[i] = (raw & 0xffff_ffff_0000_00ff) | ((fd as u64) << 32);
            }
            i += 1;
        }
        let license = b"GPL\0";
        let mut attr = BpfAttr::zeroed();
        // PROG_LOAD offsets: prog_type @0, insn_cnt @4, insns @8,
        // license @16, log_level @24, log_size @28, log_buf @32,
        // kern_version @40, prog_flags @44.
        attr.u32_at(0, BPF_PROG_TYPE_XDP);
        attr.u32_at(4, owned.len() as u32);
        attr.u64_at(8, owned.as_ptr() as u64);
        attr.u64_at(16, license.as_ptr() as u64);
        // No log buffer: the errno carries the failure class; the
        // verifier refusal surfaces as EACCES/EINVAL with the pointed
        // CLI note (the compile-time discipline keeps programs clean —
        // guarded loads, no loops).
        attr.u32_at(24, 0);
        attr.u32_at(28, 0);
        attr.u64_at(32, 0);
        attr.u32_at(40, 0);
        attr.u32_at(44, 0);
        let fd = bpf_sys(BPF_PROG_LOAD, &attr)?;
        Ok(Self { fd: fd as i32 })
    }

    pub fn fd(&self) -> i32 {
        self.fd
    }
}

impl Drop for BpfProgram {
    fn drop(&mut self) {
        // SAFETY: uniquely owned descriptor; close releases it once.
        unsafe { libc::close(self.fd) };
    }
}

// --- netlink XDP attach ------------------------------------------------------

const NLMSG_ERROR: u16 = 2;
const RTM_NEWLINK: u16 = 16;
const IFLA_XDP: u16 = 43;
const IFLA_XDP_FD: u16 = 1;
const IFLA_XDP_FLAGS: u16 = 3;
/// `XDP_FLAGS_SKB_MODE` — generic XDP (every interface, lo/veth
/// included; native mode is the perf path).
const XDP_FLAGS_SKB_MODE: u32 = 2;

#[repr(C)]
struct NlMsgHdr {
    len: u32,
    ty: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}

#[repr(C)]
struct IfInfoMsg {
    family: u8,
    _pad: u8,
    ifi_type: u16,
    index: i32,
    flags: u32,
    change: u32,
}

fn nlattr(ty: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len());
    let len = (4 + payload.len()) as u16;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&ty.to_le_bytes());
    out.extend_from_slice(payload);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

/// Attach (fd ≥ 0) or detach (fd = -1) an XDP program on `ifindex`,
/// generic (SKB) mode. Privilege honesty: `bpf()` and the netlink
/// attach check capabilities against the INITIAL user namespace —
/// the `unshare -Urn` sandbox trick unlocks neither.
pub fn xdp_attach(ifindex: i32, prog_fd: i32) -> io::Result<()> {
    let mut xdp_nested = Vec::new();
    xdp_nested.extend_from_slice(&nlattr(IFLA_XDP_FD, &prog_fd.to_le_bytes()));
    xdp_nested.extend_from_slice(&nlattr(IFLA_XDP_FLAGS, &XDP_FLAGS_SKB_MODE.to_le_bytes()));
    let xdp_attr = nlattr(IFLA_XDP, &xdp_nested);

    let payload = std::mem::size_of::<IfInfoMsg>() + xdp_attr.len();
    let total = std::mem::size_of::<NlMsgHdr>() + payload;
    let mut buf = vec![0u8; total];
    // SAFETY: writing into a zeroed, owned buffer through typed
    // references at computed offsets within its bounds.
    unsafe {
        let hdr = &mut *(buf.as_mut_ptr() as *mut NlMsgHdr);
        hdr.len = total as u32;
        hdr.ty = RTM_NEWLINK;
        hdr.flags = 0x1; // NLM_F_REQUEST
        hdr.seq = 1;
        let ifi = &mut *(buf.as_mut_ptr().add(std::mem::size_of::<NlMsgHdr>()) as *mut IfInfoMsg);
        ifi.family = libc::AF_UNSPEC as u8;
        ifi.index = ifindex;
    }
    buf[std::mem::size_of::<NlMsgHdr>() + std::mem::size_of::<IfInfoMsg>()..]
        .copy_from_slice(&xdp_attr);

    // SAFETY: `socket` returns an owned descriptor used only in this
    // function and closed on every path.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = (|| -> io::Result<()> {
        // SAFETY: sockaddr_nl is all-POD; a zeroed instance is valid.
        let mut sa: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        sa.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: `bind` reads the (owned) sockaddr; `fd` is owned here.
        let ret = unsafe {
            libc::bind(
                fd,
                &sa as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `sendto` reads `buf`; `fd` is owned.
        let n = unsafe {
            libc::sendto(
                fd,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
                std::ptr::null(),
                0,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut ack = [0u8; 4096];
        // SAFETY: `recvfrom` writes at most `ack.len()`; `fd` is owned.
        let n = unsafe {
            libc::recvfrom(
                fd,
                ack.as_mut_ptr() as *mut libc::c_void,
                ack.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let hdr_len = std::mem::size_of::<NlMsgHdr>();
        if (n as usize) < hdr_len {
            return Err(io::Error::other("short netlink reply"));
        }
        let ty = u16::from_le_bytes([ack[2], ack[3]]);
        if ty == NLMSG_ERROR {
            let err = i32::from_le_bytes(ack[hdr_len..hdr_len + 4].try_into().expect("4"));
            if err != 0 {
                return Err(io::Error::from_raw_os_error(-err));
            }
        }
        Ok(())
    })();
    // SAFETY: releasing our own descriptor exactly once.
    unsafe { libc::close(fd) };
    result
}

/// Capability probe: can this process use the eBPF machinery? The
/// capture datapath routes its fallback decision through here.
/// Capability + kernel-build probe for the capture datapath: does
/// THIS kernel, under THIS process, accept the exact map the datapath
/// needs (an XSKMAP)? The first live runs caught the distinction:
/// a HASH map succeeds on kernels whose build lacks
/// `CONFIG_XDP_SOCKETS` — BPF_MAP_TYPE_XSKMAP is registered by
/// net/xdp/xskmap.c, which only compiles under that config — and the
/// XSKMAP create then returns EINVAL (an UNREGISTERED map type, not a
/// permission refusal). Probing the XSKMAP itself makes the fallback
/// note honest about the cause.
pub fn xdp_datapath_available() -> Result<(), XdpUnavailable> {
    match BpfMap::create(BPF_MAP_TYPE_XSKMAP, 4, 4, 64) {
        Ok(_) => Ok(()),
        Err(e) => Err(match e.raw_os_error() {
            Some(libc::EPERM) | Some(libc::EACCES) => XdpUnavailable::Privileges(e),
            _ => XdpUnavailable::KernelBuild(e),
        }),
    }
}

/// The probe's verdict: the pointed reason the capture datapath
/// cannot engage (printed as the downgrade note; the AF_PACKET path
/// carries on either way).
#[derive(Debug)]
pub enum XdpUnavailable {
    /// `bpf()` refused on capabilities — checked against the INITIAL
    /// user namespace (the unshare sandbox unlocks neither).
    Privileges(io::Error),
    /// The kernel accepts plain BPF but refuses the XSKMAP create —
    /// the AF_XDP-adjacent map type is unavailable HERE. The refusal
    /// is reported, not diagnosed: unregistered (a build without
    /// `CONFIG_XDP_SOCKETS`) and live-build restriction (the
    /// 7.2.11-arch1 machine — `CONFIG_XDP_SOCKETS=y` — still refuses)
    /// are both observed; the create-matrix distinguishes them.
    KernelBuild(io::Error),
}

impl core::fmt::Display for XdpUnavailable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Privileges(e) => write!(
                f,
                "eBPF unavailable ({e}: CAP_BPF/CAP_NET_ADMIN checked in the initial user namespace)"
            ),
            Self::KernelBuild(e) => write!(
                f,
                "AF_XDP unavailable in this kernel ({e} creating the XSKMAP: the map type is \
                 unregistered or restricted in this build — the common cause is \
                 CONFIG_XDP_SOCKETS off, but live builds refusing it land here too)"
            ),
        }
    }
}

// --- AF_XDP (XSK) ------------------------------------------------------------

/// `AF_XDP` = 44 (socket.h); `SOL_XDP` = 283 (bits/socket.h — the
/// hand-copied 284 was wrong, caught by the same header pass).
const AF_XDP: libc::c_int = 44;
const SOL_XDP: libc::c_int = 283;
/// Socket-option ids (linux/if_xdp.h): XDP_MMAP_OFFSETS=1,
/// XDP_RX_RING=2, XDP_TX_RING=3, XDP_UMEM_REG=4, XDP_UMEM_FILL_RING=5,
/// XDP_UMEM_COMPLETION_RING=6 (the hand-copied RX id 7 was actually
/// XDP_STATISTICS).
const XDP_UMEM_REG: libc::c_int = 4;
const XDP_UMEM_FILL_RING: libc::c_int = 5;
const XDP_UMEM_COMPLETION_RING: libc::c_int = 6;
const XDP_RX_RING: libc::c_int = 2;
const XDP_MMAP_OFFSETS: libc::c_int = 1;
/// mmap pgoffs: RX = 0, FILL = 0x100000000, COMPLETION = 0x180000000.
const XDP_PGOFF_RX_RING: libc::off_t = 0;
const XDP_UMEM_PGOFF_FILL_RING: libc::off_t = 0x1_0000_0000;

const UMEM_FRAMES: usize = 256;
const FRAME_SIZE: usize = 4096;
const PAGE: usize = 4096;

/// `struct xdp_umem_reg` (uapi, /usr/include/linux/if_xdp.h): addr, len,
/// chunk_size, headroom, flags, tx_metadata_len — SIX fields, 32 bytes;
/// the kernel's `optlen < sizeof(struct xdp_umem_reg)` check rejects a
/// 28-byte (5-field) struct with EINVAL.
#[repr(C)]
#[derive(Clone, Copy)]
struct UmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
    tx_metadata_len: u32,
}

/// `struct xdp_ring_offset`: the producer/consumer/desc offsets within
/// each mmap'd ring (getsockopt XDP_MMAP_OFFSETS).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RingOffsets {
    producer: u32,
    consumer: u32,
    desc: u32,
    flags: u32,
}

/// `struct xdp_desc`.
#[repr(C)]
#[derive(Clone, Copy)]
struct XdpDesc {
    addr: u64,
    len: u32,
    options: u32,
}

/// An owned anonymous mmap region. `Send`: the mapping is uniquely
/// owned — no aliasing, no interior sharing (the ring atomics are the
/// kernel's shared-memory contract, not Rust sharing).
unsafe impl Send for Mmap {}
struct Mmap {
    addr: *mut libc::c_void,
    len: usize,
}

impl Mmap {
    /// SAFETY: caller contract — the returned region is uniquely owned
    /// (anonymous zero-filled pages; `mmap` with PRIVATE|ANONYMOUS).
    unsafe fn anonymous(len: usize) -> io::Result<Self> {
        // SAFETY: `mmap` with PROT_READ|WRITE, PRIVATE|ANONYMOUS —
        // zero-filled pages owned by this struct until drop.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { addr, len })
    }

    /// SAFETY: caller contract — `fd` must be a live descriptor and
    /// the pgoff/len a region the kernel declared for it; the mapping
    /// is uniquely owned until drop.
    unsafe fn shared(fd: i32, pgoff: libc::off_t, len: usize) -> io::Result<Self> {
        // SAFETY: `mmap` of the socket's declared ring region; the
        // mapping is owned by this struct until drop.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                pgoff,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { addr, len })
    }

    fn base(&self) -> *mut u8 {
        self.addr as *mut u8
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        // SAFETY: the region is uniquely owned; `munmap` releases it
        // exactly once.
        unsafe { libc::munmap(self.addr, self.len) };
    }
}

/// One configured ring: its mmap + the kernel-reported offsets.
struct Ring {
    map: Mmap,
    offsets: RingOffsets,
}

impl Ring {
    fn prod_ptr(&self) -> *mut AtomicU32 {
        // SAFETY: producer offset is within the mmap (kernel-reported).
        unsafe { self.map.base().add(self.offsets.producer as usize) as *mut AtomicU32 }
    }
    fn cons_ptr(&self) -> *mut AtomicU32 {
        // SAFETY: consumer offset is within the mmap (kernel-reported).
        unsafe { self.map.base().add(self.offsets.consumer as usize) as *mut AtomicU32 }
    }
    fn desc_ptr(&self) -> *mut XdpDesc {
        // SAFETY: desc offset is within the mmap (kernel-reported).
        unsafe { self.map.base().add(self.offsets.desc as usize) as *mut XdpDesc }
    }
}

/// Declare a ring (setsockopt its size) and fetch the mmap offsets.
fn declare_ring(fd: i32, opt: libc::c_int, entries: u32) -> io::Result<RingOffsets> {
    // SAFETY: `setsockopt` reads `entries` (u32, stack-owned).
    let ret = unsafe {
        libc::setsockopt(
            fd,
            SOL_XDP,
            opt,
            &entries as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut offsets = RingOffsets::default();
    // SAFETY: `getsockopt` writes `offsets` (struct-owned, sized).
    let mut optlen = std::mem::size_of::<RingOffsets>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_MMAP_OFFSETS,
            &mut offsets as *mut RingOffsets as *mut libc::c_void,
            &mut optlen,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(offsets)
}

/// The AF_XDP capture driver: one XSK on (iface, queue 0), UMEM +
/// fill + RX rings. RX only — an XSK TX ring is the line-rate replay
/// arm (a recorded follow-up); `send`/`replay` keep the AF_PACKET
/// path.
pub struct XskDriver {
    fd: i32,
    iface: String,
    umem: Mmap,
    fill: Ring,
    fill_entries: u32,
    fill_produced: u32,
    rx: Ring,
    rx_entries: u32,
}

impl XskDriver {
    pub fn open(iface: &str, ifindex: i32) -> Result<Self, DriverError> {
        // SAFETY: plain socket(2) with integer arguments.
        let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) };
        if fd < 0 {
            return Err(DriverError::Io {
                source: io::Error::last_os_error(),
            });
        }
        let opened = (|| -> Result<Self, DriverError> {
            // UMEM registration (the full 32-byte modern struct; the
            // kernel's size check rejects short variants).
            // SAFETY: owned anonymous region, registered below.
            let umem =
                unsafe { Mmap::anonymous(UMEM_FRAMES * FRAME_SIZE) }.map_err(io_to_driver)?;
            let reg = UmemReg {
                addr: umem.addr as u64,
                len: (UMEM_FRAMES * FRAME_SIZE) as u64,
                chunk_size: FRAME_SIZE as u32,
                headroom: 0,
                flags: 0,
                tx_metadata_len: 0,
            };
            // SAFETY: `setsockopt` reads `reg` (struct-owned, sized).
            let ret = unsafe {
                libc::setsockopt(
                    fd,
                    SOL_XDP,
                    XDP_UMEM_REG,
                    &reg as *const UmemReg as *const libc::c_void,
                    std::mem::size_of::<UmemReg>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                return Err(DriverError::Io {
                    source: io::Error::last_os_error(),
                });
            }
            let entries = UMEM_FRAMES as u32;
            let fill_off = declare_ring(fd, XDP_UMEM_FILL_RING, entries).map_err(io_to_driver)?;
            // Completion ring: declared (required for the UMEM
            // contract), not mmap'd — RX never consumes it.
            declare_ring(fd, XDP_UMEM_COMPLETION_RING, entries).map_err(io_to_driver)?;
            let rx_off = declare_ring(fd, XDP_RX_RING, entries).map_err(io_to_driver)?;
            // mmap lengths: off.desc + desc_sz * entries (desc already
            // points past the counter pages) — the af_xdp.rst formula.
            let fill_len = fill_off.desc as usize + 8 * entries as usize + PAGE;
            let rx_len =
                rx_off.desc as usize + std::mem::size_of::<XdpDesc>() * entries as usize + PAGE;
            // SAFETY: shared mappings of the socket's declared regions.
            let fill_map = unsafe { Mmap::shared(fd, XDP_UMEM_PGOFF_FILL_RING, fill_len) }
                .map_err(io_to_driver)?;
            // SAFETY: same region contract (the RX ring's declared
            // pgoff/len from getsockopt).
            let rx_map =
                unsafe { Mmap::shared(fd, XDP_PGOFF_RX_RING, rx_len) }.map_err(io_to_driver)?;
            // Bind to (ifindex, queue 0).
            // SAFETY: sockaddr_xdp is all-POD; zeroed is a valid instance.
            let mut sa: libc::sockaddr_xdp = unsafe { std::mem::zeroed() };
            sa.sxdp_family = AF_XDP as u16;
            sa.sxdp_ifindex = ifindex as u32;
            sa.sxdp_queue_id = 0;
            // SAFETY: `bind` reads the sockaddr; `fd` is owned here.
            // SAFETY: `bind` reads the (owned) sockaddr; `fd` is owned
            // here, and `sa` was initialized above.
            let ret = unsafe {
                libc::bind(
                    fd,
                    &sa as *const libc::sockaddr_xdp as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_xdp>() as libc::socklen_t,
                )
            };
            if ret < 0 {
                return Err(DriverError::Io {
                    source: io::Error::last_os_error(),
                });
            }
            let mut drv = Self {
                fd,
                iface: iface.to_string(),
                umem,
                fill: Ring {
                    map: fill_map,
                    offsets: fill_off,
                },
                fill_entries: entries,
                fill_produced: 0,
                rx: Ring {
                    map: rx_map,
                    offsets: rx_off,
                },
                rx_entries: entries,
            };
            // Hand every UMEM chunk to the kernel for RX.
            for i in 0..UMEM_FRAMES {
                drv.fill_push((i * FRAME_SIZE) as u64);
            }
            Ok(drv)
        })();
        // SAFETY: releasing our own descriptor; no double-close
        // (open() failed before any struct took ownership of fd).
        opened.inspect_err(|_| {
            unsafe { libc::close(fd) };
        })
    }

    /// Push one UMEM chunk address into the fill ring + publish.
    fn fill_push(&mut self, addr: u64) {
        let mask = self.fill_entries - 1;
        let idx = self.fill_produced & mask;
        // SAFETY: idx is masked below entries — an in-bounds u64 store
        // into our own fill-ring mmap.
        unsafe { *(self.fill.desc_ptr() as *mut u64).add(idx as usize) = addr };
        self.fill_produced = self.fill_produced.wrapping_add(1);
        // SAFETY: the producer counter store, in-bounds of the mmap.
        unsafe { (*self.fill.prod_ptr()).store(self.fill_produced, Ordering::Release) };
    }
}

impl Driver for XskDriver {
    fn send(&mut self, _frame: &[u8]) -> io::Result<()> {
        // The XSK TX ring is the line-rate replay arm — a recorded
        // follow-up; the capture datapath is RX-only by design.
        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
    }

    fn recv(&mut self, deadline: Instant) -> io::Result<Option<Frame>> {
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        let remaining = (deadline - now).as_millis().min(i32::MAX as u128) as i32;
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `poll` writes into `pfd` (stack-local, owned); `fd`
        // is valid.
        let ready = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, remaining) };
        if ready < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                return Ok(None);
            }
            return Err(err);
        }
        if ready == 0 {
            return Ok(None);
        }
        // RX ring drain: consumer/producer counters, then descs.
        // SAFETY: atomic loads of the ring counters (in-bounds).
        let c = unsafe { (*self.rx.cons_ptr()).load(Ordering::Acquire) };
        let p = unsafe { (*self.rx.prod_ptr()).load(Ordering::Acquire) };
        if c == p {
            return Ok(None);
        }
        let mask = self.rx_entries - 1;
        // SAFETY: c..p are valid ring slots (producer-consumer
        // contract) — an in-bounds read of our own mmap.
        let d = unsafe { *self.rx.desc_ptr().add((c & mask) as usize) };
        let len = (d.len as usize).min(FRAME_SIZE);
        // SAFETY: the descriptor's UMEM address is one of the chunks
        // we registered (every fill slot was ours); `len` is clamped.
        let bytes = unsafe {
            std::slice::from_raw_parts((self.umem.addr as *const u8).add(d.addr as usize), len)
        };
        let out = bytes.to_vec();
        // Release the descriptor + recycle the chunk into the fill ring.
        // SAFETY: in-bounds counter store to our own mmap.
        unsafe { (*self.rx.cons_ptr()).store(c.wrapping_add(1), Ordering::Release) };
        self.fill_push(d.addr);
        Ok(Some(Frame {
            bytes: Bytes::from(out),
            iface: self.iface.clone(),
            ts: std::time::SystemTime::now(),
        }))
    }
}

impl Drop for XskDriver {
    fn drop(&mut self) {
        // SAFETY: uniquely owned descriptor; close releases it once.
        unsafe { libc::close(self.fd) };
    }
}

/// The whole compiled-datapath capture bundle on one interface: the
/// prefilter program, its XSKMAP (the XSK at queue key 0), the attach.
/// Drop detaches.
pub struct XdpCapture {
    _program: BpfProgram,
    _xskmap: BpfMap,
    pub xsk: XskDriver,
    ifindex: i32,
}

impl XdpCapture {
    /// Wire the whole datapath, with the error naming the FAILING
    /// STEP (diagnosability the first live root runs demanded: a bare
    /// "attach failed" hid which of the five kernel calls refused).
    pub fn attach(
        iface: &str,
        ifindex: i32,
        prog: &wrex_ebpf::Program,
    ) -> Result<Self, DriverError> {
        let xskmap = BpfMap::create(BPF_MAP_TYPE_XSKMAP, 4, 4, 64)
            .map_err(|e| step("map create (XSKMAP)", e))?;
        let xsk = XskDriver::open(iface, ifindex).map_err(|e| step_driver("xsk open", e))?;
        // XSKMAP values are SOCKET fds: the XSK's own socket joins at
        // the queue key 0 (the compiled redirect uses rx_queue as key).
        let key = 0u32.to_le_bytes();
        let value = (xsk.fd as u32).to_le_bytes();
        xskmap
            .update(&key, &value)
            .map_err(|e| step("xskmap update (socket fd at queue 0)", e))?;
        // Map index 0 in the compiled stream = the XSKMAP (the
        // compiled-artifact contract).
        let program = BpfProgram::load_xdp(&prog.to_bits(), &[xskmap.fd()])
            .map_err(|e| step("prog load (BPF_PROG_LOAD)", e))?;
        xdp_attach(ifindex, program.fd()).map_err(|e| step("netlink xdp attach", e))?;
        Ok(Self {
            _program: program,
            _xskmap: xskmap,
            xsk,
            ifindex,
        })
    }
}

/// The step-tagging wrapper: the pointed CLI note names the exact
/// kernel call that refused. `step_driver` keeps the inner DriverError
/// text (XskDriver::open already maps its own io errors) on the step.
fn step_driver(name: &str, e: DriverError) -> DriverError {
    match e {
        DriverError::Io { source } => DriverError::Io {
            source: io::Error::other(format!("{name}: {source}")),
        },
        other => DriverError::Io {
            source: io::Error::other(format!("{name}: {other}")),
        },
    }
}

/// The step-tagging wrapper for raw io errors.
fn step(name: &str, e: io::Error) -> DriverError {
    let hint = match e.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => {
            format!("{name}: {e} (capabilities checked in the initial user namespace)")
        }
        _ => format!("{name}: {e}"),
    };
    DriverError::Io {
        source: io::Error::other(hint),
    }
}

impl Drop for XdpCapture {
    fn drop(&mut self) {
        // Detach before the fds close — keeps the interface state
        // honest (the kernel would clean up an orphaned attach too).
        let _ = xdp_attach(self.ifindex, -1);
    }
}

fn io_to_driver(e: io::Error) -> DriverError {
    match e.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => DriverError::PermissionDenied {
            hint: "the kernel datapath (eBPF) needs CAP_BPF/CAP_NET_ADMIN in the initial user namespace"
                .into(),
        },
        _ => DriverError::Io { source: e },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The datapath probe's verdict tracks the privilege CLASS and
    /// the KERNEL BUILD, not the env gate: eBPF needs capabilities in
    /// the INITIAL user namespace, and the XSKMAP additionally needs
    /// `CONFIG_XDP_SOCKETS` compiled in — the developer's hardened
    /// Arch kernel (7.2.11-arch1) caught the distinction live: a HASH
    /// map creates fine while the XSKMAP returns EINVAL (an
    /// unregistered map type, not a permission). The probe IS the
    /// honest fallback decision the capture datapath rides.
    #[cfg_attr(miri, ignore = "libc syscalls; not Miri-safe")]
    #[test]
    fn datapath_probe_tracks_the_privilege_class() {
        let in_userns = std::fs::read_to_string("/proc/self/uid_map")
            .map(|m| m.lines().count() > 1 || m.split_whitespace().nth(1) != Some("0"))
            .unwrap_or(true);
        match xdp_datapath_available() {
            Ok(()) => {
                // Only real root on an AF_XDP-capable kernel reaches
                // here (the sudo CI job on the ubuntu runners).
                assert!(
                    !in_userns,
                    "bpf() must be unavailable inside a user namespace"
                );
                assert_eq!(
                    std::os::unix::fs::MetadataExt::uid(
                        &std::fs::metadata("/proc/self").expect("proc")
                    ),
                    0,
                    "datapath available implies real root"
                );
            }
            Err(XdpUnavailable::Privileges(_)) => {
                // The unprivileged/user-namespace classes.
                assert!(
                    in_userns || !nix_uid_is_root(),
                    "a capabilities refusal implies not real root here"
                );
            }
            Err(XdpUnavailable::KernelBuild(_)) => {
                // A build without CONFIG_XDP_SOCKETS: the refusal is
                // orthogonal to privileges — record it, assert only
                // that the fallback (the driver test) handles it.
            }
        }
    }

    fn nix_uid_is_root() -> bool {
        std::os::unix::fs::MetadataExt::uid(&std::fs::metadata("/proc/self").expect("proc")) == 0
    }
}
