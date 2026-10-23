#![forbid(unsafe_code)]
//! wrex-pcap: pcap file formats, in-house (no libpcap).
//!
//! Tranche 5 (capture/replay): every classic-pcap magic variant read —
//! little/big endian × micro/nanosecond resolution — with the record
//! timestamps the tranche-1 corpus reader discarded, plus a streaming
//! little-endian microsecond Ethernet writer (the `wrex capture` shape).
//! Tranche 8b: pcapng read (auto-detected, both endiannesses, both
//! timestamp resolutions) and a streaming pcapng writer (`--pcapng`).

use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Little-endian microsecond classic-pcap magic (the writer's).
pub const MAGIC_US_LE: u32 = 0xa1b2_c3d4;
/// Big-endian microsecond magic.
const MAGIC_US_BE: u32 = 0xd4c3_b2a1;
/// Little-endian nanosecond magic (tcpdump 1.10+).
const MAGIC_NS_LE: u32 = 0xa1b2_3c4d;
/// Big-endian nanosecond magic.
const MAGIC_NS_BE: u32 = 0x4d3c_b2a1;

/// pcapng Section Header Block type. Byte-order agnostic on disk: the
/// value reads 0x0A0D0D0A under either endianness, so it doubles as
/// the pcapng auto-detect at file start.
pub const PCAPNG_SHB_TYPE: u32 = 0x0a0d_0d0a;
/// pcapng Interface Description Block type.
const PCAPNG_IDB_TYPE: u32 = 0x0000_0001;
/// pcapng Enhanced Packet Block type.
const PCAPNG_EPB_TYPE: u32 = 0x0000_0006;
/// pcapng byte-order magic (inside the SHB, after the block type).
/// A big-endian file stores 0x1A2B3C4D, which reads as 0x4D3C2B1A LE.
const PCAPNG_BOM: u32 = 0x1a2b_3c4d;
const PCAPNG_BOM_SWAPPED: u32 = 0x4d3c_2b1a;
/// SHB total length: type + bom + version + section length (the block
/// type is byte-order agnostic, so the BOM takes the block-length
/// slot; the SHB's own total length sits at offset 20).
const SHB_LEN: usize = 28;
/// IDB total length (linktype + reserved + snaplen, no options).
const IDB_LEN: usize = 20;
/// EPB fixed size: header + 20 field bytes + 4-byte trailer; packet
/// bytes and their zero padding ride on top.
const EPB_FIXED: usize = 32;
/// EPB field region (interface id .. orig_len) past the block header.
const EPB_FIELDS_LEN: usize = 20;
/// pcapng `if_tsresol` option code.
const OPT_TSRESOL: u16 = 9;
/// pcapng `epb_flags` option code (tranche T18b).
const OPT_EPB_FLAGS: u16 = 2;
/// Simple Packet Block type (read-only, tranche T18b: no timestamp —
/// capture needs one, so the writer never emits SPBs).
const PCAPNG_SPB_TYPE: u32 = 3;

/// Global-header size.
const GLOBAL_LEN: usize = 24;
/// Per-record header size.
const RECORD_LEN: usize = 16;

/// pcap link types we speak (`wrex capture` writes EN10MB).
pub mod linktype {
    /// Ethernet (`DLT_EN10MB`).
    pub const EN10MB: u32 = 1;
    /// Raw IP (`LINKTYPE_RAW`): read-side only in this tranche.
    pub const RAW: u32 = 101;
    /// Linux cooked capture (`LINKTYPE_LINUX_SLL`): read-side only.
    pub const LINUX_SLL: u32 = 113;
}

/// Errors from parsing a classic pcap.
#[derive(Debug, thiserror::Error)]
pub enum PcapError {
    /// Fewer bytes than a global header.
    #[error("pcap too short ({len} bytes, need 24)")]
    TooShort {
        /// Bytes present.
        len: usize,
    },
    /// None of the classic magic values, and not a pcapng SHB either.
    #[error("not a pcap or pcapng file (magic 0x{magic:08x})")]
    BadMagic {
        /// The magic as a little-endian u32.
        magic: u32,
    },
    /// Record header advertises bytes past end of file.
    #[error("pcap truncated record {index}")]
    TruncatedRecord {
        /// Zero-based record index.
        index: usize,
    },
    /// pcapng block length overruns the file (or undercuts the block
    /// header): the file is corrupt past this point.
    #[error("pcapng truncated block (record {index})")]
    TruncatedBlock {
        /// Zero-based index of the record being read when the block
        /// truncated (records so far, the `TruncatedRecord` spirit).
        index: usize,
    },
}

/// IDB timestamp resolution (tranche T18b): `if_tsresol` value — 6 =
/// microseconds (the spec default the option-less IDB carries), 9 =
/// nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TsResol {
    Micros,
    Nanos,
}

impl TsResol {
    /// The `if_tsresol` option value.
    pub const fn option_value(self) -> u8 {
        match self {
            TsResol::Micros => 6,
            TsResol::Nanos => 9,
        }
    }
    /// Timestamp ticks per second.
    pub const fn per_second(self) -> u64 {
        match self {
            TsResol::Micros => 1_000_000,
            TsResol::Nanos => 1_000_000_000,
        }
    }
}

/// One captured frame with its timestamp.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcapRecord {
    /// Capture timestamp.
    pub ts: SystemTime,
    /// Captured bytes (`incl_len`).
    pub bytes: Vec<u8>,
    /// Original wire length (`orig_len`); may exceed `bytes.len()` when
    /// the file was captured with a snaplen.
    pub orig_len: u32,
    /// Interface id (pcapng EPB/SPB; 0 for classic files, tranche T18b).
    pub iface: u32,
}

impl PcapRecord {
    /// A record with explicit parts (the writer's reader-side mirror).
    pub fn from_parts(ts: SystemTime, bytes: Vec<u8>, orig_len: u32) -> Self {
        Self {
            ts,
            bytes,
            orig_len,
            iface: 0,
        }
    }

    /// [`PcapRecord::from_parts`] with an explicit interface id (the
    /// pcapng reader-side mirror, tranche T18b).
    pub fn from_parts_iface(ts: SystemTime, bytes: Vec<u8>, orig_len: u32, iface: u32) -> Self {
        Self {
            ts,
            bytes,
            orig_len,
            iface,
        }
    }
}

/// A parsed classic pcap file.
#[derive(Clone, Debug)]
pub struct PcapFile {
    /// Link type from the global header (`linktype::*`).
    pub linktype: u32,
    /// Snaplen from the global header.
    pub snaplen: u32,
    /// Timestamps are nanosecond-resolution.
    pub nanosecond: bool,
    /// Byte order of the file.
    pub big_endian: bool,
    /// The file is pcapng (not classic pcap); read-side only.
    pub pcapng: bool,
    /// Records in file order.
    pub records: Vec<PcapRecord>,
}

/// `(ts_sec, ts_frac)` of a timestamp; before-EPOCH clamps to zero.
fn ts_parts(ts: SystemTime) -> (u32, u32) {
    let d = ts.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let sec = d.as_secs().min(u32::MAX as u64) as u32;
    (sec, d.subsec_micros())
}

/// `SystemTime` from `(ts_sec, ts_frac)` with resolution awareness.
fn ts_from_parts(sec: u32, frac: u32, nanosecond: bool) -> SystemTime {
    let frac = if nanosecond {
        Duration::from_nanos(frac as u64)
    } else {
        Duration::from_micros(frac as u64)
    };
    UNIX_EPOCH + Duration::from_secs(sec as u64) + frac
}

/// `(ts_sec, ns)` of a timestamp; before-EPOCH clamps to zero
/// (tranche T18b: the ns-resolution EPB path).
fn ts_parts_ns(ts: SystemTime) -> (u32, u32) {
    let d = ts.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let sec = d.as_secs().min(u32::MAX as u64) as u32;
    (sec, d.subsec_nanos())
}

/// Encode one record header (little-endian microsecond, the writer path).
const fn encode_record_header(
    ts_sec: u32,
    ts_frac: u32,
    incl_len: u32,
    orig_len: u32,
) -> [u8; RECORD_LEN] {
    let mut b = [0u8; RECORD_LEN];
    put_le(&mut b, 0, ts_sec);
    put_le(&mut b, 4, ts_frac);
    put_le(&mut b, 8, incl_len);
    put_le(&mut b, 12, orig_len);
    b
}

/// Decode one record header under a byte order. (const: the `pick`
/// closure inlined as a const helper — closures are not const-callable.)
const fn decode_record_header(b: &[u8; RECORD_LEN], big_endian: bool) -> (u32, u32, u32, u32) {
    (
        pick32(b, 0, big_endian),
        pick32(b, 4, big_endian),
        pick32(b, 8, big_endian),
        pick32(b, 12, big_endian),
    )
}

/// Encode the EPB fixed fields (interface id, ts_high, ts_low,
/// cap_len, orig_len): little-endian, the writer path.
const fn encode_epb_fields(
    iface: u32,
    ts_high: u32,
    ts_low: u32,
    cap_len: u32,
    orig_len: u32,
) -> [u8; EPB_FIELDS_LEN] {
    let mut b = [0u8; EPB_FIELDS_LEN];
    put_le(&mut b, 0, iface);
    put_le(&mut b, 4, ts_high);
    put_le(&mut b, 8, ts_low);
    put_le(&mut b, 12, cap_len);
    put_le(&mut b, 16, orig_len);
    b
}

/// Decode the EPB fixed fields under a byte order (the reader's mirror).
const fn decode_epb_fields(
    b: &[u8; EPB_FIELDS_LEN],
    big_endian: bool,
) -> (u32, u32, u32, u32, u32) {
    (
        pick32(b, 0, big_endian),
        pick32(b, 4, big_endian),
        pick32(b, 8, big_endian),
        pick32(b, 12, big_endian),
        pick32(b, 16, big_endian),
    )
}

/// Little-endian 32-bit store at `off` (const: `copy_from_slice` is
/// not const-callable — IndexMut is not a const trait; index stores are).
const fn put_le(b: &mut [u8], off: usize, v: u32) {
    let raw = v.to_le_bytes();
    let mut i = 0;
    while i < 4 {
        b[off + i] = raw[i];
        i += 1;
    }
}

/// A 32-bit little/big-endian pick at `off` (the shared const helper
/// for the fixed-field decoders).
const fn pick32(b: &[u8], off: usize, big_endian: bool) -> u32 {
    let raw = [b[off], b[off + 1], b[off + 2], b[off + 3]];
    if big_endian {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    }
}

/// `SystemTime` from an EPB timestamp: the 64-bit unit count since the
/// epoch start, µs or ns per the interface resolution.
fn pcapng_ts(high: u32, low: u32, nanosecond: bool) -> SystemTime {
    let v = ((high as u64) << 32) | low as u64;
    let d = if nanosecond {
        Duration::from_secs(v / 1_000_000_000) + Duration::from_nanos(v % 1_000_000_000)
    } else {
        Duration::from_secs(v / 1_000_000) + Duration::from_micros(v % 1_000_000)
    };
    UNIX_EPOCH + d
}

/// Walk a block's options region for `if_tsresol` (option 9): value 9
/// → nanoseconds, anything else — 6 included, decimal resolutions
/// (upper bit set) included — → the pcapng default, microseconds. Only
/// power-of-2 resolutions are supported; everything else falls back,
/// never fatal. Malformed options stop the walk.
fn tsresol_is_ns(opts: &[u8], big_endian: bool) -> bool {
    let pick16 = |off: usize| -> u16 {
        let raw = [opts[off], opts[off + 1]];
        if big_endian {
            u16::from_be_bytes(raw)
        } else {
            u16::from_le_bytes(raw)
        }
    };
    let mut off = 0;
    while off + 4 <= opts.len() {
        let code = pick16(off);
        let len = pick16(off + 2) as usize;
        if code == 0 {
            break; // opt_endofopt
        }
        let val = &opts[off + 4..];
        if code == OPT_TSRESOL && len >= 1 && !val.is_empty() {
            return val[0] == 9;
        }
        if len > val.len() {
            break; // option overruns the block: stop, never fatal
        }
        off += 4 + len;
    }
    false
}

/// Parse a pcapng file (auto-detected by `read`): both endiannesses,
/// one section, Enhanced Packet Blocks onto the same record list.
///
/// Unknown blocks are skipped per the spec's mandatory-skip semantics
/// (the LSB of the block type picks "skip" vs "skip or abort"; a
/// reader skips either, recording nothing). The single-interface
/// contract tolerates nonzero interface ids; when several IDBs
/// appear the LAST one wins for linktype/snaplen/tsresol, and an EPB
/// before any IDB gets the spec defaults (µs). A block that overruns
/// the file (or undercuts its own header) is `TruncatedBlock`.
fn read_pcapng(bytes: &[u8]) -> Result<PcapFile, PcapError> {
    // Spec SHB layout (pass-2 foreign-fixture fix): the BOM sits at
    // offset 8, AFTER the block total length. A pre-read as LE covers
    // both byte orders (the two constants are byte-swaps).
    let bom = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let big_endian = match bom {
        PCAPNG_BOM => false,
        PCAPNG_BOM_SWAPPED => true,
        _ => return Err(PcapError::BadMagic { magic: bom }),
    };
    let pick = |off: usize| -> u32 {
        let raw = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
        if big_endian {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        }
    };
    let pick16 = |off: usize| -> u16 {
        let raw = [bytes[off], bytes[off + 1]];
        if big_endian {
            u16::from_be_bytes(raw)
        } else {
            u16::from_le_bytes(raw)
        }
    };
    // Interface defaults: the writer's shape (µs until an IDB says
    // otherwise — the spec default resolution).
    let mut linktype = linktype::EN10MB;
    let mut snaplen = 65535;
    let mut nanosecond = false;
    let mut records = Vec::new();
    // Per-interface resolutions (tranche T18b): an EPB resolves its
    // timestamp through its OWN interface's IDB (`if_tsresol`),
    // falling back to the spec-default µs — the file-level
    // `nanosecond` stays LAST-IDB-wins (the frozen single-interface
    // contract). An `idbs` entry also carries the snaplen for SPBs.
    let mut idbs: std::collections::BTreeMap<u32, bool> = std::collections::BTreeMap::new();
    let mut last_iface: u32 = 0;
    // The SHB's total length is at offset 4 (the standard slot,
    // before the BOM); it must stay in-file, then the generic block
    // walk takes over past it.
    let shb_len = pick(4) as usize;
    if shb_len < SHB_LEN || shb_len > bytes.len() {
        return Err(PcapError::TruncatedBlock { index: 0 });
    }
    let mut off = shb_len;
    while off < bytes.len() {
        let index = records.len();
        // A block header is 8 bytes (type + total length).
        if bytes.len() - off < 8 {
            return Err(PcapError::TruncatedBlock { index });
        }
        let btype = pick(off);
        let blen = pick(off + 4) as usize;
        // Total length must cover header + trailer and stay in-file.
        if blen < 12 || blen > bytes.len() - off {
            return Err(PcapError::TruncatedBlock { index });
        }
        match btype {
            PCAPNG_IDB_TYPE => {
                // The fixed IDB fields end at off+16; a block shorter
                // than that plus the 4-byte trailing length is a pointed
                // truncation (a 12..19-byte IDB previously panicked the
                // tsresol slice — the fuzz-smoke crash).
                if blen < 20 {
                    return Err(PcapError::TruncatedBlock { index });
                }
                // The last IDB wins (single-interface contract).
                linktype = pick16(off + 8) as u32;
                snaplen = pick(off + 12);
                let opts = off + 16;
                let opt_end = off + blen - 4; // blen >= 20 keeps this >= opts
                nanosecond = tsresol_is_ns(&bytes[opts..opt_end], big_endian);
                // Tranche T18b: record this interface (its id is not a
                // fixed field of the IDB — the id IS the ordinal; the
                // EPB's own id resolves against the LAST id seen).
                last_iface = idbs.len() as u32;
                idbs.insert(last_iface, nanosecond);
            }
            PCAPNG_EPB_TYPE => {
                if blen < EPB_FIXED {
                    return Err(PcapError::TruncatedBlock { index });
                }
                let fields: [u8; EPB_FIELDS_LEN] = bytes[off + 8..off + 28]
                    .try_into()
                    .expect("blen >= 32 bounds the slice");
                let (iface, ts_high, ts_low, cap_len, orig_len) =
                    decode_epb_fields(&fields, big_endian);
                // Packet bytes run to the trailing total length,
                // padded to 4; cap_len must fit inside.
                let data_end = off + blen - 4;
                let cap = cap_len as usize;
                if off + 28 + cap > data_end {
                    return Err(PcapError::TruncatedBlock { index });
                }
                // Tranche T18b: per-interface resolution (own IDB's
                // if_tsresol, spec-default µs without one).
                let ns = idbs.get(&iface).copied().unwrap_or(false);
                records.push(PcapRecord {
                    ts: pcapng_ts(ts_high, ts_low, ns),
                    bytes: bytes[off + 28..off + 28 + cap].to_vec(),
                    orig_len,
                    iface,
                });
            }
            PCAPNG_SPB_TYPE => {
                // Simple Packet Block (read-only, tranche T18b): no
                // timestamp (epoch), cap_len = min(orig_len, snaplen of
                // the current interface), the block may legally be
                // shorter than the packet (data truncated to it).
                if blen < 16 {
                    return Err(PcapError::TruncatedBlock { index });
                }
                let orig_len = pick(off + 8);
                let limit = if snaplen == 0 {
                    orig_len
                } else {
                    snaplen.min(orig_len)
                } as usize;
                let data_end = off + blen - 4;
                let start = off + 12;
                let cap = limit.min(data_end.saturating_sub(start));
                records.push(PcapRecord {
                    ts: UNIX_EPOCH,
                    bytes: bytes[start..start + cap].to_vec(),
                    orig_len,
                    iface: last_iface,
                });
            }
            // SHB (the section was fixed at the first BOM) and every
            // unknown block: skipped. The spec's mandatory-skip rule
            // (block type LSB 0 = skip, 1 = skip-or-abort) lets a
            // reader skip either way — unknown mandatory blocks do
            // NOT abort the file.
            _ => {}
        }
        off += blen;
    }
    Ok(PcapFile {
        linktype,
        snaplen,
        nanosecond,
        big_endian,
        pcapng: true,
        records,
    })
}

/// Parse a classic pcap or pcapng file (all four magic variants, plus
/// pcapng auto-detected via the byte-order-agnostic SHB block type).
///
/// Frames past a truncated record or block are an error (the file is
/// corrupt); everything else — odd tail bytes, zero records, unknown
/// pcapng blocks — parses cleanly.
pub fn read(bytes: &[u8]) -> Result<PcapFile, PcapError> {
    if bytes.len() < GLOBAL_LEN {
        return Err(PcapError::TooShort { len: bytes.len() });
    }
    // The SHB block type is byte-order agnostic (0x0A0D0D0A both
    // ways): one comparison auto-detects pcapng before the classic
    // magic match. The classic magics never collide with it.
    if bytes[0] == 0x0a && bytes[1] == 0x0d && bytes[2] == 0x0d && bytes[3] == 0x0a {
        return read_pcapng(bytes);
    }
    let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let (big_endian, nanosecond) = match magic {
        MAGIC_US_LE => (false, false),
        MAGIC_US_BE => (true, false),
        MAGIC_NS_LE => (false, true),
        MAGIC_NS_BE => (true, true),
        _ => return Err(PcapError::BadMagic { magic }),
    };
    let pick = |off: usize| -> u32 {
        let raw = [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]];
        if big_endian {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        }
    };
    let snaplen = pick(16);
    let linktype = pick(20);
    let mut records = Vec::new();
    let mut off = GLOBAL_LEN;
    let mut index = 0usize;
    while off + RECORD_LEN <= bytes.len() {
        let hdr: [u8; RECORD_LEN] = bytes[off..off + RECORD_LEN]
            .try_into()
            .expect("bounded by the while condition");
        let (sec, frac, incl_len, orig_len) = decode_record_header(&hdr, big_endian);
        off += RECORD_LEN;
        let incl = incl_len as usize;
        if off + incl > bytes.len() {
            return Err(PcapError::TruncatedRecord { index });
        }
        records.push(PcapRecord {
            ts: ts_from_parts(sec, frac, nanosecond),
            bytes: bytes[off..off + incl].to_vec(),
            orig_len,
            iface: 0,
        });
        off += incl;
        index += 1;
    }
    Ok(PcapFile {
        linktype,
        snaplen,
        nanosecond,
        big_endian,
        pcapng: false,
        records,
    })
}

/// Streaming classic-pcap writer: little-endian microsecond, EN10MB.
///
/// The global header lands on construction (the file is valid the
/// moment the writer exists); every frame is one record header +
/// bytes, flushed through — `wrex capture` never buffers a frame.
pub struct PcapWriter<W: Write> {
    inner: W,
}

impl<W: Write> PcapWriter<W> {
    /// Write the global header (version 2.4, snaplen 65535, EN10MB).
    pub fn new(mut inner: W) -> std::io::Result<Self> {
        let mut hdr = [0u8; GLOBAL_LEN];
        hdr[..4].copy_from_slice(&MAGIC_US_LE.to_le_bytes());
        hdr[4..6].copy_from_slice(&2u16.to_le_bytes()); // version major
        hdr[6..8].copy_from_slice(&4u16.to_le_bytes()); // version minor
        // thiszone = 0 (UTC), sigfigs = 0
        hdr[16..20].copy_from_slice(&65535u32.to_le_bytes()); // snaplen
        hdr[20..].copy_from_slice(&linktype::EN10MB.to_le_bytes());
        inner.write_all(&hdr)?;
        Ok(Self { inner })
    }

    /// Append one record: capture timestamps, `snaplen` truncation with
    /// `orig_len` preserved.
    pub fn write_record(
        &mut self,
        ts: SystemTime,
        frame: &[u8],
        snaplen: usize,
    ) -> std::io::Result<()> {
        let orig = u32::try_from(frame.len()).unwrap_or(u32::MAX);
        self.write_record_orig(ts, frame, orig, snaplen)
    }

    /// [`PcapWriter::write_record`] with an explicit `orig_len` —
    /// corpus passthrough of a snaplen-truncated capture whose stored
    /// bytes are shorter than the wire length (tranche 14: `wrex patch`
    /// keeps untouched records byte-identical, `orig_len` included).
    pub fn write_record_orig(
        &mut self,
        ts: SystemTime,
        frame: &[u8],
        orig_len: u32,
        snaplen: usize,
    ) -> std::io::Result<()> {
        let (sec, frac) = ts_parts(ts);
        let incl = frame.len().min(snaplen);
        let incl = u32::try_from(incl).unwrap_or(u32::MAX);
        self.inner
            .write_all(&encode_record_header(sec, frac, incl, orig_len))?;
        let cap = incl as usize;
        self.inner.write_all(&frame[..cap])?;
        Ok(())
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }

    /// Consume and return the inner writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// Streaming pcapng writer: little-endian, one section, one EN10MB
/// interface — the pcapng mirror of [`PcapWriter`].
///
/// The SHB (byte-order magic, version 1.0) + IDB (linktype EN10MB,
/// snaplen 65535, no options) land on construction, so the file is
/// valid the moment the writer exists. The IDB carries no
/// `if_tsresol` option: the spec default resolution applies — the
/// EPB timestamps are absolute epoch microseconds split into high/low
/// 32-bit words (the classic writer's semantics).
pub struct PcapngWriter<W: Write> {
    inner: W,
    /// Timestamp resolution of the (single-section) IDB(s) — every EPB
    /// carries it (tranche T18b; `new` keeps the option-less µs default).
    resol: TsResol,
}

impl<W: Write> PcapngWriter<W> {
    /// Write the SHB (byte-order magic 0x1A2B3C4D, version 1.0,
    /// unspecified section length) + IDB (EN10MB, snaplen 65535).
    pub fn new(mut inner: W) -> std::io::Result<Self> {
        // Spec SHB layout (pcapng §3.2 / tranches: the BOM sits at
        // offset 8, AFTER the block total length — the pass-2
        // foreign-fixture fix: wrex previously wrote BOM at 4 (self-
        // consistent roundtrip, unreadable by Wireshark/text2pcap).
        // type(4) + total len(4) + BOM(4) + major(2) + minor(2) +
        // section length u64(-1) + trailing total len(4) = 28.
        let mut shb = [0u8; SHB_LEN];
        shb[..4].copy_from_slice(&PCAPNG_SHB_TYPE.to_le_bytes());
        shb[4..8].copy_from_slice(&(SHB_LEN as u32).to_le_bytes());
        shb[8..12].copy_from_slice(&PCAPNG_BOM.to_le_bytes());
        shb[12..14].copy_from_slice(&1u16.to_le_bytes()); // version major
        shb[14..16].copy_from_slice(&0u16.to_le_bytes()); // version minor
        shb[16..24].fill(0xff); // section length: -1 (unspecified)
        shb[24..].copy_from_slice(&(SHB_LEN as u32).to_le_bytes());
        inner.write_all(&shb)?;

        let mut idb = [0u8; IDB_LEN];
        idb[..4].copy_from_slice(&PCAPNG_IDB_TYPE.to_le_bytes());
        idb[4..8].copy_from_slice(&(IDB_LEN as u32).to_le_bytes());
        idb[8..10].copy_from_slice(&(linktype::EN10MB as u16).to_le_bytes());
        // reserved u16 at 10..12 stays zero
        idb[12..16].copy_from_slice(&65535u32.to_le_bytes()); // snaplen
        idb[16..].copy_from_slice(&(IDB_LEN as u32).to_le_bytes());
        inner.write_all(&idb)?;
        Ok(Self {
            inner,
            resol: TsResol::Micros,
        })
    }

    /// [`PcapngWriter::new`] with an explicit `if_tsresol` option on the
    /// IDB (tranche T18b): the EPB timestamps follow the resolution
    /// (µs value 6 / ns value 9), so the file is self-describing.
    pub fn with_resol(mut inner: W, resol: TsResol) -> std::io::Result<Self> {
        // Same SHB as `new`.
        let mut shb = [0u8; SHB_LEN];
        shb[..4].copy_from_slice(&PCAPNG_SHB_TYPE.to_le_bytes());
        shb[4..8].copy_from_slice(&(SHB_LEN as u32).to_le_bytes());
        shb[8..12].copy_from_slice(&PCAPNG_BOM.to_le_bytes());
        shb[12..14].copy_from_slice(&1u16.to_le_bytes());
        shb[14..16].copy_from_slice(&0u16.to_le_bytes());
        shb[16..24].fill(0xff);
        shb[24..].copy_from_slice(&(SHB_LEN as u32).to_le_bytes());
        inner.write_all(&shb)?;
        // IDB fixed header (16) + if_tsresol (code 9, len 1, value,
        // 3 pad) + opt_endofopt (4) + trailing total length (4) = 32.
        let total = IDB_LEN + 8 + 4;
        let mut idb = vec![0u8; total];
        idb[..4].copy_from_slice(&PCAPNG_IDB_TYPE.to_le_bytes());
        idb[4..8].copy_from_slice(&(total as u32).to_le_bytes());
        idb[8..10].copy_from_slice(&(linktype::EN10MB as u16).to_le_bytes());
        idb[12..16].copy_from_slice(&65535u32.to_le_bytes());
        // Options start right after snaplen (offset 16, the fixed
        // header end); the trailing length moves to the block end.
        let at = 16; // options start; opt_endofopt lands at 24..28
        idb[at..at + 2].copy_from_slice(&OPT_TSRESOL.to_le_bytes());
        idb[at + 2..at + 4].copy_from_slice(&1u16.to_le_bytes());
        idb[at + 4] = resol.option_value();
        // 3 pad bytes stay zero; opt_endofopt (code 0, len 0) at 24..28.
        idb[total - 4..].copy_from_slice(&(total as u32).to_le_bytes());
        inner.write_all(&idb)?;
        Ok(Self { inner, resol })
    }

    /// Append one Enhanced Packet Block: absolute epoch timestamps
    /// (µs, per the IDB's absent `if_tsresol`), `snaplen` truncation
    /// with `orig_len` preserved, packet bytes padded to 4.
    pub fn write_record(
        &mut self,
        ts: SystemTime,
        frame: &[u8],
        snaplen: usize,
    ) -> std::io::Result<()> {
        let orig = u32::try_from(frame.len()).unwrap_or(u32::MAX);
        self.write_record_orig(ts, frame, orig, snaplen)
    }

    /// [`PcapngWriter::write_record`] with an explicit `orig_len` —
    /// corpus passthrough of a snaplen-truncated capture (tranche 14:
    /// `wrex patch` keeps untouched records byte-identical, `orig_len`
    /// included).
    pub fn write_record_orig(
        &mut self,
        ts: SystemTime,
        frame: &[u8],
        orig_len: u32,
        snaplen: usize,
    ) -> std::io::Result<()> {
        self.write_record_epb(ts, frame, orig_len, snaplen, 0, None)
    }

    /// [`PcapngWriter::write_record_orig`] onto an explicit interface
    /// id (multi-IDB files, tranche T18b).
    pub fn write_record_orig_on(
        &mut self,
        ts: SystemTime,
        frame: &[u8],
        orig_len: u32,
        snaplen: usize,
        iface: u32,
    ) -> std::io::Result<()> {
        self.write_record_epb(ts, frame, orig_len, snaplen, iface, None)
    }

    /// [`PcapngWriter::write_record_orig`] with an `epb_flags` EPB
    /// option (tranche T18b): 8 bytes of option (code 2, len 4) +
    /// `opt_endofopt`, after the padded packet data.
    pub fn write_record_opts(
        &mut self,
        ts: SystemTime,
        frame: &[u8],
        orig_len: u32,
        snaplen: usize,
        epb_flags: u32,
    ) -> std::io::Result<()> {
        self.write_record_epb(ts, frame, orig_len, snaplen, 0, Some(epb_flags))
    }

    /// The EPB writer core: interface id, resolution-aware timestamp
    /// unit, optional epb_flags option, optional explicit snaplen
    /// override is not needed (caller passes it).
    fn write_record_epb(
        &mut self,
        ts: SystemTime,
        frame: &[u8],
        orig_len: u32,
        snaplen: usize,
        iface: u32,
        epb_flags: Option<u32>,
    ) -> std::io::Result<()> {
        let per = self.resol.per_second();
        let (sec, frac) = if self.resol == TsResol::Nanos {
            let (s, f) = ts_parts_ns(ts);
            (s, f as u64)
        } else {
            let (s, f) = ts_parts(ts);
            (s, f as u64)
        };
        let v = (sec as u64).saturating_mul(per).saturating_add(frac);
        let incl = frame.len().min(snaplen);
        let incl = u32::try_from(incl).unwrap_or(u32::MAX);
        let padded = (incl as usize).next_multiple_of(4);
        // Options (epb_flags): code 2, len 4 + value; then opt_endofopt.
        let opts_len = if epb_flags.is_some() { 8 + 4 } else { 0 };
        let total = (8 + EPB_FIELDS_LEN + padded + opts_len + 4) as u32;
        let mut hdr = [0u8; 8 + EPB_FIELDS_LEN];
        hdr[..4].copy_from_slice(&PCAPNG_EPB_TYPE.to_le_bytes());
        hdr[4..8].copy_from_slice(&total.to_le_bytes());
        hdr[8..].copy_from_slice(&encode_epb_fields(
            iface,
            (v >> 32) as u32,
            v as u32,
            incl,
            orig_len,
        ));
        self.inner.write_all(&hdr)?;
        self.inner.write_all(&frame[..incl as usize])?;
        // Zero padding to the 4-byte boundary (cap_len stays exact),
        // then the options, then the trailing copy of the total length.
        let pad = padded - incl as usize;
        if pad > 0 {
            self.inner.write_all(&[0u8; 4][..pad])?;
        }
        if let Some(flags) = epb_flags {
            let mut opt = [0u8; 12];
            opt[..2].copy_from_slice(&OPT_EPB_FLAGS.to_le_bytes());
            opt[2..4].copy_from_slice(&4u16.to_le_bytes());
            opt[4..8].copy_from_slice(&flags.to_le_bytes());
            // opt_endofopt (code 0, len 0) at 8..12 stays zero.
            self.inner.write_all(&opt)?;
        }
        self.inner.write_all(&total.to_le_bytes())?;
        Ok(())
    }

    /// [`PcapngWriter::new`] over several interfaces (tranche T18b):
    /// one IDB per `linktype`, in order — the interface id is the
    /// ordinal. Records land through
    /// [`PcapngWriter::write_record_orig_on`]. Resolution stays the
    /// spec-default µs (the `new` semantics).
    pub fn new_multi(mut inner: W, linktypes: &[u16]) -> std::io::Result<Self> {
        let mut shb = [0u8; SHB_LEN];
        shb[..4].copy_from_slice(&PCAPNG_SHB_TYPE.to_le_bytes());
        shb[4..8].copy_from_slice(&(SHB_LEN as u32).to_le_bytes());
        shb[8..12].copy_from_slice(&PCAPNG_BOM.to_le_bytes());
        shb[12..14].copy_from_slice(&1u16.to_le_bytes());
        shb[14..16].copy_from_slice(&0u16.to_le_bytes());
        shb[16..24].fill(0xff);
        shb[24..].copy_from_slice(&(SHB_LEN as u32).to_le_bytes());
        inner.write_all(&shb)?;
        for (i, lt) in linktypes.iter().enumerate() {
            let mut idb = [0u8; IDB_LEN];
            idb[..4].copy_from_slice(&PCAPNG_IDB_TYPE.to_le_bytes());
            idb[4..8].copy_from_slice(&(IDB_LEN as u32).to_le_bytes());
            idb[8..10].copy_from_slice(&lt.to_le_bytes());
            idb[12..16].copy_from_slice(&65535u32.to_le_bytes());
            idb[16..].copy_from_slice(&(IDB_LEN as u32).to_le_bytes());
            inner.write_all(&idb)?;
            let _ = i;
        }
        Ok(Self {
            inner,
            resol: TsResol::Micros,
        })
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }

    /// Consume and return the inner writer.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// Compile-time proofs (const-eval pass): the fixed-field codec pair
/// roundtrips in both byte orders — the Kani `record_header_roundtrip`
/// harness's concrete-matrix sibling, checkable without a solver.
const _: () = {
    const HDR: [u8; RECORD_LEN] = encode_record_header(0x1122_3344, 5, 6, 7);
    let (s, f, i, o) = decode_record_header(&HDR, false);
    // (const: tuple PartialEq is not const-callable — elementwise.)
    assert!(s == 0x1122_3344 && f == 5 && i == 6 && o == 7);
    const EPB: [u8; EPB_FIELDS_LEN] = encode_epb_fields(1, 2, 3, 4, 5);
    let (a, b, c, d, e) = decode_epb_fields(&EPB, false);
    assert!(a == 1 && b == 2 && c == 3 && d == 4 && e == 5);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Fault-injection writer (pass-2): fails on the Nth write_all,
    /// succeeding (and recording) before that.
    struct FaultAt {
        writes: Vec<u8>,
        fail_on: usize,
        count: usize,
    }
    impl FaultAt {
        fn new(fail_on: usize) -> Self {
            Self {
                writes: Vec::new(),
                fail_on,
                count: 0,
            }
        }
    }
    impl Write for FaultAt {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.count += 1;
            if self.count == self.fail_on {
                return Err(std::io::Error::other("injected: disk full"));
            }
            self.writes.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A writer fault mid-record PROPAGATES (Err) — never truncates
    /// silently — for both the classic and pcapng writers, at every
    /// write_all seam (header, record header, frame bytes).
    #[test]
    fn writer_faults_propagate_classic() {
        // new(): the global header write fails.
        let mut f = FaultAt::new(1);
        assert!(PcapWriter::new(&mut f).is_err());
        // write_record: record-header write fails.
        let mut f = FaultAt::new(2);
        let mut w = PcapWriter::new(&mut f).unwrap();
        assert!(w.write_record(UNIX_EPOCH, &[0xaa; 40], 65535).is_err());
        // frame write fails (partial record left in the sink — the
        // reader must reject it: see faulted_file_is_unreadable).
        let mut f = FaultAt::new(3);
        let mut w = PcapWriter::new(&mut f).unwrap();
        assert!(w.write_record(UNIX_EPOCH, &[0xaa; 40], 65535).is_err());
    }

    #[test]
    fn writer_faults_propagate_pcapng() {
        // new(): SHB write fails; then IDB.
        let mut f = FaultAt::new(1);
        assert!(PcapngWriter::new(&mut f).is_err());
        let mut f = FaultAt::new(2);
        assert!(PcapngWriter::new(&mut f).is_err());
        // write_record: EPB header / frame / trailing-length seams.
        for fail_on in 3..=5 {
            let mut f = FaultAt::new(fail_on);
            let mut w = PcapngWriter::new(&mut f).unwrap();
            assert!(
                w.write_record(UNIX_EPOCH, &[0xbb; 40], 65535).is_err(),
                "EPB seam {fail_on}"
            );
        }
    }

    /// A faulted (partial) file must NOT read back as a clean capture:
    /// the reader rejects the truncated tail record instead of
    /// returning the partial file as if it were complete.
    #[test]
    fn faulted_file_is_unreadable() {
        // Classic: one full record, then a tail cut mid-frame of the
        // second record (the shape a FaultAt(3) writer leaves behind).
        let mut buf = Vec::new();
        {
            let mut w = PcapWriter::new(&mut buf).unwrap();
            w.write_record(UNIX_EPOCH, &[0x11; 20], 65535).unwrap();
            w.write_record(UNIX_EPOCH + Duration::from_secs(9), &[0x22; 60], 65535)
                .unwrap();
        }
        assert_eq!(read(&buf).unwrap().records.len(), 2);
        // Cut inside the second record's frame bytes.
        let rec1_end = GLOBAL_LEN + 16 + 20;
        let faulted = &buf[..rec1_end + 16 + 30];
        match read(faulted) {
            Ok(f) => panic!("faulted file read back clean: {} records", f.records.len()),
            Err(e) => assert!(e.to_string().contains("truncated"), "{e}"),
        }
        // pcapng: a tail cut mid-frame of an EPB is rejected too.
        let mut ng = Vec::new();
        {
            let mut w = PcapngWriter::new(&mut ng).unwrap();
            w.write_record(UNIX_EPOCH, &[0x33; 40], 65535).unwrap();
        }
        assert_eq!(read(&ng).unwrap().records.len(), 1);
        let faulted_ng = &ng[..ng.len() - 30]; // cut mid-frame+pad+tail
        match read(faulted_ng) {
            Ok(f) => panic!(
                "faulted pcapng read back clean: {} records",
                f.records.len()
            ),
            Err(e) => assert!(
                e.to_string().contains("truncated") || e.to_string().contains("block"),
                "{e}"
            ),
        }
    }

    #[test]
    fn writer_reader_roundtrip() {
        let frames: Vec<(&[u8], SystemTime)> = vec![
            (&[0u8; 14], UNIX_EPOCH),
            (
                &[0xaa, 0xbb],
                UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_000),
            ),
            (
                &[0xff; 300],
                UNIX_EPOCH + Duration::from_secs(4_294_967_295),
            ),
        ];
        let mut buf = Vec::new();
        {
            let mut w = PcapWriter::new(&mut buf).unwrap();
            for (f, ts) in &frames {
                w.write_record(*ts, f, 65535).unwrap();
            }
            w.flush().unwrap();
        }
        assert!(buf.len() > GLOBAL_LEN);
        let file = read(&buf).unwrap();
        assert_eq!(file.linktype, linktype::EN10MB);
        assert!(!file.big_endian);
        assert!(!file.nanosecond);
        assert_eq!(file.records.len(), frames.len());
        for (i, (f, ts)) in frames.iter().enumerate() {
            assert_eq!(&file.records[i].bytes, f);
            assert_eq!(file.records[i].ts, *ts);
            assert_eq!(file.records[i].orig_len, f.len() as u32);
        }
    }

    #[test]
    fn snaplen_truncates_with_orig_len() {
        let frame = [0x11u8; 100];
        let mut buf = Vec::new();
        {
            let mut w = PcapWriter::new(&mut buf).unwrap();
            w.write_record(UNIX_EPOCH, &frame, 10).unwrap();
        }
        let file = read(&buf).unwrap();
        assert_eq!(file.records[0].bytes, &frame[..10]);
        assert_eq!(file.records[0].orig_len, 100);
    }

    /// Tranche 14: the explicit `orig_len` passthrough — a truncated
    /// capture record writes back with its wire length kept (the
    /// `wrex patch` corpus-passthrough contract), both writers.
    #[test]
    fn write_record_orig_keeps_wire_length() {
        let frame = [0x22u8; 10];
        for pcapng in [false, true] {
            let mut buf = Vec::new();
            if pcapng {
                let mut w = PcapngWriter::new(&mut buf).unwrap();
                w.write_record_orig(UNIX_EPOCH, &frame, 100, 65535).unwrap();
                w.flush().unwrap();
            } else {
                let mut w = PcapWriter::new(&mut buf).unwrap();
                w.write_record_orig(UNIX_EPOCH, &frame, 100, 65535).unwrap();
                w.flush().unwrap();
            }
            let file = read(&buf).unwrap();
            assert_eq!(file.records.len(), 1, "pcapng={pcapng}");
            assert_eq!(file.records[0].bytes, &frame[..], "pcapng={pcapng}");
            assert_eq!(file.records[0].orig_len, 100, "pcapng={pcapng}");
            // write_record (the T5/T8b path) is unchanged: orig == len.
            let mut buf2 = Vec::new();
            if pcapng {
                let mut w = PcapngWriter::new(&mut buf2).unwrap();
                w.write_record(UNIX_EPOCH, &frame, 65535).unwrap();
                w.flush().unwrap();
            } else {
                let mut w = PcapWriter::new(&mut buf2).unwrap();
                w.write_record(UNIX_EPOCH, &frame, 65535).unwrap();
                w.flush().unwrap();
            }
            assert_eq!(read(&buf2).unwrap().records[0].orig_len, 10);
        }
    }

    #[test]
    fn be_and_ns_magic_variants() {
        // Big-endian microsecond file: magic on disk a1 b2 c3 d4
        // (0xa1b2c3d4 stored big-endian); fields likewise BE.
        let mut be = vec![0xa1, 0xb2, 0xc3, 0xd4];
        be.extend_from_slice(&[0x00, 0x02]); // version major
        be.extend_from_slice(&[0x00, 0x04]); // version minor
        be.extend_from_slice(&[0u8; 8]); // thiszone + sigfigs
        be.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]); // snaplen 65535
        be.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // linktype EN10MB
        // One BE record: sec=1, frac=2, incl=3, orig=3, then 3 payload bytes.
        be.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 3]);
        be.extend_from_slice(&[9, 9, 9]);
        let f = read(&be).unwrap();
        assert!(f.big_endian && !f.nanosecond);
        assert_eq!(f.snaplen, 0xffff);
        assert_eq!(f.linktype, linktype::EN10MB);
        assert_eq!(f.records[0].bytes, &[9, 9, 9]);
        assert_eq!(
            f.records[0].ts,
            UNIX_EPOCH + Duration::from_secs(1) + Duration::from_micros(2)
        );

        // Nanosecond little-endian: magic number 0xa1b23c4d stored LE.
        let mut ns = vec![0x4d, 0x3c, 0xb2, 0xa1];
        ns.extend_from_slice(&[0u8; 20]);
        let rec = encode_record_header(0, 500, 1, 1);
        ns.extend_from_slice(&rec);
        ns.push(7);
        let f = read(&ns).unwrap();
        assert!(f.nanosecond && !f.big_endian);
        assert_eq!(f.records[0].ts, UNIX_EPOCH + Duration::from_nanos(500));
        assert_eq!(f.records[0].bytes, &[7]);
    }

    #[test]
    fn errors() {
        assert!(matches!(read(&[0u8; 10]), Err(PcapError::TooShort { .. })));
        assert!(matches!(
            read(&[0xa1, 0xb2, 0xc3, 0xd4][..]),
            Err(PcapError::TooShort { .. })
        ));
        assert!(matches!(
            read(
                &[0x0f, 0x0f, 0x0f, 0x0f][..]
                    .iter()
                    .copied()
                    .chain([0u8; 20])
                    .collect::<Vec<u8>>()
            ),
            Err(PcapError::BadMagic { .. })
        ));
        // Truncated record: header says 8 bytes, file has 2.
        let mut buf = Vec::new();
        {
            let mut w = PcapWriter::new(&mut buf).unwrap();
            w.write_record(UNIX_EPOCH, &[1, 2, 3, 4, 5, 6, 7, 8], 65535)
                .unwrap();
        }
        let cut = &buf[..buf.len() - 6];
        assert!(matches!(
            read(cut),
            Err(PcapError::TruncatedRecord { index: 0 })
        ));
        // A record header with no payload at EOF is truncated too.
        let cut2 = &buf[..buf.len() - 8];
        assert!(matches!(
            read(cut2),
            Err(PcapError::TruncatedRecord { index: 0 })
        ));
    }

    #[test]
    fn before_epoch_clamps_to_zero() {
        let early = UNIX_EPOCH - Duration::from_secs(5);
        let mut buf = Vec::new();
        {
            let mut w = PcapWriter::new(&mut buf).unwrap();
            w.write_record(early, &[1], 65535).unwrap();
        }
        let f = read(&buf).unwrap();
        assert_eq!(f.records[0].ts, UNIX_EPOCH);
    }

    #[test]
    fn empty_file_reads_cleanly() {
        let mut buf = Vec::new();
        let _ = PcapWriter::new(&mut buf).unwrap();
        let f = read(&buf).unwrap();
        assert!(f.records.is_empty());
        assert_eq!(f.linktype, linktype::EN10MB);
    }

    // --- pcapng (tranche 8b) -------------------------------------------------

    #[test]
    fn pcapng_writer_reader_roundtrip() {
        let frames: Vec<(&[u8], SystemTime)> = vec![
            (&[0u8; 14], UNIX_EPOCH),
            (
                &[0xaa, 0xbb],
                UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_000),
            ),
            (
                &[0xff; 300],
                UNIX_EPOCH + Duration::from_secs(4_294_967_295),
            ),
        ];
        let mut buf = Vec::new();
        {
            let mut w = PcapngWriter::new(&mut buf).unwrap();
            for (f, ts) in &frames {
                w.write_record(*ts, f, 65535).unwrap();
            }
            w.flush().unwrap();
        }
        let file = read(&buf).unwrap();
        assert!(file.pcapng);
        assert!(!file.big_endian);
        assert!(!file.nanosecond);
        assert_eq!(file.linktype, linktype::EN10MB);
        assert_eq!(file.snaplen, 0xffff);
        assert_eq!(file.records.len(), frames.len());
        for (i, (f, ts)) in frames.iter().enumerate() {
            assert_eq!(&file.records[i].bytes, f);
            assert_eq!(file.records[i].ts, *ts);
            assert_eq!(file.records[i].orig_len, f.len() as u32);
        }
    }

    #[test]
    fn pcapng_snaplen_truncates_with_orig_len() {
        let frame = [0x11u8; 100];
        let mut buf = Vec::new();
        {
            let mut w = PcapngWriter::new(&mut buf).unwrap();
            w.write_record(UNIX_EPOCH, &frame, 10).unwrap();
        }
        let file = read(&buf).unwrap();
        assert!(file.pcapng);
        assert_eq!(file.records[0].bytes, &frame[..10]);
        assert_eq!(file.records[0].orig_len, 100);
    }

    #[test]
    fn pcapng_empty_file_reads_cleanly() {
        let mut buf = Vec::new();
        let _ = PcapngWriter::new(&mut buf).unwrap();
        let f = read(&buf).unwrap();
        assert!(f.pcapng);
        assert!(f.records.is_empty());
        assert_eq!(f.linktype, linktype::EN10MB);
        assert_eq!(f.snaplen, 0xffff);
    }

    #[test]
    fn pcapng_before_epoch_clamps_to_zero() {
        let early = UNIX_EPOCH - Duration::from_secs(5);
        let mut buf = Vec::new();
        {
            let mut w = PcapngWriter::new(&mut buf).unwrap();
            w.write_record(early, &[1], 65535).unwrap();
        }
        let f = read(&buf).unwrap();
        assert_eq!(f.records[0].ts, UNIX_EPOCH);
    }

    #[test]
    fn pcapng_be_vector() {
        // Big-endian pcapng: SHB (BOM stored BE), IDB, one EPB with
        // sec=1, frac=2 (µs), 7 payload bytes + 1 pad byte.
        let be32 = |v: u32| v.to_be_bytes();
        let mut be = Vec::new();
        be.extend_from_slice(&be32(PCAPNG_SHB_TYPE)); // byte-order agnostic
        be.extend_from_slice(&be32(SHB_LEN as u32)); // block total length
        be.extend_from_slice(&be32(PCAPNG_BOM));
        be.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // version 1.0
        be.extend_from_slice(&[0xff; 8]); // section length: unspecified
        be.extend_from_slice(&be32(SHB_LEN as u32)); // trailing total length
        be.extend_from_slice(&be32(PCAPNG_IDB_TYPE));
        be.extend_from_slice(&be32(IDB_LEN as u32));
        be.extend_from_slice(&[0x00, 0x01]); // linktype EN10MB
        be.extend_from_slice(&[0x00, 0x00]); // reserved
        be.extend_from_slice(&be32(0xffff)); // snaplen
        be.extend_from_slice(&be32(IDB_LEN as u32));
        be.extend_from_slice(&be32(PCAPNG_EPB_TYPE));
        be.extend_from_slice(&be32(40)); // 32 + 8 padded payload bytes
        be.extend_from_slice(&be32(0)); // interface id
        be.extend_from_slice(&be32(0)); // ts_high
        be.extend_from_slice(&be32(1_000_002)); // ts_low: 1s + 2µs
        be.extend_from_slice(&be32(7)); // cap_len
        be.extend_from_slice(&be32(7)); // orig_len
        be.extend_from_slice(&[9, 9, 9, 9, 9, 9, 9, 0]); // payload + pad
        be.extend_from_slice(&be32(40));
        let f = read(&be).unwrap();
        assert!(f.pcapng);
        assert!(f.big_endian);
        assert!(!f.nanosecond);
        assert_eq!(f.snaplen, 0xffff);
        assert_eq!(f.linktype, linktype::EN10MB);
        assert_eq!(f.records[0].bytes, &[9, 9, 9, 9, 9, 9, 9]);
        assert_eq!(
            f.records[0].ts,
            UNIX_EPOCH + Duration::from_secs(1) + Duration::from_micros(2)
        );
    }

    #[test]
    fn pcapng_ns_tsresol_vector() {
        // LE SHB (the writer's) + an IDB carrying if_tsresol=9 (ns) +
        // one EPB with 1s + 2ns, built by hand (the writer has no
        // options path — that's a deliberate deferral).
        let le16 = |v: u16| v.to_le_bytes();
        let le32 = |v: u32| v.to_le_bytes();
        let mut ng = Vec::new();
        ng.extend_from_slice(&le32(PCAPNG_SHB_TYPE));
        ng.extend_from_slice(&le32(SHB_LEN as u32)); // block total length
        ng.extend_from_slice(&le32(PCAPNG_BOM));
        ng.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // version 1.0
        ng.extend_from_slice(&[0xff; 8]); // section length: unspecified
        ng.extend_from_slice(&le32(SHB_LEN as u32)); // trailing total length
        ng.extend_from_slice(&le32(PCAPNG_IDB_TYPE));
        ng.extend_from_slice(&le32(32)); // 20 + tsresol option + endofopt
        ng.extend_from_slice(&le16(linktype::EN10MB as u16));
        ng.extend_from_slice(&le16(0)); // reserved
        ng.extend_from_slice(&le32(0xffff)); // snaplen
        ng.extend_from_slice(&le16(OPT_TSRESOL)); // option 9
        ng.extend_from_slice(&le16(1)); // option length
        ng.extend_from_slice(&[9, 0, 0, 0]); // value 9 (ns), padded
        ng.extend_from_slice(&[0u8; 4]); // opt_endofopt
        ng.extend_from_slice(&le32(32));
        ng.extend_from_slice(&le32(PCAPNG_EPB_TYPE));
        ng.extend_from_slice(&le32(36)); // 32 + 4 payload (1 + 3 pad)
        ng.extend_from_slice(&le32(0)); // interface id
        ng.extend_from_slice(&le32(0)); // ts_high
        ng.extend_from_slice(&le32(1_000_000_002)); // ts_low: 1s + 2ns
        ng.extend_from_slice(&le32(1)); // cap_len
        ng.extend_from_slice(&le32(1)); // orig_len
        ng.extend_from_slice(&[7, 0, 0, 0]); // payload + pad
        ng.extend_from_slice(&le32(36));
        let f = read(&ng).unwrap();
        assert!(f.pcapng);
        assert!(!f.big_endian);
        assert!(f.nanosecond);
        assert_eq!(
            f.records[0].ts,
            UNIX_EPOCH + Duration::from_secs(1) + Duration::from_nanos(2)
        );
        assert_eq!(f.records[0].bytes, &[7]);
    }

    #[test]
    fn pcapng_decimal_tsresol_defaults_to_us() {
        // if_tsresol with the upper bit set is a decimal resolution
        // (10^-v seconds): unsupported, never fatal, defaults to µs.
        let mut ng = {
            // SHB+IDB skeleton from the writer, then patch the option.
            let mut buf = Vec::new();
            let _ = PcapngWriter::new(&mut buf);
            buf
        };
        // Rebuild the IDB with the decimal tsresol (0x80|3 = ms).
        let le16 = |v: u16| v.to_le_bytes();
        let le32 = |v: u32| v.to_le_bytes();
        let idb_len = 32u32;
        ng.truncate(SHB_LEN);
        ng.extend_from_slice(&le32(PCAPNG_IDB_TYPE));
        ng.extend_from_slice(&le32(idb_len));
        ng.extend_from_slice(&le16(linktype::EN10MB as u16));
        ng.extend_from_slice(&le16(0));
        ng.extend_from_slice(&le32(0xffff));
        ng.extend_from_slice(&le16(OPT_TSRESOL));
        ng.extend_from_slice(&le16(1));
        ng.extend_from_slice(&[0x83, 0, 0, 0]); // decimal 10^-3: falls back
        ng.extend_from_slice(&[0u8; 4]);
        ng.extend_from_slice(&le32(idb_len));
        // One EPB at 1s + 2µs (the µs reading of the unit count).
        ng.extend_from_slice(&le32(PCAPNG_EPB_TYPE));
        ng.extend_from_slice(&le32(36));
        ng.extend_from_slice(&encode_epb_fields(0, 0, 1_000_002, 1, 1));
        ng.extend_from_slice(&[7, 0, 0, 0]);
        ng.extend_from_slice(&le32(36));
        let f = read(&ng).unwrap();
        assert!(!f.nanosecond);
        assert_eq!(
            f.records[0].ts,
            UNIX_EPOCH + Duration::from_secs(1) + Duration::from_micros(2)
        );
    }

    #[test]
    fn pcapng_skip_block_between_records() {
        // An unknown block (LSB 1: "skip or abort" per the spec — a
        // reader skips) spliced between two records: both survive.
        let mut buf = Vec::new();
        let rec1;
        {
            let mut w = PcapngWriter::new(&mut buf).unwrap();
            w.write_record(UNIX_EPOCH, &[1, 2, 3, 4], 65535).unwrap();
            w.flush().unwrap();
            rec1 = buf.len();
        }
        // Interleave the unknown block before the second record.
        let mut file = buf[..rec1].to_vec();
        file.extend_from_slice(&0x0000_0099u32.to_le_bytes()); // unknown, mandatory
        file.extend_from_slice(&16u32.to_le_bytes()); // total length
        file.extend_from_slice(&[0xff; 4]); // body
        file.extend_from_slice(&16u32.to_le_bytes()); // trailing length
        let mut tail = Vec::new();
        {
            let mut w = PcapngWriter::new(&mut tail).unwrap();
            w.write_record(UNIX_EPOCH + Duration::from_secs(1), &[5, 6], 65535)
                .unwrap();
        }
        file.extend_from_slice(&tail[SHB_LEN + IDB_LEN..]);
        let f = read(&file).unwrap();
        assert_eq!(f.records.len(), 2);
        assert_eq!(f.records[0].bytes, &[1, 2, 3, 4]);
        assert_eq!(f.records[1].bytes, &[5, 6]);
        assert_eq!(f.records[1].ts, UNIX_EPOCH + Duration::from_secs(1));
    }

    #[test]
    fn pcapng_epb_before_idb_uses_defaults() {
        // No IDB at all: EPB timestamps read as µs (the spec default).
        let le32 = |v: u32| v.to_le_bytes();
        let mut ng = Vec::new();
        ng.extend_from_slice(&le32(PCAPNG_SHB_TYPE));
        ng.extend_from_slice(&le32(SHB_LEN as u32)); // block total length
        ng.extend_from_slice(&le32(PCAPNG_BOM));
        ng.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // version 1.0
        ng.extend_from_slice(&[0xff; 8]); // section length: unspecified
        ng.extend_from_slice(&le32(SHB_LEN as u32)); // trailing total length
        ng.extend_from_slice(&le32(PCAPNG_EPB_TYPE));
        ng.extend_from_slice(&le32(36));
        ng.extend_from_slice(&encode_epb_fields(0, 0, 1_000_002, 1, 1));
        ng.extend_from_slice(&[7, 0, 0, 0]);
        ng.extend_from_slice(&le32(36));
        let f = read(&ng).unwrap();
        assert!(f.pcapng);
        assert!(!f.nanosecond);
        assert_eq!(f.linktype, linktype::EN10MB);
        assert_eq!(f.snaplen, 0xffff);
        assert_eq!(
            f.records[0].ts,
            UNIX_EPOCH + Duration::from_secs(1) + Duration::from_micros(2)
        );
    }

    #[test]
    fn pcapng_last_idb_wins() {
        // Two IDBs: the LAST one wins for linktype/snaplen/tsresol.
        let le16 = |v: u16| v.to_le_bytes();
        let le32 = |v: u32| v.to_le_bytes();
        let idb = |lt: u16, snap: u32, tsresol: u8| -> Vec<u8> {
            let mut b = Vec::new();
            b.extend_from_slice(&le32(PCAPNG_IDB_TYPE));
            b.extend_from_slice(&le32(32));
            b.extend_from_slice(&le16(lt));
            b.extend_from_slice(&le16(0));
            b.extend_from_slice(&le32(snap));
            b.extend_from_slice(&le16(OPT_TSRESOL));
            b.extend_from_slice(&le16(1));
            b.extend_from_slice(&[tsresol, 0, 0, 0]);
            b.extend_from_slice(&[0u8; 4]);
            b.extend_from_slice(&le32(32));
            b
        };
        // Hand-built SHB (a writer would prepend its own IDB and shift
        // the interface ordinals — the probe caught exactly that).
        let mut ng = Vec::new();
        ng.extend_from_slice(&le32(PCAPNG_SHB_TYPE));
        ng.extend_from_slice(&le32(SHB_LEN as u32));
        ng.extend_from_slice(&le32(PCAPNG_BOM));
        ng.extend_from_slice(&le16(1));
        ng.extend_from_slice(&le16(0));
        ng.extend_from_slice(&[0xffu8; 8]);
        ng.extend_from_slice(&le32(SHB_LEN as u32));
        ng.extend_from_slice(&idb(1, 0xffff, 6)); // µs EN10MB
        ng.extend_from_slice(&idb(linktype::LINUX_SLL as u16, 4096, 9)); // ns SLL
        // Tranche T18b: the FILE-level fields stay LAST-IDB-wins (the
        // frozen single-interface contract); the RECORD timestamp
        // resolves through the EPB's OWN interface (iface 0 → IDB#0
        // µs; iface 1 → IDB#1 ns).
        let epb = |iface: u32, low: u32| {
            let mut b = Vec::new();
            b.extend_from_slice(&le32(PCAPNG_EPB_TYPE));
            b.extend_from_slice(&le32(36));
            b.extend_from_slice(&encode_epb_fields(iface, 0, low, 1, 1));
            b.extend_from_slice(&[7, 0, 0, 0]);
            b.extend_from_slice(&le32(36));
            b
        };
        ng.extend_from_slice(&epb(0, 1_000_000_002));
        ng.extend_from_slice(&epb(1, 1_000_000_002));
        let f = read(&ng).unwrap();
        // File-level: last IDB wins (ns, SLL, snaplen 4096).
        assert!(f.nanosecond);
        assert_eq!(f.linktype, linktype::LINUX_SLL);
        assert_eq!(f.snaplen, 4096);
        // Records: iface 0 → µs (IDB#0), iface 1 → ns (IDB#1).
        assert_eq!(f.records[0].iface, 0);
        assert_eq!(
            f.records[0].ts,
            UNIX_EPOCH + Duration::from_micros(1_000_000_002)
        );
        assert_eq!(f.records[1].iface, 1);
        assert_eq!(
            f.records[1].ts,
            UNIX_EPOCH + Duration::from_secs(1) + Duration::from_nanos(2)
        );
    }

    #[test]
    fn pcapng_truncated_errors() {
        // Shorter than an SHB at all: the existing TooShort.
        assert!(matches!(
            read(&[0x0a, 0x0d, 0x0d, 0x0a, 0x4d, 0x3c, 0x2b, 0x1a][..]),
            Err(PcapError::TooShort { .. })
        ));
        // A bad byte-order magic: BadMagic (the SHB type matched).
        let mut bad_bom = vec![0x0a, 0x0d, 0x0d, 0x0a];
        bad_bom.extend_from_slice(&28u32.to_le_bytes()); // total length
        bad_bom.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // bad BOM
        bad_bom.extend_from_slice(&[0u8; 16]);
        assert!(matches!(read(&bad_bom), Err(PcapError::BadMagic { .. })));
        // SHB total length overruns the file: TruncatedBlock.
        let mut cut_shb = vec![0x0a, 0x0d, 0x0d, 0x0a];
        cut_shb.extend_from_slice(&100u32.to_le_bytes()); // len > remaining
        cut_shb.extend_from_slice(&PCAPNG_BOM.to_le_bytes());
        cut_shb.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        cut_shb.extend_from_slice(&[0xff; 8]);
        assert!(matches!(
            read(&cut_shb),
            Err(PcapError::TruncatedBlock { index: 0 })
        ));
        // A block length below the header + trailer floor.
        let mut tiny = cut_shb;
        tiny[4..8].copy_from_slice(&8u32.to_le_bytes());
        assert!(matches!(
            read(&tiny),
            Err(PcapError::TruncatedBlock { index: 0 })
        ));
        // Truncated EPB: cut 6 bytes off the writer's single record.
        let mut buf = Vec::new();
        {
            let mut w = PcapngWriter::new(&mut buf).unwrap();
            w.write_record(UNIX_EPOCH, &[1, 2, 3, 4, 5, 6, 7, 8], 65535)
                .unwrap();
        }
        let cut = &buf[..buf.len() - 6];
        assert!(matches!(
            read(cut),
            Err(PcapError::TruncatedBlock { index: 0 })
        ));
    }

    proptest::prelude::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(256))]

        #[test]
        fn proptest_roundtrip(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..64),
                              sec in proptest::num::u32::ANY,
                              frac in proptest::num::u32::ANY) {
            let ts = UNIX_EPOCH + Duration::from_secs(sec as u64) + Duration::from_micros((frac % 1_000_000) as u64);
            let mut buf = Vec::new();
            {
                let mut w = PcapWriter::new(&mut buf).unwrap();
                w.write_record(ts, &bytes, 65535).unwrap();
                // A second record exercises the offset walk.
                w.write_record(ts, &bytes, 65535).unwrap();
            }
            let f = read(&buf).unwrap();
            assert_eq!(f.records.len(), 2);
            assert_eq!(f.records[0].bytes, bytes);
            assert_eq!(f.records[0].ts, ts);
            assert_eq!(f.records[1].bytes, bytes);
        }

        #[test]
        fn proptest_pcapng_roundtrip(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..64),
                               sec in proptest::num::u32::ANY,
                               frac in proptest::num::u32::ANY) {
            let ts = UNIX_EPOCH + Duration::from_secs(sec as u64) + Duration::from_micros((frac % 1_000_000) as u64);
            let mut buf = Vec::new();
            {
                let mut w = PcapngWriter::new(&mut buf).unwrap();
                w.write_record(ts, &bytes, 65535).unwrap();
                // A second record exercises the block-offset walk.
                w.write_record(ts, &bytes, 65535).unwrap();
            }
            let f = read(&buf).unwrap();
            assert!(f.pcapng);
            assert_eq!(f.records.len(), 2);
            assert_eq!(f.records[0].bytes, bytes);
            assert_eq!(f.records[0].ts, ts);
            assert_eq!(f.records[1].bytes, bytes);
        }
    }

    /// Two arbitrary records through the ns-resolution pcapng writer
    /// (`if_tsresol` 9, tranche T18b) read back identically: ns
    /// timestamps preserved exactly, bytes, orig_len, iface 0.
    #[test]
    fn proptest_pcapng_ns_roundtrip() {
        use proptest::prelude::*;
        let mut config = ProptestConfig::with_cases(256);
        config.failure_persistence = None;
        proptest!(
            config,
            |(bytes in proptest::collection::vec(any::<u8>(), 0..64),
              sec in any::<u32>(),
              nanos in any::<u32>())| {
                let ts = UNIX_EPOCH
                    + Duration::from_secs(sec as u64)
                    + Duration::from_nanos((nanos % 1_000_000_000) as u64);
                let mut buf = Vec::new();
                {
                    let mut w = PcapngWriter::with_resol(&mut buf, TsResol::Nanos).unwrap();
                    w.write_record(ts, &bytes, 65535).unwrap();
                    // A second record exercises the block-offset walk.
                    w.write_record(ts, &bytes, 65535).unwrap();
                    w.flush().unwrap();
                }
                let f = read(&buf).unwrap();
                assert!(f.nanosecond);
                prop_assert_eq!(f.records.len(), 2);
                prop_assert_eq!(&f.records[0].bytes, &bytes);
                prop_assert_eq!(f.records[0].ts, ts);
                prop_assert_eq!(f.records[0].iface, 0);
                prop_assert_eq!(&f.records[1].bytes, &bytes);
                prop_assert_eq!(f.records[1].ts, ts);
            }
        );
    }

    // --- tranche T18b: writer completion + reader tolerance -------------------

    #[test]
    fn pcapng_with_resol_ns_roundtrip() {
        // The IDB carries if_tsresol=9; EPB timestamps are ns.
        let ts = UNIX_EPOCH + Duration::from_secs(5) + Duration::from_nanos(123_456_789);
        let mut buf = Vec::new();
        {
            let mut w = PcapngWriter::with_resol(&mut buf, TsResol::Nanos).unwrap();
            w.write_record(ts, &[1, 2, 3, 4, 5], 65535).unwrap();
            w.flush().unwrap();
        }
        // The IDB option is on the wire (code 9, len 1, value 9),
        // starting right after the snaplen (fixed header end).
        let idb_at = 28; // past the SHB
        assert_eq!(&buf[idb_at + 16..idb_at + 18], &9u16.to_le_bytes());
        assert_eq!(&buf[idb_at + 18..idb_at + 20], &1u16.to_le_bytes());
        assert_eq!(buf[idb_at + 20], 9);
        let f = read(&buf).unwrap();
        assert!(f.nanosecond);
        assert_eq!(f.records[0].ts, ts);
        assert_eq!(f.records[0].bytes, &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn pcapng_with_resol_us_is_byte_identical_to_new() {
        // Explicit µs `if_tsresol` vs the option-less default: the EPB
        // bytes match (resolution semantics identical), only the IDB
        // option region differs.
        let ts = UNIX_EPOCH + Duration::from_secs(7) + Duration::from_micros(9);
        let mut plain = Vec::new();
        {
            let mut w = PcapngWriter::new(&mut plain).unwrap();
            w.write_record(ts, &[9, 9], 65535).unwrap();
            w.flush().unwrap();
        }
        let mut us = Vec::new();
        {
            let mut w = PcapngWriter::with_resol(&mut us, TsResol::Micros).unwrap();
            w.write_record(ts, &[9, 9], 65535).unwrap();
            w.flush().unwrap();
        }
        // The EPB (from its block type onward) is byte-identical: the
        // plain IDB is 20 bytes, the option-carrying one 32.
        assert_eq!(&plain[28 + 20..], &us[28 + 32..]);
        let f = read(&us).unwrap();
        assert!(!f.nanosecond);
        assert_eq!(f.records[0].ts, ts);
    }

    #[test]
    fn pcapng_multi_idb_roundtrip() {
        let a: Vec<u8> = (0..12).collect();
        let b: Vec<u8> = (12..24).collect();
        let mut buf = Vec::new();
        {
            let mut w = PcapngWriter::new_multi(&mut buf, &[linktype::EN10MB as u16, 113]).unwrap();
            w.write_record_orig_on(UNIX_EPOCH + Duration::from_secs(1), &a, 12, 65535, 0)
                .unwrap();
            w.write_record_orig_on(UNIX_EPOCH + Duration::from_secs(2), &b, 24, 4096, 1)
                .unwrap();
            w.flush().unwrap();
        }
        let f = read(&buf).unwrap();
        assert_eq!(f.records.len(), 2);
        assert_eq!(f.records[0].iface, 0);
        assert_eq!(f.records[0].bytes, a);
        assert_eq!(f.records[0].orig_len, 12);
        assert_eq!(f.records[1].iface, 1);
        assert_eq!(f.records[1].bytes, b);
        assert_eq!(f.records[1].orig_len, 24);
        // File-level stays LAST-IDB-wins; the writer's IDBs are
        // fixed-shape (snaplen 65535 — the record's snaplen only
        // truncates cap_len).
        assert_eq!(f.snaplen, 65535);
    }

    #[test]
    fn pcapng_epb_flags_roundtrip() {
        let frame: Vec<u8> = (0..10).collect();
        let mut buf = Vec::new();
        {
            let mut w = PcapngWriter::new(&mut buf).unwrap();
            w.write_record_opts(UNIX_EPOCH, &frame, 10, 65535, 0xdead_beef)
                .unwrap();
            w.flush().unwrap();
        }
        // The option rides after the padded packet data: code 2, len 4,
        // value LE.
        let tail = &buf[buf.len() - 16..buf.len() - 4];
        assert_eq!(&tail[..2], &OPT_EPB_FLAGS.to_le_bytes());
        assert_eq!(&tail[2..4], &4u16.to_le_bytes());
        assert_eq!(&tail[4..8], &0xdead_beefu32.to_le_bytes());
        // The record still reads back whole.
        let f = read(&buf).unwrap();
        assert_eq!(f.records[0].bytes, frame);
        assert_eq!(f.records[0].ts, UNIX_EPOCH);
    }

    #[test]
    fn pcapng_spb_reads() {
        // Simple Packet Block (read-only): orig_len at off+8, data past
        // off+12 truncated by min(orig_len, snaplen of the current
        // interface), no timestamp (epoch).
        let le16 = |v: u16| v.to_le_bytes();
        let le32 = |v: u32| v.to_le_bytes();
        let mut ng = Vec::new();
        ng.extend_from_slice(&le32(PCAPNG_SHB_TYPE));
        ng.extend_from_slice(&le32(SHB_LEN as u32));
        ng.extend_from_slice(&le32(PCAPNG_BOM));
        ng.extend_from_slice(&le16(1));
        ng.extend_from_slice(&le16(0));
        ng.extend_from_slice(&[0xffu8; 8]);
        ng.extend_from_slice(&le32(SHB_LEN as u32));
        // IDB with snaplen 4.
        ng.extend_from_slice(&le32(PCAPNG_IDB_TYPE));
        ng.extend_from_slice(&le32(IDB_LEN as u32));
        ng.extend_from_slice(&le16(1));
        ng.extend_from_slice(&le16(0));
        ng.extend_from_slice(&le32(4));
        ng.extend_from_slice(&le32(IDB_LEN as u32));
        // SPB carrying 6 bytes (padded to the 4-grid), orig_len 8 —
        // snaplen truncates to 4.
        let data = [1u8, 2, 3, 4, 5, 6, 0, 0];
        let total = 8 + 4 + 8 + 4;
        ng.extend_from_slice(&le32(PCAPNG_SPB_TYPE));
        ng.extend_from_slice(&le32(total as u32));
        ng.extend_from_slice(&le32(8));
        ng.extend_from_slice(&data);
        ng.extend_from_slice(&le32(total as u32));
        let f = read(&ng).unwrap();
        assert_eq!(f.records.len(), 1);
        assert_eq!(f.records[0].bytes, &[1, 2, 3, 4]);
        assert_eq!(f.records[0].orig_len, 8);
        assert_eq!(f.records[0].ts, UNIX_EPOCH);
        assert_eq!(f.records[0].iface, 0);
    }

    #[test]
    fn pcapng_spb_snaplen_zero_means_unlimited() {
        // snaplen 0 in the IDB = no limit: cap_len = orig_len.
        let le16 = |v: u16| v.to_le_bytes();
        let le32 = |v: u32| v.to_le_bytes();
        let mut ng = Vec::new();
        ng.extend_from_slice(&le32(PCAPNG_SHB_TYPE));
        ng.extend_from_slice(&le32(SHB_LEN as u32));
        ng.extend_from_slice(&le32(PCAPNG_BOM));
        ng.extend_from_slice(&le16(1));
        ng.extend_from_slice(&le16(0));
        ng.extend_from_slice(&[0xffu8; 8]);
        ng.extend_from_slice(&le32(SHB_LEN as u32));
        ng.extend_from_slice(&le32(PCAPNG_IDB_TYPE));
        ng.extend_from_slice(&le32(IDB_LEN as u32));
        ng.extend_from_slice(&le16(1));
        ng.extend_from_slice(&le16(0));
        ng.extend_from_slice(&le32(0));
        ng.extend_from_slice(&le32(IDB_LEN as u32));
        let data = [1u8, 2, 3, 4];
        let total = 8 + 4 + 4 + 4;
        ng.extend_from_slice(&le32(PCAPNG_SPB_TYPE));
        ng.extend_from_slice(&le32(total as u32));
        ng.extend_from_slice(&le32(4));
        ng.extend_from_slice(&data);
        ng.extend_from_slice(&le32(total as u32));
        let f = read(&ng).unwrap();
        assert_eq!(f.records[0].bytes, &[1, 2, 3, 4]);
    }

    #[test]
    fn pcapng_multi_section_reads() {
        // A second SHB mid-file (multi-section): skipped like any
        // unknown-to-this-reader block, records on both sides read.
        let le16 = |v: u16| v.to_le_bytes();
        let le32 = |v: u32| v.to_le_bytes();
        let shb = || -> Vec<u8> {
            let mut b = Vec::new();
            b.extend_from_slice(&le32(PCAPNG_SHB_TYPE));
            b.extend_from_slice(&le32(SHB_LEN as u32));
            b.extend_from_slice(&le32(PCAPNG_BOM));
            b.extend_from_slice(&le16(1));
            b.extend_from_slice(&le16(0));
            b.extend_from_slice(&[0xffu8; 8]);
            b.extend_from_slice(&le32(SHB_LEN as u32));
            b
        };
        let mut ng = shb();
        let epb = |byte: u8| -> Vec<u8> {
            let mut b = Vec::new();
            let total = 8 + EPB_FIELDS_LEN + 4 + 4;
            b.extend_from_slice(&le32(PCAPNG_EPB_TYPE));
            b.extend_from_slice(&le32(total as u32));
            b.extend_from_slice(&encode_epb_fields(0, 0, 1, 1, 1));
            b.extend_from_slice(&[byte, 0, 0, 0]);
            b.extend_from_slice(&le32(total as u32));
            b
        };
        ng.extend(epb(7));
        ng.extend(shb());
        ng.extend(epb(8));
        let f = read(&ng).unwrap();
        assert_eq!(f.records.len(), 2);
        assert_eq!(f.records[0].bytes, &[7]);
        assert_eq!(f.records[1].bytes, &[8]);
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Record-header encode/decode is an involution on LE files:
    /// every symbolic `(sec, frac, incl, orig)` survives the trip.
    #[kani::proof]
    fn record_header_roundtrip() {
        let sec = kani::any();
        let frac = kani::any();
        let incl = kani::any();
        let orig = kani::any();
        let b = encode_record_header(sec, frac, incl, orig);
        let (d_sec, d_frac, d_incl, d_orig) = decode_record_header(&b, false);
        assert_eq!(sec, d_sec);
        assert_eq!(frac, d_frac);
        assert_eq!(incl, d_incl);
        assert_eq!(orig, d_orig);
    }

    /// EPB fixed-field encode/decode is an involution on LE files:
    /// every symbolic `(iface, ts_high, ts_low, cap_len, orig_len)`
    /// survives the trip (the tranche-8b mirror of the header proof).
    #[kani::proof]
    fn epb_fields_roundtrip() {
        let iface = kani::any();
        let ts_high = kani::any();
        let ts_low = kani::any();
        let cap_len = kani::any();
        let orig = kani::any();
        let b = encode_epb_fields(iface, ts_high, ts_low, cap_len, orig);
        let (d_iface, d_high, d_low, d_cap, d_orig) = decode_epb_fields(&b, false);
        assert_eq!(iface, d_iface);
        assert_eq!(ts_high, d_high);
        assert_eq!(ts_low, d_low);
        assert_eq!(cap_len, d_cap);
        assert_eq!(orig, d_orig);
    }
}
