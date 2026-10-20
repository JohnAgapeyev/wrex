#![forbid(unsafe_code)]
//! wrex-pcap: classic pcap file format, in-house (no libpcap).
//!
//! Tranche 5 (capture/replay). The reader accepts every classic-pcap
//! magic variant — little/big endian × micro/nanosecond resolution — and
//! keeps the record timestamps the tranche-1 corpus reader discarded.
//! The writer emits little-endian microsecond Ethernet files (the
//! `wrex capture` shape). pcapng is out of the tranche-5 charter.

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
    /// None of the four classic magic values.
    #[error("not a classic pcap (magic 0x{magic:08x}); pcapng is out of the tranche-5 charter")]
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
}

impl PcapRecord {
    /// A record with explicit parts (the writer's reader-side mirror).
    pub fn from_parts(ts: SystemTime, bytes: Vec<u8>, orig_len: u32) -> Self {
        Self {
            ts,
            bytes,
            orig_len,
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

/// Encode one record header (little-endian microsecond, the writer path).
fn encode_record_header(
    ts_sec: u32,
    ts_frac: u32,
    incl_len: u32,
    orig_len: u32,
) -> [u8; RECORD_LEN] {
    let mut b = [0u8; RECORD_LEN];
    b[..4].copy_from_slice(&ts_sec.to_le_bytes());
    b[4..8].copy_from_slice(&ts_frac.to_le_bytes());
    b[8..12].copy_from_slice(&incl_len.to_le_bytes());
    b[12..].copy_from_slice(&orig_len.to_le_bytes());
    b
}

/// Decode one record header under a byte order.
fn decode_record_header(b: &[u8; RECORD_LEN], big_endian: bool) -> (u32, u32, u32, u32) {
    let pick = |off: usize| -> u32 {
        let raw = [b[off], b[off + 1], b[off + 2], b[off + 3]];
        if big_endian {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        }
    };
    (pick(0), pick(4), pick(8), pick(12))
}

/// Parse a classic pcap file (all four magic variants).
///
/// Frames past a truncated record are an error (the file is corrupt);
/// everything else — odd tail bytes, zero records — parses cleanly.
pub fn read(bytes: &[u8]) -> Result<PcapFile, PcapError> {
    if bytes.len() < GLOBAL_LEN {
        return Err(PcapError::TooShort { len: bytes.len() });
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
        });
        off += incl;
        index += 1;
    }
    Ok(PcapFile {
        linktype,
        snaplen,
        nanosecond,
        big_endian,
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
        let (sec, frac) = ts_parts(ts);
        let orig = u32::try_from(frame.len()).unwrap_or(u32::MAX);
        let incl = frame.len().min(snaplen);
        let incl = u32::try_from(incl).unwrap_or(u32::MAX);
        self.inner
            .write_all(&encode_record_header(sec, frac, incl, orig))?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
