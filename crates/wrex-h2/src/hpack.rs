//! HPACK (RFC 7541): the static table, the integer/string primitives,
//! the dynamic table with size accounting + eviction, the decoder, and
//! wrex's deterministic literal encoder.
//!
//! **Disposition (ADR 2, T15 planning)**: HPACK is *owned* — byte
//! control over the header block is the point. Decode implements the
//! full §6 grammar (indexed, literal with/without indexing,
//! never-indexed, dynamic-table size updates, Huffman strings).
//! **Encode is deliberately literal**: every field goes out as a
//! literal-without-indexing representation with raw (no-Huffman)
//! strings — deterministic recipe bytes, no dynamic-table state on the
//! send side (Huffman *encode* and incremental indexing are recorded
//! deferrals). Every encoding this module produces decodes to exactly
//! what went in (roundtrip-tested).

use std::collections::VecDeque;

use bytes::{BufMut as _, Bytes, BytesMut};

use crate::huffman::huffman_decode;

/// One static-table entry (RFC 7541 appendix A). Index = position + 1.
pub fn static_entry(idx: usize) -> Option<(&'static str, &'static str)> {
    STATIC_TABLE.get(idx).copied()
}

/// The static table (RFC 7541 appendix A, 61 entries).
#[rustfmt::skip]
pub static STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// One decoded header field (name octets, value octets).
pub type HeaderField = (Vec<u8>, Vec<u8>);

/// One decoded header list (order preserved, duplicates kept).
pub type HeaderList = Vec<HeaderField>;

/// Entry overhead in the dynamic-table size accounting (RFC 7541 §4.1).
const ENTRY_OVERHEAD: usize = 32;

/// Default dynamic table capacity (SETTINGS_HEADER_TABLE_SIZE).
pub const DEFAULT_MAX_SIZE: usize = 4096;

/// Integer primitives (RFC 7541 §5.1). `prefix` is the bit width of the
/// first octet's high bits already consumed by the representation.
pub fn encode_integer(out: &mut BytesMut, prefix: u8, mut value: u32) {
    let max_prefix = (1u32 << prefix) - 1;
    if value < max_prefix {
        out.put_u8(value as u8);
        return;
    }
    out.put_u8(max_prefix as u8);
    value -= max_prefix;
    while value >= 128 {
        out.put_u8((value % 128 + 128) as u8);
        value /= 128;
    }
    out.put_u8(value as u8);
}

/// Decode one integer with a `prefix`-bit prefix from `buf` (the caller
/// has already consumed the pattern bits of `buf[0]`'s low bits —
/// `prefix` bits of the first octet belong to the integer).
pub fn decode_integer(buf: &[u8], prefix: u8) -> Result<(u32, usize), String> {
    let Some(&first) = buf.first() else {
        return Err("integer: empty".to_string());
    };
    let mask = if prefix == 8 { 0xff } else { (1 << prefix) - 1 };
    let max_prefix = (1u32 << prefix) - 1;
    let mut value = u32::from(first & mask);
    if value < max_prefix {
        return Ok((value, 1));
    }
    let mut consumed = 1usize;
    let mut shift = 0u32;
    while let Some(&b) = buf.get(consumed) {
        consumed += 1;
        value = value
            .checked_add(
                u32::from(b & 0x7f)
                    .checked_mul(1 << shift)
                    .ok_or_else(|| "integer: overflow".to_string())?,
            )
            .ok_or_else(|| "integer: overflow".to_string())?;
        if b & 0x80 == 0 {
            return Ok((value, consumed));
        }
        shift += 7;
        if shift > 28 {
            return Err("integer: too long".to_string());
        }
    }
    Err("integer: truncated".to_string())
}

/// One string literal (RFC 7541 §5.2): H bit + 7-bit-prefix length +
/// data (raw or Huffman).
fn encode_string(out: &mut BytesMut, value: &[u8]) {
    // Never Huffman (the crate rule): H = 0.
    encode_integer(out, 7, value.len() as u32);
    out.extend_from_slice(value);
}

/// Decode one string literal; returns `(bytes, consumed)`.
fn decode_string(buf: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let Some(&first) = buf.first() else {
        return Err("string: empty".to_string());
    };
    let huff = first & 0x80 != 0;
    let (len, mut consumed) = decode_integer(buf, 7)?;
    let len = len as usize;
    // A lying length must not panic or read past the buffer.
    if len > MAX_STRING {
        return Err("string: length over budget".to_string());
    }
    if buf.len() < consumed + len {
        return Err("string: truncated".to_string());
    }
    let data = &buf[consumed..consumed + len];
    consumed += len;
    let out = if huff {
        huffman_decode(data)?
    } else {
        data.to_vec()
    };
    Ok((out, consumed))
}

/// Bound on a single decoded string (implementation limit, RFC 7541
/// §7.4 — a prober budget, not a protocol rule).
pub const MAX_STRING: usize = 64 * 1024;

/// Find a full static-table match (name+value) → its 1-based index.
fn static_full(name: &[u8], value: &[u8]) -> Option<u8> {
    STATIC_TABLE
        .iter()
        .position(|&(n, v)| n.as_bytes() == name && v.as_bytes() == value)
        .map(|i| i as u8 + 1)
}

/// Find the first static-table name match → its 1-based index.
fn static_name(name: &[u8]) -> Option<u8> {
    STATIC_TABLE
        .iter()
        .position(|&(n, _)| n.as_bytes() == name)
        .map(|i| i as u8 + 1)
}

/// Encode one header list as a deterministic literal block: indexed
/// representation for exact static matches, literal-without-indexing
/// (indexed name where the static table knows it) otherwise. No
/// dynamic-table state on the send side (the crate rule).
pub fn encode_header_block(headers: &[(&str, &str)]) -> Bytes {
    let mut out = BytesMut::new();
    for &(name, value) in headers {
        let (name, value) = (name.as_bytes(), value.as_bytes());
        if let Some(idx) = static_full(name, value) {
            // Indexed (§6.1): 1 + 7-bit index. Static matches are
            // always < 127, so one octet — the pattern bit set by hand.
            out.put_u8(0x80 | idx);
        } else if let Some(idx) = static_name(name) {
            // Literal without indexing, indexed name (§6.2.2):
            // 0000 + 4-bit index, then the value string.
            encode_integer(&mut out, 4, idx as u32);
            encode_string(&mut out, value);
        } else {
            // Literal without indexing, new name (§6.2.2): 0000 0000,
            // name string, value string.
            out.put_u8(0);
            encode_string(&mut out, name);
            encode_string(&mut out, value);
        }
    }
    out.freeze()
}

/// The HPACK decoding context: the dynamic table plus its size cap.
#[derive(Debug)]
pub struct HpackDecoder {
    table: VecDeque<(Vec<u8>, Vec<u8>)>,
    size: usize,
    max_size: usize,
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_SIZE)
    }
}

impl HpackDecoder {
    pub fn new(max_size: usize) -> Self {
        Self {
            table: VecDeque::new(),
            size: 0,
            max_size,
        }
    }

    /// Apply a new size cap (evicting per §4.3). Used by
    /// SETTINGS_HEADER_TABLE_SIZE.
    pub fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
        self.evict();
    }

    fn evict(&mut self) {
        while self.size > self.max_size {
            if let Some((name, value)) = self.table.pop_back() {
                self.size -= name.len() + value.len() + ENTRY_OVERHEAD;
            } else {
                break;
            }
        }
    }

    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let entry = name.len() + value.len() + ENTRY_OVERHEAD;
        if entry > self.max_size {
            // §4.4: adding a too-large entry empties the table.
            self.table.clear();
            self.size = 0;
            return;
        }
        self.evict_to(self.max_size.saturating_sub(entry));
        self.table.push_front((name, value));
        self.size += entry;
    }

    fn evict_to(&mut self, limit: usize) {
        while self.size > limit {
            if let Some((name, value)) = self.table.pop_back() {
                self.size -= name.len() + value.len() + ENTRY_OVERHEAD;
            } else {
                break;
            }
        }
    }

    /// Decode one header block (§3.2). Never panics; pointed errors.
    pub fn decode(&mut self, mut block: &[u8]) -> Result<HeaderList, String> {
        let mut out = Vec::new();
        while !block.is_empty() {
            let b = block[0];
            if b & 0x80 != 0 {
                // Indexed (§6.1).
                let (idx, used) = decode_integer(block, 7)?;
                if idx == 0 {
                    return Err("indexed representation with index 0".to_string());
                }
                let (name, value) = self.lookup(idx as usize)?;
                out.push((name, value));
                block = &block[used..];
            } else if b & 0xc0 == 0x40 {
                // Literal with incremental indexing (§6.2.1).
                let (idx, used) = decode_integer(block, 6)?;
                block = &block[used..];
                let name = if idx == 0 {
                    let (n, used) = decode_string(block)?;
                    block = &block[used..];
                    n
                } else {
                    self.lookup_name(idx as usize)?
                };
                let (value, vused) = decode_string(block)?;
                block = &block[vused..];
                self.insert(name.clone(), value.clone());
                out.push((name, value));
            } else if b & 0xe0 == 0x20 {
                // Dynamic table size update (§6.3) — the 001 prefix.
                let (new_max, used) = decode_integer(block, 5)?;
                if new_max as usize > self.max_size {
                    return Err("table size update above our cap".to_string());
                }
                self.set_max_size(new_max as usize);
                block = &block[used..];
            } else if b & 0xf0 == 0 {
                // Literal without indexing (§6.2.2) — the 0000 prefix.
                let (idx, used) = decode_integer(block, 4)?;
                block = &block[used..];
                let name = if idx == 0 {
                    let (n, used) = decode_string(block)?;
                    block = &block[used..];
                    n
                } else {
                    self.lookup_name(idx as usize)?
                };
                let (value, vused) = decode_string(block)?;
                block = &block[vused..];
                out.push((name, value));
            } else {
                // b & 0xf0 == 0x10: literal never indexed (§6.2.3).
                let (idx, used) = decode_integer(block, 4)?;
                block = &block[used..];
                let name = if idx == 0 {
                    let (n, used) = decode_string(block)?;
                    block = &block[used..];
                    n
                } else {
                    self.lookup_name(idx as usize)?
                };
                let (value, vused) = decode_string(block)?;
                block = &block[vused..];
                out.push((name, value));
            }
        }
        Ok(out)
    }

    /// Whole-table lookup (§2.3.3): 1..=61 static, then dynamic
    /// (overall 62 = `table[0]`).
    fn lookup(&self, idx: usize) -> Result<(Vec<u8>, Vec<u8>), String> {
        if let Some(entry) = static_entry(idx.wrapping_sub(1)) {
            return Ok((entry.0.as_bytes().to_vec(), entry.1.as_bytes().to_vec()));
        }
        match self.dynamic(idx.saturating_sub(STATIC_TABLE.len() + 1)) {
            Some((name, value)) => Ok((name.clone(), value.clone())),
            None => Err(format!("index {idx} out of range")),
        }
    }

    fn lookup_name(&self, idx: usize) -> Result<Vec<u8>, String> {
        if let Some(entry) = static_entry(idx.wrapping_sub(1)) {
            return Ok(entry.0.as_bytes().to_vec());
        }
        match self.dynamic(idx.saturating_sub(STATIC_TABLE.len() + 1)) {
            Some((name, _)) => Ok(name.clone()),
            None => Err(format!("name index {idx} out of range")),
        }
    }

    /// Dynamic-table position for an overall index (0-based).
    fn dynamic(&self, pos: usize) -> Option<&(Vec<u8>, Vec<u8>)> {
        self.table.get(pos)
    }

    /// The current dynamic table (test/diagnostic surface).
    pub fn dynamic_entries(&self) -> &VecDeque<(Vec<u8>, Vec<u8>)> {
        &self.table
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        hex::decode(s).unwrap()
    }

    fn headers_of(pairs: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
        pairs
            .iter()
            .map(|&(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect()
    }

    // --- primitives (RFC 7541 appendix C.1) ------------------------------

    #[test]
    fn integer_encode_examples() {
        // C.1.1: 10 with 5-bit prefix → 0x0a.
        let mut out = BytesMut::new();
        encode_integer(&mut out, 5, 10);
        assert_eq!(&out[..], &[0x0a]);
        // C.1.2: 1337 with 5-bit prefix → 1f 9a 0a.
        out.clear();
        encode_integer(&mut out, 5, 1337);
        assert_eq!(&out[..], &[0x1f, 0x9a, 0x0a]);
        // C.1.3: 42 at octet boundary → 2a.
        out.clear();
        encode_integer(&mut out, 8, 42);
        assert_eq!(&out[..], &[0x2a]);
    }

    #[test]
    fn integer_decode_examples_and_roundtrip() {
        assert_eq!(decode_integer(&[0x0a], 5).unwrap(), (10, 1));
        let (v, used) = decode_integer(&[0x1f, 0x9a, 0x0a], 5).unwrap();
        assert_eq!((v, used), (1337, 3));
        assert_eq!(decode_integer(&[0x2a], 8).unwrap(), (42, 1));
        // roundtrip across prefixes and magnitudes
        for prefix in [4u8, 5, 6, 7, 8] {
            for value in [0u32, 1, 13, 14, 15, 127, 128, 1337, 65_535, 1 << 20] {
                let mut out = BytesMut::new();
                encode_integer(&mut out, prefix, value);
                let (back, _) = decode_integer(&out, prefix).unwrap();
                assert_eq!(back, value, "prefix {prefix} value {value}");
            }
        }
    }

    // --- encoder/decoder roundtrip ---------------------------------------

    #[test]
    fn literal_roundtrip_arbitrary_headers() {
        let headers = [
            (":method", "GET"),
            (":scheme", "https"),
            (":path", "/x"),
            (":authority", "example.test"),
            ("custom-key", "custom-value"),
            ("x-binary", "\u{1}\u{2}"),
        ];
        let block = encode_header_block(&headers);
        let mut dec = HpackDecoder::default();
        let back = dec.decode(&block).unwrap();
        assert_eq!(back, headers_of(&headers));
        assert!(dec.dynamic_entries().is_empty(), "no indexing on send");
    }

    // --- RFC 7541 appendix C known-answer vectors ------------------------

    #[test]
    fn c22_literal_without_indexing() {
        let mut dec = HpackDecoder::default();
        // custom-key: custom-value, without Huffman (C.2.2).
        let block = hex("000a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65");
        let out = dec.decode(&block).unwrap();
        assert_eq!(out, headers_of(&[("custom-key", "custom-value")]));
        assert!(dec.dynamic_entries().is_empty());
        // …and wrex's own encoder emits exactly these bytes for the
        // pair (literal-without-indexing, new name, no Huffman).
        assert_eq!(
            &encode_header_block(&[("custom-key", "custom-value")])[..],
            &block[..]
        );
    }

    #[test]
    fn c23_literal_never_indexed() {
        let mut dec = HpackDecoder::default();
        // password: secret (C.2.3) — the 0001 prefix.
        let block = hex("10 08 7061 7373 776f 7264 06 7365 6372 6574");
        let out = dec.decode(&block).unwrap();
        assert_eq!(out, headers_of(&[("password", "secret")]));
    }

    #[test]
    fn c24_indexed() {
        let mut dec = HpackDecoder::default();
        let out = dec.decode(&hex("82")).unwrap();
        assert_eq!(out, headers_of(&[(":method", "GET")]));
    }

    #[test]
    fn c3_request_sequence_without_huffman() {
        let mut dec = HpackDecoder::default();
        // C.3.1 first request
        let out = dec
            .decode(&hex("8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d"))
            .unwrap();
        assert_eq!(
            out,
            headers_of(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ])
        );
        assert_eq!(dec.size(), 57, "dynamic table entry size");
        assert_eq!(dec.dynamic_entries().len(), 1);
        // C.3.2 second request — idx 62 is the dynamic :authority.
        let out = dec
            .decode(&hex("8286 84be 5808 6e6f 2d63 6163 6865"))
            .unwrap();
        assert_eq!(
            out,
            headers_of(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ])
        );
        assert_eq!(dec.size(), 110);
        // C.3.3 third request — https + /index.html + custom-key.
        let out = dec
            .decode(&hex(
                "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65",
            ))
            .unwrap();
        assert_eq!(
            out,
            headers_of(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value"),
            ])
        );
        assert_eq!(dec.size(), 164);
    }

    #[test]
    fn c42_request_with_huffman() {
        let mut dec = HpackDecoder::default();
        // C.4.1: authority literal Huffman-coded (f1e3 c2e5 ...).
        let out = dec
            .decode(&hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"))
            .unwrap();
        assert_eq!(
            out,
            headers_of(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ])
        );
        // C.4.2 second request: dynamic idx 62 + Huffman no-cache.
        let out = dec.decode(&hex("8286 84be 5886 a8eb 1064 9cbf")).unwrap();
        assert_eq!(
            out.last().unwrap(),
            &(b"cache-control".to_vec(), b"no-cache".to_vec())
        );
        // C.4.3 third request: custom-key/custom-value Huffman literals.
        let out = dec
            .decode(&hex(
                "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
            ))
            .unwrap();
        assert_eq!(out[4], (b"custom-key".to_vec(), b"custom-value".to_vec()));
    }

    #[test]
    fn c5_response_sequence_with_eviction() {
        // SETTINGS_HEADER_TABLE_SIZE = 256 for the whole sequence (the
        // module models the C.5 narrative).
        let mut dec = HpackDecoder::new(256);
        // C.5.1 first response.
        let out = dec
            .decode(&hex(
                "4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
            ))
            .unwrap();
        assert_eq!(out[0], (b":status".to_vec(), b"302".to_vec()));
        assert_eq!(dec.size(), 222);
        // C.5.2 second response: :status 307 evicts the 302.
        let out = dec.decode(&hex("4803 3330 37c1 c0bf")).unwrap();
        assert_eq!(out[0], (b":status".to_vec(), b"307".to_vec()));
        assert_eq!(dec.size(), 222);
        assert_eq!(dec.dynamic_entries().len(), 4);
        // C.5.3 third response: set-cookie (56-octet value) evicts.
        let out = dec
            .decode(&hex(
                "88 c1 61 1d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3220 474d 54 c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 514b 425a 584f 5157 454f 5049 5541 5851 5745 4f49 553b 206d 6178 2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e 3d31",
            ))
            .unwrap();
        assert_eq!(out[0], (b":status".to_vec(), b"200".to_vec()));
        assert!(
            out.iter()
                .any(|(n, v)| n.as_slice() == b"set-cookie" && v.starts_with(b"foo=AS"))
        );
    }

    #[test]
    fn c62_response_with_huffman() {
        let mut dec = HpackDecoder::new(256);
        // C.6.2: :status 307 as a literal-with-indexing :status value,
        // Huffman-coded (640e ff). The c1/c0/bf tail references the
        // C.6.1 dynamic table and stays with the C.6 sequence.
        let out = dec.decode(&hex("4883 640e ff")).unwrap();
        assert_eq!(out, vec![(b":status".to_vec(), b"307".to_vec())]);
        assert_eq!(dec.dynamic_entries().len(), 1);
    }

    #[test]
    fn table_size_update_and_cap() {
        // §6.3: 001 + 5-bit prefix, MUST be ≤ our current cap.
        let mut dec = HpackDecoder::default();
        dec.decode(&hex("20")).unwrap(); // cap down to 0
        assert_eq!(dec.size(), 0);
        // A cap above our limit is a pointed error (the settings value
        // is the protocol limit).
        let mut small = HpackDecoder::new(40);
        assert!(
            small.decode(&hex("3f e9 07")).is_err(),
            "114824 must exceed the 40-octet cap"
        );
        // SETTINGS-driven eviction (§4.3) drops from the back.
        let mut dec = HpackDecoder::default();
        dec.decode(&hex("41 03 6162 63")).unwrap(); // :authority: abc (size 45)
        dec.decode(&hex("41 03 6465 66")).unwrap(); // :authority: def (size 45)
        assert_eq!(dec.size(), 90);
        assert_eq!(dec.dynamic_entries().len(), 2);
        dec.set_max_size(50); // evicts the oldest ("abc") → 45 ≤ 50
        assert_eq!(dec.dynamic_entries().len(), 1);
        assert_eq!(dec.dynamic_entries()[0].1, b"def".to_vec());
        assert_eq!(dec.size(), 45);
    }

    #[test]
    fn pointed_errors() {
        let mut dec = HpackDecoder::default();
        assert!(dec.decode(&hex("80")).is_err(), "indexed 0");
        assert!(dec.decode(&hex("7f ff")).is_err(), "truncated index");
        assert!(dec.decode(&hex("beff")).is_err(), "index out of range");
        assert!(dec.decode(&hex("40")).is_err(), "truncated literal name");
        // lying string length
        let mut dec2 = HpackDecoder::default();
        assert!(dec2.decode(&hex("40 7f ff")).is_err(), "length over budget");
    }

    #[test]
    fn oversized_literal_never_panic() {
        let mut dec = HpackDecoder::default();
        // A 64 KiB-1 name literal (just under the budget) decodes; the
        // lying-length / truncated shapes error pointedly.
        let n = MAX_STRING - 1;
        let mut block = vec![0u8];
        let mut int = BytesMut::new();
        encode_integer(&mut int, 7, n as u32);
        block.extend_from_slice(&int);
        block.extend(std::iter::repeat_n(b'a', n));
        block.push(0); // empty value string
        let out = dec.decode(&block).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.len(), n);
        // exactly at budget + 1: a pointed error, never a panic.
        let n = MAX_STRING + 1;
        let mut block = vec![0u8];
        let mut int = BytesMut::new();
        encode_integer(&mut int, 7, n as u32);
        block.extend_from_slice(&int);
        block.extend(std::iter::repeat_n(b'a', n));
        block.push(0);
        let mut dec2 = HpackDecoder::default();
        assert!(dec2.decode(&block).is_err(), "over-budget literal");
    }
}
