//! The static HPACK Huffman code (RFC 7541 appendix B): decode and
//! (tranche 16a) encode.
//!
//! The table is generated from the RFC's appendix B `(sym, code, len)`
//! rows (verified at generation: bits == hex == len for every row).
//! Decode is bit-serial with a per-length sorted index — the code is
//! canonical per length, so a binary search per accumulated bit length
//! resolves each symbol. Encode emits each symbol's code MSB-first
//! and pads the final octet with the EOS prefix (§5.2: the padding is
//! the EOS code's leading bits, all 1s). The 16a
//! **encode-when-strictly-shorter** rule lives with the encoder's
//! policy (`hpack`); `huffman_encode` itself always encodes.

/// `(symbol, code, len)` for every symbol 0..=256 (256 = EOS).
/// Source: RFC 7541 appendix B.
#[rustfmt::skip]
pub static HUFFMAN_TABLE: [(u32, u32, u8); 257] = [
(0, 0x1ff8, 13),
    (1, 0x7fffd8, 23),
    (2, 0xfffffe2, 28),
    (3, 0xfffffe3, 28),
    (4, 0xfffffe4, 28),
    (5, 0xfffffe5, 28),
    (6, 0xfffffe6, 28),
    (7, 0xfffffe7, 28),
    (8, 0xfffffe8, 28),
    (9, 0xffffea, 24),
    (10, 0x3ffffffc, 30),
    (11, 0xfffffe9, 28),
    (12, 0xfffffea, 28),
    (13, 0x3ffffffd, 30),
    (14, 0xfffffeb, 28),
    (15, 0xfffffec, 28),
    (16, 0xfffffed, 28),
    (17, 0xfffffee, 28),
    (18, 0xfffffef, 28),
    (19, 0xffffff0, 28),
    (20, 0xffffff1, 28),
    (21, 0xffffff2, 28),
    (22, 0x3ffffffe, 30),
    (23, 0xffffff3, 28),
    (24, 0xffffff4, 28),
    (25, 0xffffff5, 28),
    (26, 0xffffff6, 28),
    (27, 0xffffff7, 28),
    (28, 0xffffff8, 28),
    (29, 0xffffff9, 28),
    (30, 0xffffffa, 28),
    (31, 0xffffffb, 28),
    (32, 0x14, 6),
    (33, 0x3f8, 10),
    (34, 0x3f9, 10),
    (35, 0xffa, 12),
    (36, 0x1ff9, 13),
    (37, 0x15, 6),
    (38, 0xf8, 8),
    (39, 0x7fa, 11),
    (40, 0x3fa, 10),
    (41, 0x3fb, 10),
    (42, 0xf9, 8),
    (43, 0x7fb, 11),
    (44, 0xfa, 8),
    (45, 0x16, 6),
    (46, 0x17, 6),
    (47, 0x18, 6),
    (48, 0x0, 5),
    (49, 0x1, 5),
    (50, 0x2, 5),
    (51, 0x19, 6),
    (52, 0x1a, 6),
    (53, 0x1b, 6),
    (54, 0x1c, 6),
    (55, 0x1d, 6),
    (56, 0x1e, 6),
    (57, 0x1f, 6),
    (58, 0x5c, 7),
    (59, 0xfb, 8),
    (60, 0x7ffc, 15),
    (61, 0x20, 6),
    (62, 0xffb, 12),
    (63, 0x3fc, 10),
    (64, 0x1ffa, 13),
    (65, 0x21, 6),
    (66, 0x5d, 7),
    (67, 0x5e, 7),
    (68, 0x5f, 7),
    (69, 0x60, 7),
    (70, 0x61, 7),
    (71, 0x62, 7),
    (72, 0x63, 7),
    (73, 0x64, 7),
    (74, 0x65, 7),
    (75, 0x66, 7),
    (76, 0x67, 7),
    (77, 0x68, 7),
    (78, 0x69, 7),
    (79, 0x6a, 7),
    (80, 0x6b, 7),
    (81, 0x6c, 7),
    (82, 0x6d, 7),
    (83, 0x6e, 7),
    (84, 0x6f, 7),
    (85, 0x70, 7),
    (86, 0x71, 7),
    (87, 0x72, 7),
    (88, 0xfc, 8),
    (89, 0x73, 7),
    (90, 0xfd, 8),
    (91, 0x1ffb, 13),
    (92, 0x7fff0, 19),
    (93, 0x1ffc, 13),
    (94, 0x3ffc, 14),
    (95, 0x22, 6),
    (96, 0x7ffd, 15),
    (97, 0x3, 5),
    (98, 0x23, 6),
    (99, 0x4, 5),
    (100, 0x24, 6),
    (101, 0x5, 5),
    (102, 0x25, 6),
    (103, 0x26, 6),
    (104, 0x27, 6),
    (105, 0x6, 5),
    (106, 0x74, 7),
    (107, 0x75, 7),
    (108, 0x28, 6),
    (109, 0x29, 6),
    (110, 0x2a, 6),
    (111, 0x7, 5),
    (112, 0x2b, 6),
    (113, 0x76, 7),
    (114, 0x2c, 6),
    (115, 0x8, 5),
    (116, 0x9, 5),
    (117, 0x2d, 6),
    (118, 0x77, 7),
    (119, 0x78, 7),
    (120, 0x79, 7),
    (121, 0x7a, 7),
    (122, 0x7b, 7),
    (123, 0x7ffe, 15),
    (124, 0x7fc, 11),
    (125, 0x3ffd, 14),
    (126, 0x1ffd, 13),
    (127, 0xffffffc, 28),
    (128, 0xfffe6, 20),
    (129, 0x3fffd2, 22),
    (130, 0xfffe7, 20),
    (131, 0xfffe8, 20),
    (132, 0x3fffd3, 22),
    (133, 0x3fffd4, 22),
    (134, 0x3fffd5, 22),
    (135, 0x7fffd9, 23),
    (136, 0x3fffd6, 22),
    (137, 0x7fffda, 23),
    (138, 0x7fffdb, 23),
    (139, 0x7fffdc, 23),
    (140, 0x7fffdd, 23),
    (141, 0x7fffde, 23),
    (142, 0xffffeb, 24),
    (143, 0x7fffdf, 23),
    (144, 0xffffec, 24),
    (145, 0xffffed, 24),
    (146, 0x3fffd7, 22),
    (147, 0x7fffe0, 23),
    (148, 0xffffee, 24),
    (149, 0x7fffe1, 23),
    (150, 0x7fffe2, 23),
    (151, 0x7fffe3, 23),
    (152, 0x7fffe4, 23),
    (153, 0x1fffdc, 21),
    (154, 0x3fffd8, 22),
    (155, 0x7fffe5, 23),
    (156, 0x3fffd9, 22),
    (157, 0x7fffe6, 23),
    (158, 0x7fffe7, 23),
    (159, 0xffffef, 24),
    (160, 0x3fffda, 22),
    (161, 0x1fffdd, 21),
    (162, 0xfffe9, 20),
    (163, 0x3fffdb, 22),
    (164, 0x3fffdc, 22),
    (165, 0x7fffe8, 23),
    (166, 0x7fffe9, 23),
    (167, 0x1fffde, 21),
    (168, 0x7fffea, 23),
    (169, 0x3fffdd, 22),
    (170, 0x3fffde, 22),
    (171, 0xfffff0, 24),
    (172, 0x1fffdf, 21),
    (173, 0x3fffdf, 22),
    (174, 0x7fffeb, 23),
    (175, 0x7fffec, 23),
    (176, 0x1fffe0, 21),
    (177, 0x1fffe1, 21),
    (178, 0x3fffe0, 22),
    (179, 0x1fffe2, 21),
    (180, 0x7fffed, 23),
    (181, 0x3fffe1, 22),
    (182, 0x7fffee, 23),
    (183, 0x7fffef, 23),
    (184, 0xfffea, 20),
    (185, 0x3fffe2, 22),
    (186, 0x3fffe3, 22),
    (187, 0x3fffe4, 22),
    (188, 0x7ffff0, 23),
    (189, 0x3fffe5, 22),
    (190, 0x3fffe6, 22),
    (191, 0x7ffff1, 23),
    (192, 0x3ffffe0, 26),
    (193, 0x3ffffe1, 26),
    (194, 0xfffeb, 20),
    (195, 0x7fff1, 19),
    (196, 0x3fffe7, 22),
    (197, 0x7ffff2, 23),
    (198, 0x3fffe8, 22),
    (199, 0x1ffffec, 25),
    (200, 0x3ffffe2, 26),
    (201, 0x3ffffe3, 26),
    (202, 0x3ffffe4, 26),
    (203, 0x7ffffde, 27),
    (204, 0x7ffffdf, 27),
    (205, 0x3ffffe5, 26),
    (206, 0xfffff1, 24),
    (207, 0x1ffffed, 25),
    (208, 0x7fff2, 19),
    (209, 0x1fffe3, 21),
    (210, 0x3ffffe6, 26),
    (211, 0x7ffffe0, 27),
    (212, 0x7ffffe1, 27),
    (213, 0x3ffffe7, 26),
    (214, 0x7ffffe2, 27),
    (215, 0xfffff2, 24),
    (216, 0x1fffe4, 21),
    (217, 0x1fffe5, 21),
    (218, 0x3ffffe8, 26),
    (219, 0x3ffffe9, 26),
    (220, 0xffffffd, 28),
    (221, 0x7ffffe3, 27),
    (222, 0x7ffffe4, 27),
    (223, 0x7ffffe5, 27),
    (224, 0xfffec, 20),
    (225, 0xfffff3, 24),
    (226, 0xfffed, 20),
    (227, 0x1fffe6, 21),
    (228, 0x3fffe9, 22),
    (229, 0x1fffe7, 21),
    (230, 0x1fffe8, 21),
    (231, 0x7ffff3, 23),
    (232, 0x3fffea, 22),
    (233, 0x3fffeb, 22),
    (234, 0x1ffffee, 25),
    (235, 0x1ffffef, 25),
    (236, 0xfffff4, 24),
    (237, 0xfffff5, 24),
    (238, 0x3ffffea, 26),
    (239, 0x7ffff4, 23),
    (240, 0x3ffffeb, 26),
    (241, 0x7ffffe6, 27),
    (242, 0x3ffffec, 26),
    (243, 0x3ffffed, 26),
    (244, 0x7ffffe7, 27),
    (245, 0x7ffffe8, 27),
    (246, 0x7ffffe9, 27),
    (247, 0x7ffffea, 27),
    (248, 0x7ffffeb, 27),
    (249, 0xffffffe, 28),
    (250, 0x7ffffec, 27),
    (251, 0x7ffffed, 27),
    (252, 0x7ffffee, 27),
    (253, 0x7ffffef, 27),
    (254, 0x7fffff0, 27),
    (255, 0x3ffffee, 26),
    (256, 0x3fffffff, 30),
];

/// EOS symbol value.
const EOS: u32 = 256;

/// Decode a Huffman-coded string literal (RFC 7541 §5.2). Errors are
/// pointed and never fatal to the caller's memory: the output is
/// bounded by the input length (worst case 8x expansion is impossible —
/// every symbol consumes ≥5 bits).
pub fn huffman_decode(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(data.len());
    for &byte in data {
        for i in (0..8).rev() {
            acc = (acc << 1) | u32::from((byte >> i) & 1);
            bits += 1;
            if let Some(sym) = lookup(acc, bits) {
                if sym == EOS {
                    return Err("huffman: EOS symbol in data".to_string());
                }
                out.push(sym as u8);
                acc = 0;
                bits = 0;
            }
        }
    }
    // Trailing padding (RFC 7541 §5.2): <8 bits, and the MSB prefix of
    // the EOS code, else a decoding error.
    if bits > 0 {
        if bits >= 8 {
            return Err("huffman: padding longer than 7 bits".to_string());
        }
        let (_, eos_code, eos_len) = HUFFMAN_TABLE[EOS as usize];
        let eos_prefix = eos_code >> (u32::from(eos_len) - bits);
        if acc != eos_prefix {
            return Err("huffman: padding is not the EOS prefix".to_string());
        }
    }
    Ok(out)
}

/// Encode `data` with the static Huffman code (RFC 7541 §5.2): each
/// symbol's code MSB-first, the final partial octet padded with the
/// EOS prefix (1 bits). Every output decodes back through
/// [`huffman_decode`] to exactly `data`.
pub fn huffman_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() * 5 / 8 + 1);
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        let (_, code, len) = HUFFMAN_TABLE[b as usize];
        acc = (acc << len) | u64::from(code);
        bits += u32::from(len);
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1u64 << bits) - 1;
        }
    }
    if bits > 0 {
        // Pad with the EOS prefix (all 1 bits — the decoder's padding
        // check accepts exactly that prefix).
        let pad = 8 - bits;
        out.push(((acc << pad) | ((1u64 << pad) - 1)) as u8);
    }
    out
}

/// Encoded length of `data` (the [`huffman_encode`] output length).
/// (const: index loop — the iter().map().sum() closure chain is not
/// const-callable.)
pub const fn huffman_encoded_len(data: &[u8]) -> usize {
    let mut bits: usize = 0;
    let mut i = 0;
    while i < data.len() {
        bits += HUFFMAN_TABLE[data[i] as usize].2 as usize;
        i += 1;
    }
    bits.div_ceil(8)
}

/// Resolve `(acc, bits)` to a symbol via the per-length sorted index.
fn lookup(acc: u32, bits: u32) -> Option<u32> {
    let by_len = index();
    let slice = &by_len[bits as usize];
    let pos = slice.binary_search_by(|probe| probe.0.cmp(&acc));
    match pos {
        Ok(i) => Some(slice[i].1),
        Err(_) => None,
    }
}

/// Per-length `(code, sym)` lists, sorted by code (canonical within a
/// length — one symbol per code). Built once.
/// Per-length `(code, sym)` lists (index by bit length).
type CodeIndex = Box<[Vec<(u32, u32)>; 31]>;

fn index() -> &'static CodeIndex {
    static INDEX: std::sync::OnceLock<CodeIndex> = std::sync::OnceLock::new();
    INDEX.get_or_init(|| {
        let mut idx: Box<[Vec<(u32, u32)>; 31]> = Box::new(std::array::from_fn(|_| Vec::new()));
        for &(sym, code, len) in HUFFMAN_TABLE.iter() {
            idx[len as usize].push((code, sym));
        }
        for list in idx.iter_mut() {
            list.sort_by_key(|&(code, _)| code);
        }
        idx
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7541 C.4.1: `www.example.com` Huffman-coded inside the
    /// :authority literal (`f1e3 c2e5 f23a 6ba0 ab90 f4ff`).
    #[test]
    fn decodes_rfc_c41_authority() {
        let out = huffman_decode(&[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ])
        .expect("c4.1 authority");
        assert_eq!(out, b"www.example.com");
    }

    /// RFC 7541 C.4.2: `no-cache` as `a8eb 1064 9cbf`.
    #[test]
    fn decodes_rfc_c42_no_cache() {
        let out = huffman_decode(&[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]).expect("c4.2 value");
        assert_eq!(out, b"no-cache");
    }

    /// RFC 7541 C.4.3: `custom-key`/`custom-value` literals.
    #[test]
    fn decodes_rfc_c43_custom() {
        let key = huffman_decode(&[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f]).expect("key");
        assert_eq!(key, b"custom-key");
        let val =
            huffman_decode(&[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf]).expect("val");
        assert_eq!(val, b"custom-value");
    }

    /// RFC 7541 C.6.2: `307` Huffman-coded as `640e ff`.
    #[test]
    fn decodes_rfc_c62_status() {
        let out = huffman_decode(&[0x64, 0x0e, 0xff]).expect("status");
        assert_eq!(out, b"307");
    }

    #[test]
    fn rejects_eos_in_data_and_bad_padding() {
        // EOS code (30 bits of 1s): the raw code bits as whole bytes
        // must be a decoding error (EOS in data).
        let code = HUFFMAN_TABLE[256].1;
        let bits: Vec<bool> = (0..30).rev().map(|i| ((code >> i) & 1) == 1).collect();
        let mut bytes = Vec::new();
        for chunk in bits.chunks(8) {
            let mut b = 0u8;
            for (i, bit) in chunk.iter().enumerate() {
                if *bit {
                    b |= 1 << (7 - i);
                }
            }
            bytes.push(b);
        }
        assert_eq!(bytes.len(), 4); // 30 bits + 2 padding bits
        assert!(
            huffman_decode(&bytes).is_err(),
            "EOS-in-data must be a pointed error"
        );
        // 7 zero bits: no symbol resolves and the EOS prefix is 1s —
        // a pointed padding error, never a panic.
        assert!(
            huffman_decode(&[0x00]).is_err(),
            "all-zero padding must error"
        );
    }

    #[test]
    fn table_is_wellformed() {
        // One entry per symbol, codes unique, lengths within 5..=30.
        assert_eq!(HUFFMAN_TABLE.len(), 257);
        for (i, &(sym, code, len)) in HUFFMAN_TABLE.iter().enumerate() {
            assert_eq!(sym, i as u32);
            assert!((5..=30).contains(&len), "sym {sym} len {len}");
            assert!(code < (1u32 << len), "sym {sym} code exceeds len");
        }
    }

    // --- encode (tranche 16a) --------------------------------------------

    /// RFC 7541 C.4.1: `www.example.com` → `f1e3 c2e5 f23a 6ba0 ab90
    /// f4ff`.
    #[test]
    fn encodes_rfc_c41_authority() {
        let out = huffman_encode(b"www.example.com");
        assert_eq!(
            out,
            vec![
                0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff
            ]
        );
        assert_eq!(out.len(), huffman_encoded_len(b"www.example.com"));
    }

    /// RFC 7541 C.4.2: `no-cache` → `a8eb 1064 9cbf`.
    #[test]
    fn encodes_rfc_c42_no_cache() {
        assert_eq!(
            huffman_encode(b"no-cache"),
            vec![0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]
        );
    }

    /// RFC 7541 C.4.3: `custom-key`/`custom-value` literals.
    #[test]
    fn encodes_rfc_c43_custom() {
        assert_eq!(
            huffman_encode(b"custom-key"),
            vec![0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f]
        );
        assert_eq!(
            huffman_encode(b"custom-value"),
            vec![0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf]
        );
    }

    #[test]
    fn encodes_rfc_c62_status() {
        // RFC 7541 C.6.2: `307` → `640e ff`.
        assert_eq!(huffman_encode(b"307"), vec![0x64, 0x0e, 0xff]);
    }

    #[test]
    fn every_byte_roundtrips() {
        for b in 0..=u8::MAX {
            let enc = huffman_encode(&[b]);
            assert_eq!(huffman_decode(&enc).unwrap(), vec![b], "byte {b}");
        }
        // multi-symbol strings, including the empty string (zero bytes:
        // no padding at all).
        for s in [
            &b""[..],
            b"a",
            b"www.example.com",
            b"no-cache",
            b"custom-key",
            b"custom-value",
            b"307",
            b"0123456789 abcdefghijklmnopqrstuvwxyz",
            &[0u8, 1, 128, 255][..],
        ] {
            let enc = huffman_encode(s);
            assert_eq!(enc.len(), huffman_encoded_len(s));
            assert_eq!(huffman_decode(&enc).unwrap(), s, "{s:?}");
        }
    }
}
