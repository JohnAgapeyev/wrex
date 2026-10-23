#![no_main]
//! libFuzzer target: the fragment reassembly engine (tranche T18a)
//! under arbitrary fragment streams. Invariants:
//!
//! - no panics: gaps, overlaps, duplicate offset-0 carriers,
//!   conflicting terminals, overhangs, empty/zero-length pieces and
//!   budget breaches are all *outcomes* (Pending/Complete/Overrun) or
//!   notes — never crashes (the engine splices offsets into byte
//!   buffers and must never underflow or corrupt);
//! - a completed datagram always carries the unfragmentable prefix
//!   (synthesized header) — whatever the piece soup;
//! - the frame-extraction path (`classify`) is fed through the real
//!   registry on fuzzed frames: any outcome is data, never a panic.
//!
//! The generated pieces are structured (family/key/offset/more/data
//! packed from the fuzz bytes) so the state machine's coverage — not
//! just the bytes — is randomized.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wrex::standard;
use wrex_core::dissect::dissect;
use wrex_frag::{Family, FragInfo, FragKey, PrefixRewrite, Reassembler};

#[derive(Arbitrary, Debug)]
struct FuzzPiece {
    family: bool,
    src: u32,
    dst: u32,
    proto: u8,
    ident: u32,
    offset_units: u16,
    more: bool,
    data: Vec<u8>,
}

fn info(p: &FuzzPiece) -> FragInfo {
    let (family, src, dst, prefix, rewrites) = if p.family {
        (
            Family::V4,
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(p.src.to_be())),
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(p.dst.to_be())),
            {
                // 20-byte header stand-in: total_len at 2, flags word at 6.
                let mut h = vec![0x45u8; 20];
                h[2] = 0;
                h[3] = 0;
                h[6] = 0x40 | if p.more { 0x80 } else { 0 };
                h
            },
            vec![PrefixRewrite::TotalLen(2), PrefixRewrite::ClearMf(6)],
        )
    } else {
        (
            Family::V6,
            v6_addr(p.src),
            v6_addr(p.dst),
            {
                let mut h = vec![0x60u8; 40];
                h[6] = 44; // next_header -> frag
                h
            },
            vec![PrefixRewrite::PayloadLen(4), PrefixRewrite::NextHeader(6, 17)],
        )
    };
    FragInfo {
        key: FragKey {
            src,
            dst,
            proto: p.proto,
            ident: p.ident,
        },
        family,
        offset: (p.offset_units as usize) * 8,
        more: p.more,
        prefix,
        rewrites,
        data: p.data.clone(),
    }
}

fuzz_target!(|stream: Vec<FuzzPiece>| {
    let registry = standard();
    let mut re = Reassembler::new(4096, std::time::Duration::from_secs(1));
    let mut now = 0u64;
    for piece in &stream {
        now += 1;
        // The classify path rides the real registry on the fuzzed data
        // (any outcome is data): exercise it alongside the engine.
        let _ = classify_probe(&registry, piece);
        match re.push(info(piece), now) {
            wrex_frag::Push::Complete(bytes) => {
                // Always carries the synthesized header (>= 20 bytes v4,
                // >= 40 v6) — whatever the piece soup.
                assert!(bytes.len() >= if piece.family { 20 } else { 40 });
            }
            wrex_frag::Push::Pending => {}
            wrex_frag::Push::Overrun => {}
        }
    }
    let _ = re.incomplete();
    let _ = re.evict_expired(now + 10_000_000);
});

fn v6_addr(seed: u32) -> std::net::IpAddr {
    let mut o = [0u8; 16];
    o[12..16].copy_from_slice(&seed.to_be_bytes());
    std::net::IpAddr::V6(std::net::Ipv6Addr::from(o))
}

fn classify_probe(registry: &wrex_core::Registry, piece: &FuzzPiece) {
    let frame = &piece.data;
    if !frame.is_empty() {
        let p = dissect(registry, frame, "auto");
        let _ = wrex_frag::classify(&p);
    }
}