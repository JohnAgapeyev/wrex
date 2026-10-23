#![no_main]
//! libFuzzer target: the `--filter` engine (`wrex-core/src/filter.rs`)
//! under arbitrary filter expressions against real corpus frames.
//! Invariants:
//!
//! - `Filter::parse` never panics: malformed terms are pointed
//!   `FilterError`s (typo'd layer, unknown field, bad value — data,
//!   not crashes);
//! - a parsed filter matched against any dissected packet never panics
//!   and is deterministic (same filter + frame ⇒ same verdict);
//! - verdicts are total: absent paths are false, never an error.
//!
//! The engine gates every `recv --filter`, `patch --filter` and
//! `send --wait-reply` user: it parses `<path><op><value>` AND-terms
//! with ops = != < <= > >=, values across ints, CIDR v4/v6, MACs,
//! hex prefixes, flag names and flag bits.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wrex::standard;
use wrex_core::dissect::dissect;
use wrex_core::filter::Filter;

/// Path vocabulary: real dissected paths (incl. bit subpaths), paths
/// absent from the fixture (must be false, never an error), and path
/// grammar edges.
const PATHS: &[&str] = &[
    "eth.dst",
    "eth.src",
    "eth.type",
    "ipv4.src",
    "ipv4.dst",
    "ipv4.ttl",
    "ipv4.proto",
    "ipv4.flags.df",
    "tcp.flags.syn",
    "udp.sport",
    "udp.dport",
    "udp.checksum",
    "icmp.type",
    "icmpv6.type",
    "dns.qd.0.name",
    "nope",
    "no.such.field",
    "eth",
    "",
];

/// Value vocabulary: the full grammar surface per filter.rs — ints,
/// CIDR, bare v6, MACs, hex prefixes, flag names, bools, junk.
const VALUES: &[&str] = &[
    "0",
    "63",
    "0x3f",
    "2048",
    "1",
    "0.0.0.0/0",
    "127.0.0.1",
    "10.0.0.0/8",
    "::1",
    "2001:db8::/32",
    "ff02::1",
    "00:11:22:33:44:55",
    "ff:ff:ff:ff:ff:ff",
    "dead",
    "deadbe",
    "0a",
    "syn",
    "syn,ack",
    "syn+ack",
    "df",
    "true",
    "false",
    "",
    "-1",
    "999999999999999999999999",
    "zzzz",
    "127.0.0.999",
    "::1/129",
    "10.0.0.0/33",
];

#[derive(Arbitrary, Debug)]
struct FuzzFilter {
    frame_idx: u8,
    /// (path_idx, op_idx, value_idx) triples.
    terms: Vec<(u8, u8, u8)>,
}

fn realize(terms: &[(u8, u8, u8)]) -> String {
    const OPS: &[&str] = &["=", "!=", "<", "<=", ">", ">="];
    terms
        .iter()
        .map(|(p, o, v)| {
            format!(
                "{}{}{}",
                PATHS[(*p as usize) % PATHS.len()],
                OPS[(*o as usize) % OPS.len()],
                VALUES[(*v as usize) % VALUES.len()]
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Fixture frames from every corpus family, dissected from `eth`.
fn fixture(reg: &wrex_core::Registry) -> Vec<wrex_core::dissect::DissectedPacket> {
    let corpora = wrex_test::corpus::Corpus::load_all();
    let mut frames = Vec::new();
    for corpus in corpora {
        for case in &corpus.frames {
            if frames.len() >= 24 {
                break;
            }
            frames.push(dissect(reg, &case.bytes, "eth"));
        }
    }
    frames
}

fuzz_target!(|input: FuzzFilter| {
    let reg = standard();
    let expr = realize(&input.terms);
    // Parse: never a panic; rejection is a pointed FilterError.
    let filter = match Filter::parse(&reg, &expr) {
        Ok(f) => f,
        Err(_) => return, // a malformed expression is data
    };

    let packets = fixture(&reg);
    if packets.is_empty() {
        return;
    }
    let packet = &packets[(input.frame_idx as usize) % packets.len()];

    // Match: never a panic; deterministic verdict per (filter, frame).
    let a = filter.matches(packet);
    let b = filter.matches(packet);
    assert_eq!(a, b, "filter verdict must be deterministic");

    // Reparse + rematch: the whole pipeline is deterministic.
    let again = Filter::parse(&reg, &expr).expect("reparse of an accepted expr");
    assert_eq!(again.matches(packet), a, "reparse verdict drift");
});