//! wrex-frag — the fragment reassembly engine (tranche T18a).
//!
//! Sans-IO and pure: the engine never touches sockets, clocks or codecs.
//! A **fragment stream** is a sequence of [`FragInfo`] values (one per
//! dissected frame, extracted by [`classify`]) plus a caller-supplied
//! `now` in **microseconds since the Unix epoch** (the pcap record
//! timestamp on the CLI path — wall-clock noise, never a behavior
//! input beyond expiry). Pushing a fragment either keeps the key
//! [`Push::Pending`], completes the datagram ([`Push::Complete`] — the
//! full reassembled IP packet, synthesized header included, ready for
//! re-dissection), or evicts the key ([`Push::Overrun`] when the
//! per-key byte budget is breached — never fatal, the standing rule).
//!
//! Design (settled at the T18 planning pass):
//!
//! - **Keyed table** on `(src, dst, proto, ident)` — v4 `id` / v6
//!   `ident`, widened to u32. `Ord` for deterministic flush order.
//! - **offset in bytes** internally (v6 converts its 8-octet units at
//!   the classify boundary); `more` = v4 `mf` / v6 `m`.
//! - **Completion** requires: an offset-0 piece (the unfragmentable
//!   prefix carrier), a terminal piece (`more == false`), and full
//!   coverage of `[0, terminal)` — gaps at the end mean the stream is
//!   just incomplete ([`Reassembler::incomplete`] reports residual
//!   keys at flush; data, not error — the scan precedent).
//! - **Overlaps never abort**: coverage merges intervals (an overlap
//!   records a never-fatal anomaly note on the key), and splice order
//!   is **push order — last write wins** (a deliberately simple,
//!   deterministic policy — never partial application).
//! - **Header synthesis**: the reassembled packet takes its
//!   unfragmentable part (v4: header incl. options; v6: fixed header +
//!   any ext headers *before* the frag header, RFC 8200 §4.5) from
//!   the offset-0 fragment, with the derived length fields rewritten
//!   (`ipv4.total_len` = header + payload; `ipv6.payload_len` = payload;
//!   the byte that pointed at the frag header rewritten to the
//!   terminal upper protocol) and `mf` cleared. Fragment payloads are
//!   never re-derived beyond that — the L4 checksum rides the
//!   original bytes (the T11a preserve contract on the data path).
//! - **Budget + TTL**: per-key pushed-byte budget (default 1 MiB) and
//!   expiry since last push (default 30 s), both caller-tunable.
//!
//! The kind strings (`ipv4`, `ipv6`, `frag`) mirror the codec `KIND`
//! consts (ADR 3); this crate stays dependency-pure (`wrex-core`
//! only) — the engine is not a codec and registers nothing. The
//! integration suite in `crates/wrex/tests/frag.rs` pins the strings
//! against the real registry.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use wrex_core::dissect::{DissectedPacket, FieldSpan};
use wrex_core::value::Value;

/// Mirrors `wrex_proto_ip::KIND` (pinned by the integration suite).
pub const KIND_IPV4: &str = "ipv4";
/// Mirrors `wrex_proto_ip6::KIND` (pinned by the integration suite).
pub const KIND_IPV6: &str = "ipv6";
/// Mirrors `wrex_proto_ip6ext::KIND_FRAG` (pinned by the integration suite).
pub const KIND_FRAG: &str = "frag";

/// Default per-key byte budget (pushed fragment bytes; 1 MiB — a
/// pathological fragment stream evicts the key instead of growing).
pub const DEFAULT_BUDGET: usize = 1 << 20;
/// Default per-key expiry since the last push (30 s — the caller's
/// `now` drives it; `FakeClock`-style determinism holds by
/// construction since `now` is an input).
pub const DEFAULT_TTL: Duration = Duration::from_secs(30);

/// Reassembly key: v4 `(src, dst, proto, id)` / v6 `(src, dst, terminal
/// proto, ident)` widened over one shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FragKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub ident: u32,
}

/// Address family of a fragment (drives the prefix rewrite set).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

/// One rewrite applied to the unfragmentable prefix when synthesizing
/// the reassembled packet. Positions are **relative to the prefix**.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefixRewrite {
    /// v4: `total_len` := prefix.len + payload.len (BE u16 at `pos`).
    TotalLen(usize),
    /// v4: clear `mf` (bit 15 of the BE u16 word at `pos`); `df` and a
    /// zero `frag_off` pass through untouched.
    ClearMf(usize),
    /// v6: `payload_len` := payload.len (BE u16 at `pos`).
    PayloadLen(usize),
    /// v6: the header byte that pointed at the frag header becomes the
    /// terminal upper-layer protocol (`next_header` of the offset-0
    /// fragment's frag header — RFC 8200 §4.5 reassembly rule).
    NextHeader(usize, u8),
}

/// One extracted fragment: everything the engine needs from a single
/// dissected frame. [`classify`] builds it from a [`DissectedPacket`];
/// tests build it by hand.
#[derive(Clone, Debug)]
pub struct FragInfo {
    pub key: FragKey,
    pub family: Family,
    /// Fragment offset in **bytes** (v6 8-octet units converted).
    pub offset: usize,
    /// `more fragments follow` (v4 `mf` / v6 `m`).
    pub more: bool,
    /// Unfragmentable part of the offset-0 carrier (v4: header incl.
    /// options; v6: fixed header + pre-frag ext headers). Copied from
    /// the packet this was classified from; only the offset-0 piece's
    /// copy is used at completion (last write wins on duplicates).
    pub prefix: Vec<u8>,
    /// Rewrites for the synthesized header (captured from the same
    /// frame as `prefix`; applied at completion).
    pub rewrites: Vec<PrefixRewrite>,
    /// This fragment's data: the bytes past the fragment's own headers
    /// (v4: past `upper_start`; v6: past the frag header).
    pub data: Vec<u8>,
}

/// Result of one push.
#[derive(Debug, PartialEq, Eq)]
pub enum Push {
    /// Not complete yet (or no offset-0/terminal piece seen so far).
    Pending,
    /// Complete: the full reassembled IP packet (synthesized header +
    /// spliced payload), ready for re-dissection at `auto`.
    Complete(Vec<u8>),
    /// Per-key budget breached: the key was evicted (data, never fatal).
    Overrun,
}

#[derive(Debug)]
struct Entry {
    /// Pieces in push order — splice order is push order, so overlaps
    /// resolve last-write-wins by construction.
    pieces: Vec<(usize, Vec<u8>)>,
    /// End offset of the latest terminal piece (`more == false`), if any.
    terminal: Option<usize>,
    /// Offset-0 prefix + rewrites (last write wins).
    prefix: Option<(Vec<u8>, Vec<PrefixRewrite>)>,
    notes: Vec<String>,
    last: u64,
    /// Sum of pushed data lengths (the budget proxy).
    bytes: usize,
}

/// The reassembly engine: one instance per stream (capture file, CLI
/// session). Deterministic: same fragment sequence + same `now` values
/// ⇒ same outcomes, byte-identical.
#[derive(Debug)]
pub struct Reassembler {
    entries: BTreeMap<FragKey, Entry>,
    budget: usize,
    ttl_us: u64,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new(DEFAULT_BUDGET, DEFAULT_TTL)
    }
}

impl Reassembler {
    /// New engine with an explicit per-key byte budget and expiry.
    pub fn new(budget: usize, ttl: Duration) -> Self {
        Self {
            entries: BTreeMap::new(),
            budget,
            ttl_us: ttl.as_micros() as u64,
        }
    }

    /// Push one fragment. `now` is µs since the Unix epoch (the caller's
    /// clock; only expiry reads it).
    pub fn push(&mut self, frag: FragInfo, now: u64) -> Push {
        let key = frag.key;
        let entry = self.entries.entry(key).or_insert_with(|| Entry {
            pieces: Vec::new(),
            terminal: None,
            prefix: None,
            notes: Vec::new(),
            last: now,
            bytes: 0,
        });
        entry.last = now;
        if entry.bytes + frag.data.len() > self.budget {
            // Budget breach: evict (never fatal, never a partial splice).
            self.entries.remove(&key);
            return Push::Overrun;
        }
        entry.bytes += frag.data.len();
        if frag.offset == 0 {
            if entry.prefix.is_some() {
                entry
                    .notes
                    .push("duplicate offset-0 fragment (last write wins)".to_string());
            }
            entry.prefix = Some((frag.prefix.clone(), frag.rewrites.clone()));
        }
        let end = frag.offset + frag.data.len();
        if !frag.more {
            if let Some(prev) = entry.terminal
                && prev != end
            {
                entry.notes.push(format!(
                    "conflicting terminal offsets ({prev} vs {end}; last write wins)"
                ));
            }
            entry.terminal = Some(end);
        }
        entry.pieces.push((frag.offset, frag.data));
        // Completion: offset-0 prefix + a terminal end + full coverage.
        let Some((prefix, rewrites)) = entry.prefix.clone() else {
            return Push::Pending;
        };
        let Some(terminal) = entry.terminal else {
            return Push::Pending;
        };
        // Union-of-intervals coverage check (records overlaps as notes).
        let mut spans: Vec<(usize, usize)> = entry
            .pieces
            .iter()
            .filter(|(o, d)| o + d.len() > *o)
            .map(|(o, d)| (*o, o + d.len()))
            .collect();
        spans.sort_unstable();
        let mut covered_end = 0usize;
        let mut contiguous_from_zero = true;
        for (start, end) in &spans {
            if *start > covered_end {
                contiguous_from_zero = false;
                break;
            }
            if *start < covered_end {
                entry
                    .notes
                    .push(format!("overlap at offset {start} (last write wins)"));
            }
            covered_end = covered_end.max(*end);
        }
        if !contiguous_from_zero || covered_end < terminal {
            return Push::Pending;
        }
        // Splice: push order, last write wins, clipped to `terminal`.
        let mut payload = vec![0u8; terminal];
        for (off, data) in &entry.pieces {
            let take = data.len().min(terminal.saturating_sub(*off));
            if take > 0 {
                payload[*off..*off + take].copy_from_slice(&data[..take]);
            }
            if take < data.len() {
                entry.notes.push(format!(
                    "piece overhangs the terminal end at {off} (clipped)"
                ));
            }
        }
        self.entries.remove(&key);
        Push::Complete(synthesize(&prefix, &rewrites, &payload))
    }

    /// Evict every key whose last push is older than the ttl (the
    /// caller's `now`). Returns the evicted keys in `Ord` order.
    pub fn evict_expired(&mut self, now: u64) -> Vec<FragKey> {
        let cutoff = now.saturating_sub(self.ttl_us);
        let expired: Vec<FragKey> = self
            .entries
            .iter()
            .filter(|(_, e)| e.last < cutoff)
            .map(|(k, _)| *k)
            .collect();
        for k in &expired {
            self.entries.remove(k);
        }
        expired
    }

    /// Residual incomplete keys (flush time): one human note per key,
    /// `Ord` order, anomalies included — data, never an error.
    pub fn incomplete(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (key, e) in &self.entries {
            let proto = if key.proto == 0 {
                String::new()
            } else {
                format!(" proto {}", key.proto)
            };
            out.push(format!(
                "incomplete datagram {key:?} ({} byte{} held, {} piece{}){}",
                e.bytes,
                if e.bytes == 1 { "" } else { "s" },
                e.pieces.len(),
                if e.pieces.len() == 1 { "" } else { "s" },
                proto,
            ));
            for n in &e.notes {
                out.push(format!("  ! {n}"));
            }
        }
        out
    }

    /// Number of live keys (walkthrough units).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no key is live.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Synthesize the reassembled IP packet: prefix + rewrites + payload.
fn synthesize(prefix: &[u8], rewrites: &[PrefixRewrite], payload: &[u8]) -> Vec<u8> {
    let mut out = prefix.to_vec();
    for r in rewrites {
        match *r {
            PrefixRewrite::TotalLen(pos) => {
                let v = (prefix.len() + payload.len()) as u16;
                out[pos] = (v >> 8) as u8;
                out[pos + 1] = v as u8;
            }
            PrefixRewrite::ClearMf(pos) => {
                let word = u16::from_be_bytes([out[pos], out[pos + 1]]);
                let v = word & !0x8000;
                out[pos] = (v >> 8) as u8;
                out[pos + 1] = v as u8;
            }
            PrefixRewrite::PayloadLen(pos) => {
                let v = payload.len() as u16;
                out[pos] = (v >> 8) as u8;
                out[pos + 1] = v as u8;
            }
            PrefixRewrite::NextHeader(pos, nh) => out[pos] = nh,
        }
    }
    out.extend_from_slice(payload);
    out
}

/// Classify one dissected packet: `Some(frag)` if it carries an IP
/// fragment, `None` otherwise (whole packets, non-IP frames). Works on
/// any chain an `eth`/`vlan`/raw start produced — the ipv4/ipv6 layer
/// is located by kind, so encapsulation is free.
///
/// v4: a fragment iff `frag_off > 0` or `mf` set. v6: a fragment iff a
/// `frag` layer rides the ipv6 chain (a degenerate offset-0/m-0 frag
/// header reassembles to itself minus the header — kept, the honest
/// reading). Everything else — including `ipv4` without `mf` at
/// offset 0 — is not a fragment.
pub fn classify(packet: &DissectedPacket) -> Option<FragInfo> {
    let frame = &packet.frame[..];
    if let Some(l) = packet.layers.iter().find(|l| l.kind == KIND_IPV4) {
        let src = match l.fields.get("src") {
            Some(Value::Ipv4(a)) => *a,
            _ => return None,
        };
        let dst = match l.fields.get("dst") {
            Some(Value::Ipv4(a)) => *a,
            _ => return None,
        };
        let proto = int_field(l, "proto")? as u8;
        let ident = int_field(l, "id")? as u32;
        let frag_off = int_field(l, "frag_off")? as usize;
        let more = flag(l, "mf");
        if frag_off == 0 && !more {
            return None;
        }
        let upper = packet.facts.upper_start?;
        let prefix = frame.get(l.span.start..upper)?.to_vec();
        let data = frame.get(upper..)?.to_vec();
        return Some(FragInfo {
            key: FragKey {
                src: IpAddr::V4(src),
                dst: IpAddr::V4(dst),
                proto,
                ident,
            },
            family: Family::V4,
            offset: frag_off * 8,
            more,
            prefix,
            // Positions relative to the prefix (= layer start).
            rewrites: vec![PrefixRewrite::TotalLen(2), PrefixRewrite::ClearMf(6)],
            data,
        });
    }
    if let Some(ip6) = packet.layers.iter().find(|l| l.kind == KIND_IPV6) {
        let frag = packet.layers.iter().find(|l| l.kind == KIND_FRAG)?;
        let src = match ip6.fields.get("src") {
            Some(Value::Ipv6(a)) => *a,
            _ => return None,
        };
        let dst = match ip6.fields.get("dst") {
            Some(Value::Ipv6(a)) => *a,
            _ => return None,
        };
        let terminal = int_field(frag, "next_header")? as u8;
        let ident = int_field(frag, "ident")? as u32;
        let offset_units = int_field(frag, "offset")? as usize;
        let m = int_field(frag, "m")? as u8;
        let more = m == 1;
        if offset_units == 0 && !more {
            return None;
        }
        // The header byte that points at the frag header: the last
        // `next_header` field before it (the fixed ipv6 header's own at
        // byte 6 when frag rides directly; a pre-frag ext header's
        // otherwise — located through the layer's field spans, so any
        // supported pre-frag chain works).
        let nh_pos = next_header_pos(packet, ip6, frag)? - ip6.span.start;
        let prefix = frame.get(ip6.span.start..frag.span.start)?.to_vec();
        let data = frame.get(frag.span.end..)?.to_vec();
        return Some(FragInfo {
            key: FragKey {
                src: IpAddr::V6(src),
                dst: IpAddr::V6(dst),
                proto: terminal,
                ident,
            },
            family: Family::V6,
            offset: offset_units * 8,
            more,
            prefix,
            rewrites: vec![
                PrefixRewrite::PayloadLen(4),
                PrefixRewrite::NextHeader(nh_pos, terminal),
            ],
            data,
        });
    }
    None
}

/// Absolute position of the `next_header` byte of the last layer
/// before `frag` in the ipv6 chain (the fixed header's at byte 6 when
/// nothing rides between — read through the span map, total presence).
fn next_header_pos(
    packet: &DissectedPacket,
    ip6: &wrex_core::dissect::LayerView,
    frag: &wrex_core::dissect::LayerView,
) -> Option<usize> {
    let prev = packet.layers.iter().rfind(|l| {
        l.span.start >= ip6.span.start
            && l.span.end <= frag.span.start
            && l.field_spans.contains_key("next_header")
    })?;
    match prev.field_spans.get("next_header")? {
        FieldSpan::Bytes(r) => Some(r.start),
        FieldSpan::Bits { container, .. } => Some(container.start),
        _ => None,
    }
}

fn int_field(l: &wrex_core::dissect::LayerView, name: &str) -> Option<u128> {
    match l.fields.get(name) {
        Some(Value::Int(v)) => Some(*v),
        _ => None,
    }
}

fn flag(l: &wrex_core::dissect::LayerView, name: &str) -> bool {
    matches!(l.fields.get("flags"), Some(Value::List(names)) if {
        names.iter().any(|v| matches!(v, Value::Str(s) if s == name))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4_info(offset: usize, more: bool, data: &[u8]) -> FragInfo {
        FragInfo {
            key: FragKey {
                src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                proto: 17,
                ident: 7,
            },
            family: Family::V4,
            offset,
            more,
            // 20-byte header stand-in: total_len at 2, flags word at 6.
            prefix: {
                let mut h = vec![0x45u8; 20];
                h[2] = 0;
                h[3] = 0;
                h[6] = 0x40 | if more { 0x80 } else { 0x00 }; // df set, mf as given
                h
            },
            rewrites: vec![PrefixRewrite::TotalLen(2), PrefixRewrite::ClearMf(6)],
            data: data.to_vec(),
        }
    }

    fn v6_info(offset: usize, more: bool, data: &[u8]) -> FragInfo {
        FragInfo {
            key: FragKey {
                src: IpAddr::V6(Ipv6Addr::LOCALHOST),
                dst: IpAddr::V6(Ipv6Addr::LOCALHOST),
                proto: 17,
                ident: 9,
            },
            family: Family::V6,
            offset,
            more,
            prefix: {
                let mut h = vec![0x60u8; 40];
                h[6] = 44; // next_header -> frag
                h
            },
            rewrites: vec![
                PrefixRewrite::PayloadLen(4),
                PrefixRewrite::NextHeader(6, 17),
            ],
            data: data.to_vec(),
        }
    }

    #[test]
    fn v4_two_fragment_reassembly() {
        let mut r = Reassembler::default();
        assert_eq!(r.push(v4_info(0, true, &[1, 2, 3, 4]), 0), Push::Pending);
        let Push::Complete(out) = r.push(v4_info(4, false, &[5, 6, 7, 8]), 1) else {
            panic!("expected completion");
        };
        // 20-byte prefix + 8 payload == 28 total_len; mf cleared.
        assert_eq!(out.len(), 28);
        assert_eq!(&out[20..], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(u16::from_be_bytes([out[2], out[3]]), 28);
        assert_eq!(out[6] & 0x40, 0x40, "df kept");
        assert_eq!(out[6] & 0x80, 0x00, "mf bit cleared");
        assert!(r.is_empty(), "completed key evicted");
    }

    #[test]
    fn v4_out_of_order() {
        let mut r = Reassembler::default();
        assert_eq!(r.push(v4_info(4, false, &[5, 6, 7, 8]), 0), Push::Pending);
        assert_eq!(r.push(v4_info(4, false, &[9, 9, 9, 9]), 1), Push::Pending);
        // Only the terminal piece: no offset-0 prefix yet.
        assert_eq!(r.len(), 1);
        let Push::Complete(out) = r.push(v4_info(0, true, &[1, 2, 3, 4]), 2) else {
            panic!("expected completion");
        };
        assert_eq!(&out[20..], &[1, 2, 3, 4, 9, 9, 9, 9]);
    }

    #[test]
    fn v4_gap_at_end_is_incomplete() {
        let mut r = Reassembler::default();
        r.push(v4_info(0, true, &[1, 2, 3, 4]), 0);
        r.push(v4_info(8, false, &[9]), 1); // gap at bytes 4..8
        assert_eq!(r.len(), 1);
        let notes = r.incomplete();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("incomplete datagram"), "{:?}", notes);
        assert!(notes[0].contains("5 bytes held"), "{:?}", notes);
    }

    #[test]
    fn overlap_is_last_write_wins_and_noted() {
        let mut r = Reassembler::default();
        r.push(v4_info(0, true, &[1, 1, 1, 1]), 0);
        r.push(v4_info(0, true, &[2, 2, 2, 2]), 1); // full overlap
        r.push(v4_info(8, false, &[9]), 2); // terminal past a gap: pending
        assert!(
            r.incomplete().iter().any(|n| n.contains("overlap")),
            "{:?}",
            r.incomplete()
        );
        // Splice: push order, last write wins.
        let Push::Complete(out) = r.push(v4_info(4, false, &[3, 3, 3, 3]), 3) else {
            panic!("expected completion");
        };
        // Terminal end became 8 (last write wins); the [9] piece at 8
        // overhangs and is clipped.
        assert_eq!(&out[20..28], &[2, 2, 2, 2, 3, 3, 3, 3]);
    }

    #[test]
    fn duplicate_offset_zero_noted() {
        let mut r = Reassembler::default();
        r.push(v4_info(0, true, &[1]), 0);
        r.push(v4_info(0, true, &[2]), 1);
        assert!(
            r.incomplete()
                .iter()
                .any(|n| n.contains("duplicate offset-0"))
        );
    }

    #[test]
    fn conflicting_terminals_noted() {
        let mut r = Reassembler::default();
        // Terminals first (no offset-0 carrier: pending), then disagree.
        r.push(v4_info(2, false, &[3]), 0);
        r.push(v4_info(4, false, &[5]), 1);
        assert!(
            r.incomplete()
                .iter()
                .any(|n| n.contains("conflicting terminal"))
        );
    }

    #[test]
    fn overhang_clipped_at_terminal() {
        let mut r = Reassembler::default();
        r.push(v4_info(2, false, &[3]), 0); // terminal end at 3
        assert_eq!(r.len(), 1);
        // The offset-0 carrier overhangs the terminal end: 4 bytes for
        // a 3-byte datagram — clipped, noted, completed.
        let out = match r.push(v4_info(0, true, &[1, 2, 3, 4]), 1) {
            Push::Complete(o) => o,
            other => panic!("{other:?}"),
        };
        assert_eq!(&out[20..23], &[1, 2, 3]);
    }

    #[test]
    fn overrun_evicts() {
        let mut r = Reassembler::new(8, DEFAULT_TTL);
        assert_eq!(r.push(v4_info(0, true, &[1, 2, 3, 4]), 0), Push::Pending);
        assert_eq!(r.push(v4_info(4, true, &[5; 8]), 1), Push::Overrun);
        assert!(r.is_empty(), "overrun key evicted");
        // A fresh stream after eviction works.
        assert_eq!(r.push(v4_info(0, true, &[1, 2]), 2), Push::Pending);
    }

    #[test]
    fn ttl_expiry() {
        let mut r = Reassembler::new(DEFAULT_BUDGET, Duration::from_secs(1));
        r.push(v4_info(0, true, &[1]), 0);
        assert_eq!(r.evict_expired(500_000), Vec::<FragKey>::new());
        assert_eq!(r.evict_expired(2_000_000).len(), 1);
        assert!(r.is_empty());
    }

    #[test]
    fn cross_talk_between_keys() {
        let mut r = Reassembler::default();
        let mut other = v4_info(0, true, &[0xaa, 0xbb]);
        other.key.ident = 999;
        r.push(v4_info(0, true, &[1, 2]), 0);
        r.push(other, 1);
        assert_eq!(r.len(), 2);
        let mut terminal = v4_info(2, false, &[3]);
        terminal.key.ident = 999;
        // The other stream completes alone; ours stays incomplete.
        assert!(matches!(r.push(terminal, 2), Push::Complete(_)));
        assert_eq!(r.len(), 1);
        let ours = FragKey {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            proto: 17,
            ident: 7,
        };
        assert!(r.incomplete()[0].contains(&format!("{ours:?}")));
    }

    #[test]
    fn v6_reassembly_rewrites_header() {
        let mut r = Reassembler::default();
        r.push(v6_info(0, true, &[1, 2, 3, 4, 5, 6, 7, 8]), 0);
        let Push::Complete(out) = r.push(v6_info(8, false, &[9, 10]), 1) else {
            panic!("expected completion");
        };
        assert_eq!(out.len(), 40 + 10);
        // payload_len := 10, next_header -> terminal proto 17.
        assert_eq!(u16::from_be_bytes([out[4], out[5]]), 10);
        assert_eq!(out[6], 17);
        assert_eq!(&out[40..], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn never_panic_proptest() {
        proptest!(|(offset in 0usize..64, chunk in proptest::collection::vec(any::<u8>(), 0..32), more in any::<bool>(), ident in any::<u32>())| {
            let mut r = Reassembler::default();
            let mut frag = v4_info(0, true, &chunk);
            frag.key.ident = ident;
            frag.data = chunk.clone();
            let _ = r.push(frag, 0);
            let mut frag2 = v4_info(offset, more, &chunk);
            frag2.key.ident = ident;
            if let Push::Complete(out) = r.push(frag2, 1) {
                // Reassembled packets always carry the prefix.
                assert!(out.len() >= 20);
            }
            let _ = r.incomplete();
            let _ = r.evict_expired(u64::MAX);
        });
    }
}
