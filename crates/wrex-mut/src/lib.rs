#![forbid(unsafe_code)]
//! wrex-mut: the tranche-6a mutation engine — seeded, dissect-aware
//! frame mutation for over-the-wire fuzzing.
//!
//! Sans-IO and CLI-free: the engine consumes seed frames (raw bytes)
//! and produces mutants; `wrex mut` (the CLI crate) feeds it pcaps,
//! hex frames or stdin and prints/writes the output. Determinism is
//! pinned by [`wrex_io::Rng`] (in-house SplitMix64, no `rand`): the
//! same `--seed U64` yields the byte-identical mutant sequence.
//!
//! Strategies ([`Strategy`]):
//!
//! - **field** — dissect each seed, mutate one *typed* field value,
//!   re-encode with autofill: checksums (and, unless mutated, length
//!   fields) re-derive, so mutants stay dissectable where the mutation
//!   itself permits it;
//! - **len** — the field strategy restricted to length-bearing fields
//!   (`total_len`, `length`, `len`): the perturbed length is set
//!   *explicitly*, so autofill keeps the mutation instead of
//!   re-deriving it;
//! - **flip** — a raw bit flip, biased toward header bytes (the first
//!   40) where protocol state lives;
//! - **splice** — cross-over: `A[..k] + B[k..]` of two seed frames
//!   (needs >= 2 seeds; falls back to a raw flip otherwise);
//! - **raw** — byte-level surgery: flip / overwrite / insert / delete
//!   one byte anywhere;
//! - **all** — a seeded weighted mix of the above.
//!
//! [`Mutator::next_mutant`] never fails: a strategy that cannot apply
//! (no fields to mutate, a single seed for splice, an encode failure)
//! falls through to the raw byte level, so a mutant stream is always
//! producible and reproducible.

use wrex_core::spec::{LayerSpec, PacketSpec};
use wrex_core::value::Value;
use wrex_core::{
    Registry,
    dissect::dissect,
    encode::{EncodeOpts, encode},
};
use wrex_io::Rng;

/// Mutation strategy selection (`wrex mut --strategy`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Strategy {
    /// Mutate one typed field value; re-encode (checksums re-derive).
    Field,
    /// Perturb a length field explicitly (autofill keeps it).
    Len,
    /// Raw bit flip, header-biased.
    Flip,
    /// Cross-over of two seed frames.
    Splice,
    /// Byte-level surgery anywhere.
    Raw,
    /// Seeded weighted mix of the rest.
    All,
}

impl Strategy {
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw {
            None => Ok(Self::All),
            Some("field") => Ok(Self::Field),
            Some("len") => Ok(Self::Len),
            Some("flip") => Ok(Self::Flip),
            Some("splice") => Ok(Self::Splice),
            Some("raw") => Ok(Self::Raw),
            Some("all") => Ok(Self::All),
            Some(other) => Err(format!(
                "unknown mutation strategy `{other}` (field|len|flip|splice|raw|all)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Field => "field",
            Self::Len => "len",
            Self::Flip => "flip",
            Self::Splice => "splice",
            Self::Raw => "raw",
            Self::All => "all",
        }
    }
}

/// Fields autofill re-derives from the packet: copying them from a
/// dissection as explicit values would pin stale checksums and lengths.
const DERIVED_FIELDS: &[&str] = &["checksum", "total_len", "length", "len"];

/// Length-bearing fields the **len** strategy perturbs (explicitly, so
/// autofill keeps the mutation).
const LENGTH_FIELDS: &[&str] = &["total_len", "length", "len"];

/// Header-biased flip region: protocol state lives in the first bytes.
const HEADER_BIAS_BYTES: usize = 40;

/// The seeded mutation engine. Construct with [`Mutator::new`], pull
/// mutants with [`Mutator::next_mutant`].
pub struct Mutator<'a> {
    registry: &'a Registry,
    seeds: Vec<Vec<u8>>,
    strategy: Strategy,
    rng: Rng,
}

impl<'a> Mutator<'a> {
    /// New mutator. Fails ([`String`] → usage error) on an empty seed
    /// set — there is nothing to mutate.
    pub fn new(
        registry: &'a Registry,
        seeds: Vec<Vec<u8>>,
        strategy: Strategy,
        seed: u64,
    ) -> Result<Self, String> {
        if seeds.is_empty() {
            return Err(
                "mut: no seed frames given (positional hex, -r FILE.pcap or stdin)".to_string(),
            );
        }
        Ok(Self {
            registry,
            seeds,
            strategy,
            rng: Rng::new(seed),
        })
    }

    /// The configured strategy.
    pub fn strategy(&self) -> Strategy {
        self.strategy
    }

    /// Produce the next mutant. Deterministic per construction seed;
    /// never fails (inapplicable strategies fall through to raw).
    pub fn next_mutant(&mut self) -> Vec<u8> {
        let mut frame = self.seeds[(self.rng.next_u64() as usize) % self.seeds.len()].clone();
        let pick = self.pick_concrete();
        self.apply(pick, &mut frame);
        frame
    }

    /// Resolve the configured strategy into a concrete per-iteration
    /// pick: `All` mixes (seeded; splice only with >= 2 seeds), every
    /// other strategy is itself.
    fn pick_concrete(&mut self) -> Strategy {
        let mix: Vec<Strategy> = if self.strategy == Strategy::All {
            let mut v = vec![
                Strategy::Field,
                Strategy::Len,
                Strategy::Flip,
                Strategy::Raw,
            ];
            if self.seeds.len() >= 2 {
                v.push(Strategy::Splice);
            }
            v
        } else {
            vec![self.strategy]
        };
        mix[(self.rng.next_u64() as usize) % mix.len()]
    }

    /// Apply one concrete strategy to `frame` in place.
    fn apply(&mut self, strategy: Strategy, frame: &mut Vec<u8>) {
        match strategy {
            Strategy::Field | Strategy::Len => {
                if let Some(mutant) = self.mutate_spec(frame, strategy == Strategy::Len) {
                    *frame = mutant;
                } else {
                    self.flip(frame);
                }
            }
            Strategy::Flip => self.flip(frame),
            Strategy::Splice => {
                if self.seeds.len() >= 2 {
                    let a = (self.rng.next_u64() as usize) % self.seeds.len();
                    let mut b = (self.rng.next_u64() as usize) % self.seeds.len();
                    if b == a {
                        b = (b + 1) % self.seeds.len();
                    }
                    let a = &self.seeds[a];
                    let b = &self.seeds[b];
                    let k = 1 + (self.rng.next_u64() as usize) % a.len().min(b.len()).max(1);
                    let spliced: Vec<u8> = a[..k.min(a.len())].to_vec();
                    let tail: Vec<u8> = if k < b.len() {
                        b[k..].to_vec()
                    } else {
                        Vec::new()
                    };
                    *frame = [spliced, tail].concat();
                } else {
                    self.flip(frame);
                }
            }
            Strategy::Raw => self.raw(frame),
            // `pick_concrete` resolved `All` before `apply`; reaching
            // here is a bug, not a user outcome.
            Strategy::All => unreachable!("All resolves in pick_concrete"),
        }
    }

    /// The field/len strategies: dissect → build a spec → mutate one
    /// typed value → re-encode (autofill re-derives checksums and
    /// lengths unless the mutation is the length itself). `None` when
    /// there is no field to mutate or the encode fails.
    fn mutate_spec(&mut self, frame: &[u8], len_only: bool) -> Option<Vec<u8>> {
        let spec = spec_from_frame(self.registry, frame)?;
        // Candidate (layer, field) pairs. The len strategy targets
        // length-bearing fields, which spec_from_frame drops (autofill
        // re-derives them) — enumerate them from a fresh dissection.
        let mut candidates: Vec<(usize, String)> = Vec::new();
        if len_only {
            let pkt = dissect(self.registry, frame, "auto");
            for (li, l) in pkt.layers.iter().enumerate() {
                for name in l.fields.keys() {
                    if LENGTH_FIELDS.contains(&name.as_str()) {
                        candidates.push((li, name.clone()));
                    }
                }
            }
        } else {
            for (li, layer) in spec.layers.iter().enumerate() {
                for name in layer.fields.keys() {
                    if !LENGTH_FIELDS.contains(&name.as_str()) {
                        candidates.push((li, name.clone()));
                    }
                }
            }
        }
        if candidates.is_empty() {
            return None;
        }
        let (li, name) = candidates[(self.rng.next_u64() as usize) % candidates.len()].clone();
        // The old value: from the spec (field strategy — lengths were
        // dropped there), or from the fresh dissection (len strategy —
        // the spec does not carry the field).
        let old = if len_only {
            let pkt = dissect(self.registry, frame, "auto");
            pkt.layers.get(li)?.fields.get(&name)?.clone()
        } else {
            spec.layers[li].fields.get(&name)?.clone()
        };
        let mutated = if len_only {
            // Perturb the length explicitly: autofill keeps it.
            let delta = 1 + (self.rng.next_u64() % 16) as u128;
            match old {
                Value::Int(v) => Value::Int((v.wrapping_add(delta)) & 0xffff),
                _ => Value::Int(delta & 0xffff),
            }
        } else {
            self.mutate_value(&old)
        };
        let mut spec = spec;
        spec.layers[li].fields.insert(name, mutated);
        encode(
            self.registry,
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .ok()
        .map(|e| e.bytes.to_vec())
    }

    /// Mutate one typed value per its kind (stays type-valid; range
    /// validity is the encode/checks layer's business — explicit values
    /// are kept unvalidated by the craft contract).
    fn mutate_value(&mut self, v: &Value) -> Value {
        match v {
            Value::Int(x) => {
                let mask = 1u128 << (self.rng.next_u64() % 16);
                Value::Int(x ^ mask)
            }
            Value::Ipv4(_) => {
                let bits = self.rng.next_u64() as u32;
                Value::Ipv4(std::net::Ipv4Addr::from(bits))
            }
            Value::Ipv6(_) => {
                let mut o = [0u8; 16];
                for b in o.iter_mut() {
                    *b = self.rng.next_u64() as u8;
                }
                Value::Ipv6(std::net::Ipv6Addr::from(o))
            }
            Value::Mac(_) => {
                let mut mac = [0u8; 6];
                for b in &mut mac {
                    *b = self.rng.next_u64() as u8;
                }
                Value::Mac(mac)
            }
            Value::Bytes(b) => {
                if b.is_empty() {
                    Value::Bytes(bytes::Bytes::from(vec![self.rng.next_u64() as u8]))
                } else {
                    let mut out = b.to_vec();
                    let i = (self.rng.next_u64() as usize) % out.len();
                    out[i] ^= 1 << (self.rng.next_u64() % 8);
                    Value::Bytes(bytes::Bytes::from(out))
                }
            }
            Value::Str(s) => {
                let mut out = s.clone();
                let c = (b'a' + (self.rng.next_u64() % 26) as u8) as char;
                if out.is_empty() {
                    out.push(c);
                } else {
                    let i = (self.rng.next_u64() as usize) % out.len();
                    out.replace_range(i..i + 1, &c.to_string());
                }
                Value::Str(out)
            }
            Value::List(items) => {
                // Flagset: toggle one present/absent member.
                let mut out = items.clone();
                if out.is_empty() {
                    out.push(Value::Str("syn".into()));
                } else {
                    let i = (self.rng.next_u64() as usize) % out.len();
                    out.remove(i);
                }
                Value::List(out)
            }
            Value::Bool(b) => Value::Bool(!b),
        }
    }

    /// Bit flip, header-biased: 70% within the first [`HEADER_BIAS_BYTES`]
    /// bytes (protocol state), 30% anywhere.
    fn flip(&mut self, frame: &mut [u8]) {
        if frame.is_empty() {
            return;
        }
        let idx = if frame.len() <= HEADER_BIAS_BYTES || self.rng.next_f64() < 0.7 {
            (self.rng.next_u64() as usize) % frame.len().min(HEADER_BIAS_BYTES)
        } else {
            (self.rng.next_u64() as usize) % frame.len()
        };
        frame[idx] ^= 1 << (self.rng.next_u64() % 8);
    }

    /// Byte-level surgery: flip / overwrite / insert / delete. A
    /// mutant is never empty: deletion needs >= 2 bytes (a 1-byte
    /// frame overwrites instead).
    fn raw(&mut self, frame: &mut Vec<u8>) {
        if frame.is_empty() {
            frame.push(self.rng.next_u64() as u8);
            return;
        }
        let idx = (self.rng.next_u64() as usize) % frame.len();
        let can_delete = frame.len() >= 2;
        match self.rng.next_u64() % 4 {
            0 => frame[idx] ^= 1 << (self.rng.next_u64() % 8),
            1 => frame[idx] = self.rng.next_u64() as u8,
            2 => frame.insert(idx, self.rng.next_u64() as u8),
            _ if can_delete => {
                frame.remove(idx);
            }
            _ => frame[idx] = self.rng.next_u64() as u8,
        }
    }
}

/// Dissect a frame back into a craftable spec. Derived fields
/// (checksums, lengths) are dropped so autofill re-derives them;
/// `None` when nothing dissects.
pub fn spec_from_frame(registry: &Registry, frame: &[u8]) -> Option<PacketSpec> {
    let pkt = dissect(registry, frame, "auto");
    let mut layers = Vec::with_capacity(pkt.layers.len());
    for l in &pkt.layers {
        let mut fields = std::collections::BTreeMap::new();
        for (name, v) in &l.fields {
            if DERIVED_FIELDS.contains(&name.as_str()) {
                continue;
            }
            fields.insert(name.clone(), v.clone());
        }
        layers.push(LayerSpec::with_fields(l.kind, fields));
    }
    if layers.is_empty() {
        return None;
    }
    let payload = if pkt.payload.is_empty() {
        None
    } else {
        Some(Value::Bytes(pkt.payload.clone()))
    };
    Some(PacketSpec::new(layers, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wrex_core::encode::EncodeOpts;

    fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&wrex_proto_eth::CODEC);
        r.register(&wrex_proto_ip::CODEC);
        r.register(&wrex_proto_udp::CODEC);
        r.register(&wrex_proto_tcp::CODEC);
        r.register(&wrex_proto_icmp::CODEC);
        r
    }

    /// A golden eth+ipv4+udp frame (the README recipe).
    fn golden_udp() -> Vec<u8> {
        let reg = registry();
        let mk = |pairs: &[(&str, Value)]| -> std::collections::BTreeMap<String, Value> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect()
        };
        let spec = PacketSpec::new(
            vec![
                LayerSpec::with_fields("eth", mk(&[("dst", Value::Mac([0xff; 6]))])),
                LayerSpec::with_fields(
                    "ipv4",
                    mk(&[
                        ("src", Value::Ipv4("127.0.0.1".parse().unwrap())),
                        ("dst", Value::Ipv4("127.0.0.1".parse().unwrap())),
                    ]),
                ),
                LayerSpec::with_fields(
                    "udp",
                    mk(&[("sport", Value::Int(4444)), ("dport", Value::Int(5555))]),
                ),
            ],
            Some(Value::Bytes(bytes::Bytes::from_static(&[
                0xde, 0xad, 0xbe, 0xef,
            ]))),
        );
        encode(
            &reg,
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap()
        .bytes
        .to_vec()
    }

    #[test]
    fn empty_seeds_is_an_error() {
        assert!(Mutator::new(&registry(), vec![], Strategy::All, 1).is_err());
    }

    #[test]
    fn deterministic_per_seed() {
        let reg = registry();
        let seeds = vec![golden_udp()];
        let mut a = Mutator::new(&reg, seeds.clone(), Strategy::All, 42).unwrap();
        let mut b = Mutator::new(&reg, seeds.clone(), Strategy::All, 42).unwrap();
        for _ in 0..64 {
            assert_eq!(a.next_mutant(), b.next_mutant());
        }
        let mut c = Mutator::new(&reg, seeds, Strategy::All, 43).unwrap();
        // Different seeds differ (at least one of the first few mutants).
        assert_ne!(
            (0..8).map(|_| a.next_mutant()).collect::<Vec<_>>(),
            (0..8).map(|_| c.next_mutant()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn every_strategy_produces_mutants() {
        let reg = registry();
        for s in [
            Strategy::Field,
            Strategy::Len,
            Strategy::Flip,
            Strategy::Splice,
            Strategy::Raw,
            Strategy::All,
        ] {
            let seeds = vec![golden_udp(), golden_tcp()];
            let mut m = Mutator::new(&reg, seeds, s, 7).unwrap();
            let mut distinct = 0;
            for _ in 0..64 {
                let mutant = m.next_mutant();
                assert!(!mutant.is_empty(), "{s:?} produced an empty mutant");
                if mutant != golden_udp() {
                    distinct += 1;
                }
            }
            assert!(distinct > 0, "{s:?} never mutated the seed");
        }
    }

    #[test]
    fn field_strategy_stays_dissectable() {
        let reg = registry();
        let mut m = Mutator::new(&reg, vec![golden_udp()], Strategy::Field, 99).unwrap();
        for _ in 0..64 {
            let mutant = m.next_mutant();
            // Whatever the mutation, dissection must not panic (it
            // may legitimately report anomalies).
            let pkt = dissect(&reg, &mutant, "auto");
            if pkt.anomalies.is_empty() {
                // A clean mutant must still identify as eth.
                assert_eq!(pkt.layers[0].kind, "eth");
            }
        }
    }

    #[test]
    fn len_strategy_moves_a_length() {
        let reg = registry();
        let base = golden_udp();
        let mut moved = false;
        for seed in 0..32u64 {
            let mut m = Mutator::new(&reg, vec![base.clone()], Strategy::Len, seed).unwrap();
            for _ in 0..16 {
                let mutant = m.next_mutant();
                let pkt = dissect(&reg, &mutant, "auto");
                let ip = pkt.layers.iter().find(|l| l.kind == "ipv4").unwrap();
                let udp = pkt.layers.iter().find(|l| l.kind == "udp").unwrap();
                let ip_len = match ip.fields.get("total_len") {
                    Some(Value::Int(v)) => *v as u64,
                    _ => continue,
                };
                let udp_len = match udp.fields.get("length") {
                    Some(Value::Int(v)) => *v as u64,
                    _ => continue,
                };
                if ip_len != base.len() as u64 || udp_len != (base.len() - 14 - 20) as u64 {
                    moved = true;
                }
            }
        }
        assert!(moved, "len strategy never perturbed a length field");
    }

    /// A second, distinct seed frame (eth+ipv4+tcp) for splice tests.
    fn golden_tcp() -> Vec<u8> {
        let reg = registry();
        let mk = |pairs: &[(&str, Value)]| -> std::collections::BTreeMap<String, Value> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect()
        };
        let spec = PacketSpec::new(
            vec![
                LayerSpec::with_fields("eth", mk(&[("dst", Value::Mac([0xff; 6]))])),
                LayerSpec::with_fields(
                    "ipv4",
                    mk(&[
                        ("src", Value::Ipv4("127.0.0.1".parse().unwrap())),
                        ("dst", Value::Ipv4("127.0.0.1".parse().unwrap())),
                    ]),
                ),
                LayerSpec::with_fields(
                    "tcp",
                    mk(&[
                        ("sport", Value::Int(40000)),
                        ("dport", Value::Int(80)),
                        ("seq", Value::Int(0x1122_3344)),
                        ("flags", Value::Int(0x02)),
                    ]),
                ),
            ],
            None,
        );
        encode(
            &reg,
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap()
        .bytes
        .to_vec()
    }

    #[test]
    fn single_seed_splice_falls_back() {
        let reg = registry();
        let mut m = Mutator::new(&reg, vec![golden_udp()], Strategy::Splice, 5).unwrap();
        // Single seed: splice degrades to a flip, never panics.
        for _ in 0..32 {
            let mutant = m.next_mutant();
            assert!(!mutant.is_empty());
        }
    }

    #[test]
    fn mutants_are_never_empty() {
        // Fuzzer-found invariant: raw delete on a 1-byte frame must
        // not produce an empty mutant.
        let reg = registry();
        for strategy in [
            Strategy::Field,
            Strategy::Len,
            Strategy::Flip,
            Strategy::Splice,
            Strategy::Raw,
            Strategy::All,
        ] {
            let mut m = Mutator::new(&reg, vec![vec![0xab], vec![0xcd]], strategy, 3).unwrap();
            for _ in 0..256 {
                assert!(!m.next_mutant().is_empty(), "{strategy:?} emptied a seed");
            }
        }
    }
}
