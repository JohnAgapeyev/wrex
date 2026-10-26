//! Single-pass + backpatch encode engine.
//!
//! Layers are written outer→inner into one `BytesMut`; the engine appends
//! the terminal payload after the last codec's write, then resolves the
//! deferred [`Patch`] records (lengths, checksums) against the final buffer.
//! L4 checksums thereby cover the payload without reordering writes.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::{Bytes, BytesMut};

use crate::checksum::{ChecksumAccumulator, PseudoHeader};
use crate::codec::Registry;
use crate::dissect::{Facts, NetFacts};
use crate::error::EncodeError;
use crate::schema::{FieldKind, FieldSchema};
use crate::spec::{LayerSpec, PacketSpec};
use crate::value::Value;

/// A deferred field write, recorded by a codec during
/// [`crate::codec::Codec::write`] and resolved by the engine once the final
/// layout (payload included) is known.
///
/// `at`/`base`/`end` are absolute buffer offsets. `end: None` means "to the
/// final buffer end" (payload included).
#[derive(Clone, Copy, Debug)]
pub enum Patch {
    /// `u16 at = (end - base)` — total_len / udp.length style fields.
    Length {
        at: usize,
        base: usize,
        explicit: bool,
        path: &'static str,
    },
    /// `--strict` check: low nibble at `at` must be ≥ `min` (ipv4 ihl ≥ 5).
    MinNibble {
        at: usize,
        min: u8,
        path: &'static str,
    },
    /// One's-complement checksum over `buf[start..end]`, optionally prefixed
    /// by the IP pseudo-header ([`PseudoHeader`]; v4 or v6).
    Checksum {
        at: usize,
        start: usize,
        end: Option<usize>,
        pseudo: Option<PseudoHeader>,
        explicit: bool,
        path: &'static str,
    },
    /// `--strict` check: byte at `at` must be ≥ `min` (ihl ≥ 5, data_offset ≥ 5).
    MinByte {
        at: usize,
        min: u8,
        path: &'static str,
    },
}

/// A `--strict` validation failure, rendered `wrex: <path>: <message>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub path: String,
    pub message: String,
}

/// Encode-side context passed to [`crate::codec::Codec::write`].
pub struct EncodeCtx<'a> {
    /// Output buffer; the codec appends its header here.
    pub buf: &'a mut BytesMut,
    /// Facts recorded by earlier layers / seeded by the caller (iface MACs).
    pub facts: Facts,
    /// `--no-autofill` disables every autofill/derivation.
    pub autofill: bool,
    /// Terminal payload bytes (already fully known from `PacketSpec`).
    pub payload: Option<&'a [u8]>,
    /// Next layer kind in the stack, `None` when this layer is terminal.
    pub next: Option<&'static str>,
    deferred: Vec<Patch>,
}

impl<'a> EncodeCtx<'a> {
    /// Record a deferred field for engine resolution.
    pub fn defer(&mut self, patch: Patch) {
        self.deferred.push(patch);
    }
}

/// Engine options: autofill, strict validation, caller-seeded facts.
#[derive(Clone, Copy, Debug, Default)]
pub struct EncodeOpts {
    pub autofill: bool,
    pub strict: bool,
    pub facts: Facts,
}

/// Encode result: final bytes plus `--strict` violations (empty otherwise).
#[derive(Debug)]
pub struct Encoded {
    pub bytes: Bytes,
    pub violations: Vec<Violation>,
}

/// Encode a [`PacketSpec`] through the registered codecs.
///
/// Engine phases: (1) resolve codecs + required-field check, (2) outer→inner
/// header writes with patch deferral, (3) payload append, (4) patch
/// resolution (autofill writes / strict checks).
pub fn encode(
    registry: &Registry,
    spec: &PacketSpec,
    opts: &EncodeOpts,
) -> Result<Encoded, EncodeError> {
    let mut codecs = Vec::with_capacity(spec.layers.len());
    for layer in &spec.layers {
        let codec = registry
            .get(layer.kind)
            .ok_or_else(|| EncodeError::IncompatibleStack {
                detail: format!("unknown layer `{}`", layer.kind),
            })?;
        codecs.push(codec);
    }
    if codecs.is_empty() {
        return Err(EncodeError::IncompatibleStack {
            detail: "no layers specified".into(),
        });
    }

    // Required fields must be present (tranche 1: only arp.tpa).
    for (layer, codec) in spec.layers.iter().zip(&codecs) {
        for f in codec.schema().fields {
            if f.required && !layer.fields.contains_key(f.name) {
                return Err(EncodeError::Unfillable {
                    field: format!("{}.{}", layer.kind, f.name),
                });
            }
        }
    }

    let payload: Option<Bytes> = match &spec.payload {
        None => None,
        Some(Value::Bytes(b)) => Some(b.clone()),
        Some(other) => {
            return Err(EncodeError::IncompatibleStack {
                detail: format!("payload must be bytes, got {}", other.kind()),
            });
        }
    };

    let mut buf = BytesMut::new();
    let mut patches: Vec<Patch> = Vec::new();
    let mut facts = opts.facts;
    for (i, (layer, codec)) in spec.layers.iter().zip(&codecs).enumerate() {
        let next = spec
            .layers
            .get(i + 1)
            .and_then(|l| registry.get(l.kind))
            .map(|c| c.schema().kind);
        let mut ctx = EncodeCtx {
            buf: &mut buf,
            facts,
            autofill: opts.autofill,
            payload: payload.as_deref(),
            next,
            deferred: Vec::new(),
        };
        codec.write(layer, &mut ctx)?;
        facts = ctx.facts;
        patches.extend(ctx.deferred);
    }
    if let Some(p) = &payload {
        buf.extend_from_slice(p);
    }

    let violations = resolve_patches(&mut buf, &patches, opts.strict);
    Ok(Encoded {
        bytes: buf.freeze(),
        violations,
    })
}

fn resolve_patches(buf: &mut BytesMut, patches: &[Patch], strict: bool) -> Vec<Violation> {
    let mut violations = Vec::new();
    let end = buf.len();
    for p in patches {
        match *p {
            Patch::Length {
                at,
                base,
                explicit,
                path,
            } => {
                let actual = end.saturating_sub(base);
                if actual > u16::MAX as usize {
                    violations.push(Violation {
                        path: path.to_string(),
                        message: format!("length {actual} does not fit in u16"),
                    });
                    continue;
                }
                let computed = actual as u16;
                if !explicit {
                    buf[at..at + 2].copy_from_slice(&computed.to_be_bytes());
                } else if strict {
                    let found = u16::from_be_bytes([buf[at], buf[at + 1]]);
                    if found != computed {
                        violations.push(Violation {
                            path: path.to_string(),
                            message: format!(
                                "length mismatch (actual {computed} (0x{computed:04x}), found {found} (0x{found:04x}))"
                            ),
                        });
                    }
                }
            }
            Patch::MinNibble { at, min, path } => {
                if strict && buf[at] & 0x0f < min {
                    violations.push(Violation {
                        path: path.to_string(),
                        message: format!("below minimum {min}"),
                    });
                }
            }
            Patch::Checksum {
                at,
                start,
                end: region_end,
                pseudo,
                explicit,
                path,
            } => {
                let region_end = region_end.unwrap_or(end).min(end);
                let mut acc = ChecksumAccumulator::new();
                if let Some(pseudo) = pseudo {
                    pseudo.accumulate_into(&mut acc, region_end - start);
                }
                // The checksum field itself participates as zero (RFC 1071
                // convention), whether the codec left a placeholder or an
                // explicit user value.
                acc.add_bytes(&buf[start..at]);
                acc.add_u16(0);
                acc.add_bytes(&buf[at + 2..region_end]);
                let computed = acc.value();
                if !explicit {
                    buf[at..at + 2].copy_from_slice(&computed.to_be_bytes());
                } else if strict {
                    let found = u16::from_be_bytes([buf[at], buf[at + 1]]);
                    if found != computed {
                        violations.push(Violation {
                            path: path.to_string(),
                            message: format!(
                                "mismatch (computed 0x{computed:04x}, found 0x{found:04x})"
                            ),
                        });
                    }
                }
            }
            Patch::MinByte { at, min, path } => {
                if strict && buf[at] < min {
                    violations.push(Violation {
                        path: path.to_string(),
                        message: format!("below minimum {min}"),
                    });
                }
            }
        }
    }
    violations
}

// --- spec-access helpers shared by protocol codecs --------------------------

/// Serialize one field value to its **wire bytes** (tranche 11b-γ): the
/// `SetField` payload producer for the span-patch engine. `bits` is the
/// field's wire **bit** width — a `Bytes` span's length × 8, or a bit
/// window's `width` — and the output is `ceil(bits/8)` big-endian bytes
/// (the engine's `Bits` masked-write expects exactly that).
///
/// FlagSet aggregates ([`FieldKind::FlagSet`]) follow the schema's
/// MSB-first `bit_names` unit convention (`bit_names[0]` ↔ the highest
/// bit of the unit), LSB-aligned inside the window (the reserved bits
/// above the unit — e.g. ipv4's — stay zero).
///
/// `None` = the value does not serialize at this width/kind (a type
/// mismatch): the caller falls back (the mutation engine drops to the
/// raw byte level).
pub fn serialize_field_value(
    kind: FieldKind,
    bit_names: &[&'static str],
    bits: usize,
    v: &Value,
) -> Option<Vec<u8>> {
    // Bytes kinds serialize at any span width (the tranche-17a ext
    // regions run 20+ bytes); the 16-byte ceiling below is a *numeric*
    // constraint (u128 masking), not a Bytes one.
    if matches!(kind, FieldKind::Bytes | FieldKind::ByteList) {
        return match v {
            Value::Bytes(b) => Some(b.to_vec()),
            _ => None,
        };
    }
    if bits == 0 || bits > 16 * 8 {
        return None;
    }
    /// `x` as `ceil(bits/8)` big-endian bytes, masked into the window.
    fn num(x: u128, bits: usize) -> Option<Vec<u8>> {
        let mask = if bits >= 128 {
            u128::MAX
        } else {
            (1u128 << bits) - 1
        };
        let bytes = (x & mask).to_be_bytes(); // 16 bytes, BE
        let want = bits.div_ceil(8);
        Some(bytes[16 - want..].to_vec())
    }
    match (kind, v) {
        (
            FieldKind::U8
            | FieldKind::U16
            | FieldKind::U32
            | FieldKind::U64
            | FieldKind::U128
            | FieldKind::FlagSet,
            Value::Int(x),
        ) => num(*x, bits),
        (FieldKind::FlagSet, Value::List(items)) => {
            // The unit convention: bit_names[i] ↔ unit bit (n-1-i),
            // MSB-first — the same packing `flagset_or_default` uses.
            let n = bit_names.len();
            let mut x: u128 = 0;
            for item in items {
                let Value::Str(name) = item else {
                    return None;
                };
                let index = bit_names.iter().position(|b| *b == &**name)?;
                if index >= n || n > 8 * 16 {
                    return None;
                }
                x |= 1u128 << (n - 1 - index);
            }
            num(x, bits)
        }
        (FieldKind::Ipv4, Value::Ipv4(a)) => Some(a.octets().to_vec()),
        (FieldKind::Ipv6, Value::Ipv6(a)) => Some(a.octets().to_vec()),
        (FieldKind::Mac, Value::Mac(m)) => Some(m.to_vec()),
        (FieldKind::Bytes | FieldKind::ByteList, Value::Bytes(b)) => Some(b.to_vec()),
        (FieldKind::Str, Value::Str(s)) => Some(s.as_bytes().to_vec()),
        // Any other kind/value pairing (Bool is not a wire kind; Str
        // values on numeric kinds, …) does not serialize — None.
        _ => None,
    }
}

/// Explicit field value if set.
pub fn field_value<'v>(spec: &'v LayerSpec, name: &str) -> Option<&'v Value> {
    spec.fields.get(name)
}

/// Explicit int if set (any width).
pub fn field_int(spec: &LayerSpec, name: &str) -> Option<u128> {
    match spec.fields.get(name) {
        Some(Value::Int(v)) => Some(*v),
        _ => None,
    }
}

/// Numeric field accessor: explicit value wins (invalid values included);
/// else schema default when autofilling; else 0.
pub fn int_or_default(spec: &LayerSpec, field: &FieldSchema, autofill: bool) -> u128 {
    match spec.fields.get(field.name) {
        Some(Value::Int(v)) => *v,
        _ => match &field.default {
            Value::Int(d) if autofill => *d,
            _ => 0,
        },
    }
}

/// Aggregate flag-set byte: explicit aggregate wins; per-bit subpaths
/// (`flags.syn=true`) modify single bits of whatever aggregate is in effect.
pub fn flagset_or_default(spec: &LayerSpec, field: &FieldSchema, autofill: bool) -> u128 {
    let mut agg = int_or_default(spec, field, autofill);
    let prefix = format!("{}.", field.name);
    for (key, val) in &spec.fields {
        let Some(bit_name) = key.strip_prefix(&prefix) else {
            continue;
        };
        let Some(bit) = field.bit_pos(bit_name) else {
            continue;
        };
        let set = matches!(val, Value::Bool(true));
        if set {
            agg |= 1 << bit;
        } else {
            agg &= !(1 << bit);
        }
    }
    agg
}

/// IPv4 field accessor (explicit or zero).
pub fn ipv4_or_zero(spec: &LayerSpec, name: &str) -> Ipv4Addr {
    match spec.fields.get(name) {
        Some(Value::Ipv4(a)) => *a,
        _ => Ipv4Addr::UNSPECIFIED,
    }
}

/// IPv4 field accessor: explicit value wins; else schema default when
/// autofilling; else unspecified.
pub fn ipv4_or_default(spec: &LayerSpec, field: &FieldSchema, autofill: bool) -> Ipv4Addr {
    match spec.fields.get(field.name) {
        Some(Value::Ipv4(a)) => *a,
        _ => match &field.default {
            Value::Ipv4(d) if autofill => *d,
            _ => Ipv4Addr::UNSPECIFIED,
        },
    }
}

/// MAC field accessor (explicit or zero).
pub fn mac_or_zero(spec: &LayerSpec, name: &str) -> [u8; 6] {
    match spec.fields.get(name) {
        Some(Value::Mac(m)) => *m,
        _ => [0; 6],
    }
}

/// MAC field accessor: explicit value wins; else schema default when
/// autofilling; else all-zero.
pub fn mac_or_default(
    spec: &LayerSpec,
    field: &FieldSchema,
    autofill: bool,
    fallback: [u8; 6],
) -> [u8; 6] {
    match spec.fields.get(field.name) {
        Some(Value::Mac(m)) => *m,
        _ => match &field.default {
            Value::Mac(d) if autofill => *d,
            _ => fallback,
        },
    }
}

/// Bytes field accessor (explicit or empty).
pub fn bytes_or_empty(spec: &LayerSpec, name: &str) -> Bytes {
    match spec.fields.get(name) {
        Some(Value::Bytes(b)) => b.clone(),
        _ => Bytes::new(),
    }
}

/// IPv6 field accessor: explicit value wins; else schema default when
/// autofilling; else unspecified.
pub fn ipv6_or_default(spec: &LayerSpec, field: &FieldSchema, autofill: bool) -> Ipv6Addr {
    match spec.fields.get(field.name) {
        Some(Value::Ipv6(a)) => *a,
        _ => match &field.default {
            Value::Ipv6(d) if autofill => *d,
            _ => Ipv6Addr::UNSPECIFIED,
        },
    }
}

/// L4/ICMPv6 pseudo-header for the recorded [`NetFacts`] (family-aware;
/// `proto` is the upper-layer protocol number — 17 udp, 6 tcp, 58 icmpv6).
pub fn l4_pseudo(net: NetFacts, proto: u8) -> PseudoHeader {
    match net {
        NetFacts::V4 { src, dst, .. } => PseudoHeader::V4 { src, dst, proto },
        NetFacts::V6 { src, dst, .. } => PseudoHeader::V6 { src, dst, proto },
    }
}

/// Record [`NetFacts`] into `ctx.facts` (called by the network-layer
/// codecs before L4).
pub fn record_net_facts(ctx: &mut EncodeCtx<'_>, facts: NetFacts) {
    ctx.facts.net = Some(facts);
}

/// Convenience for codecs: append `bytes` to `ctx.buf`.
pub fn put_bytes(ctx: &mut EncodeCtx<'_>, bytes: &[u8]) {
    ctx.buf.extend_from_slice(bytes);
}

/// Truncate an int to `N` bytes big-endian (explicit values may exceed the
/// wire width; `--strict` or downstream validation catches the bad ones —
/// deliberate invalid packets are a feature).
pub const fn trunc_u8(v: u128) -> u8 {
    v as u8
}

pub const fn trunc_u16(v: u128) -> u16 {
    v as u16
}

/// Is this field kind integer-comparable in filters?
pub const fn is_int_kind(kind: FieldKind) -> bool {
    matches!(
        kind,
        FieldKind::U8 | FieldKind::U16 | FieldKind::U32 | FieldKind::U64 | FieldKind::U128
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Codec, Next, ReadOutcome, Registry};
    use crate::dissect::DecodeCtx;
    use crate::schema::{FieldKind, FieldSchema, LayerSchema};
    use crate::value::parse_value;
    use bytes::BufMut;

    // A tiny fixed-header protocol for engine tests:
    //   id u8 | len u16 | checksum u16      (5-byte header)
    static MOCK_SCHEMA_FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "id",
            kind: FieldKind::U8,
            bit_names: &[],
            default: Value::Int(7),
            required: false,
            doc: "id",
        },
        FieldSchema {
            name: "len",
            kind: FieldKind::U16,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "len",
        },
        FieldSchema {
            name: "checksum",
            kind: FieldKind::U16,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "checksum",
        },
        FieldSchema {
            name: "req",
            kind: FieldKind::U8,
            bit_names: &[],
            default: Value::Int(0),
            required: true,
            doc: "required field",
        },
    ];

    static MOCK_SCHEMA: LayerSchema = LayerSchema {
        kind: "mock",
        rank: 5,
        parents: &[],
        doc: "engine-test mock layer",
        fields: MOCK_SCHEMA_FIELDS,
        records: &[],
    };

    struct MockCodec;

    impl Codec for MockCodec {
        fn schema(&self) -> &'static LayerSchema {
            &MOCK_SCHEMA
        }
        fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
            Ok(6)
        }
        fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
            let start = ctx.buf.len();
            let id = int_or_default(spec, &MOCK_SCHEMA_FIELDS[0], ctx.autofill);
            ctx.buf.put_u8(trunc_u8(id));
            let req = field_int(spec, "req").unwrap_or(0);
            ctx.buf.put_u8(trunc_u8(req));
            let at_len = ctx.buf.len();
            ctx.buf.put_u16(0); // len placeholder
            let at_ck = ctx.buf.len();
            ctx.buf.put_u16(0); // checksum placeholder
            let len_explicit = spec.fields.contains_key("len");
            if len_explicit {
                let v = field_int(spec, "len").unwrap_or(0);
                ctx.buf[at_len..at_len + 2].copy_from_slice(&trunc_u16(v).to_be_bytes());
            }
            ctx.defer(Patch::Length {
                at: at_len,
                base: start,
                explicit: len_explicit,
                path: "mock.len",
            });
            let ck_explicit = spec.fields.contains_key("checksum");
            if ck_explicit {
                let v = field_int(spec, "checksum").unwrap_or(0);
                ctx.buf[at_ck..at_ck + 2].copy_from_slice(&trunc_u16(v).to_be_bytes());
            }
            ctx.defer(Patch::Checksum {
                at: at_ck,
                start,
                end: None,
                pseudo: None,
                explicit: ck_explicit,
                path: "mock.checksum",
            });
            Ok(())
        }
        fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
            if bytes.len() < 6 {
                return ReadOutcome::Anomaly(
                    crate::error::DecodeError::Truncated {
                        kind: "mock",
                        need: 6,
                        have: bytes.len(),
                    },
                    Next::Payload,
                );
            }
            let mut fields = std::collections::BTreeMap::new();
            fields.insert("id".into(), Value::Int(bytes[0] as u128));
            fields.insert("req".into(), Value::Int(bytes[1] as u128));
            fields.insert(
                "len".into(),
                Value::Int(u16::from_be_bytes([bytes[2], bytes[3]]) as u128),
            );
            fields.insert(
                "checksum".into(),
                Value::Int(u16::from_be_bytes([bytes[4], bytes[5]]) as u128),
            );
            let view = crate::dissect::LayerView {
                kind: "mock",
                span: ctx.offset..ctx.offset + 6,
                field_spans: Default::default(),
                fields,
            };
            ReadOutcome::Layer(view, Some(Next::Payload))
        }
    }

    static MOCK_CODEC: MockCodec = MockCodec;

    fn mock_registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&MOCK_CODEC);
        r
    }

    fn mock_spec(fields: &[(&str, &str)]) -> PacketSpec {
        let mut spec = LayerSpec::new("mock");
        for (k, v) in fields {
            let f = MOCK_SCHEMA.field(k.split('.').next().unwrap()).unwrap();
            spec.fields
                .insert(k.to_string(), parse_value(f, v).unwrap());
        }
        PacketSpec::new(
            vec![spec],
            Some(Value::Bytes(Bytes::from_static(&[0xaa, 0xbb]))),
        )
    }

    #[test]
    fn encode_backpatches_len_and_checksum_over_payload() {
        let r = mock_registry();
        let spec = mock_spec(&[("req", "1")]);
        let enc = encode(
            &r,
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        // header 6 (id, req, len u16, ck u16) + payload 2 = 8 bytes total
        assert_eq!(enc.bytes.len(), 8);
        assert_eq!(enc.bytes[0], 7); // autofilled default
        assert_eq!(enc.bytes[1], 1); // explicit req
        // len patch = end - base = whole mock region incl payload
        let len = u16::from_be_bytes([enc.bytes[2], enc.bytes[3]]);
        assert_eq!(len, 8);
        // checksum covers the whole region with its own field zeroed
        let mut acc = ChecksumAccumulator::new();
        acc.add_bytes(&enc.bytes[0..4]);
        acc.add_u16(0);
        acc.add_bytes(&enc.bytes[6..8]);
        assert_eq!(
            u16::from_be_bytes([enc.bytes[4], enc.bytes[5]]),
            acc.value()
        );
    }

    #[test]
    fn encode_requires_required_field() {
        let r = mock_registry();
        // no "req"
        let mut spec = LayerSpec::new("mock");
        spec.fields.insert("id".into(), Value::Int(1));
        let ps = PacketSpec::new(vec![spec], None);
        let err = encode(&r, &ps, &EncodeOpts::default()).unwrap_err();
        assert!(matches!(err, EncodeError::Unfillable { field } if field == "mock.req"));
    }

    #[test]
    fn encode_unknown_layer_and_empty_stack() {
        let r = mock_registry();
        let spec = LayerSpec::new("nope");
        let ps = PacketSpec::new(vec![spec.clone()], None);
        assert!(matches!(
            encode(&r, &ps, &EncodeOpts::default()),
            Err(EncodeError::IncompatibleStack { .. })
        ));
        let empty = PacketSpec::new(vec![], None);
        assert!(matches!(
            encode(&r, &empty, &EncodeOpts::default()),
            Err(EncodeError::IncompatibleStack { .. })
        ));
    }

    #[test]
    fn strict_catches_explicit_bad_len_and_checksum() {
        let r = mock_registry();
        let spec = mock_spec(&[("req", "1"), ("len", "999"), ("checksum", "0xdead")]);
        let enc = encode(
            &r,
            &spec,
            &EncodeOpts {
                autofill: true,
                strict: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(enc.violations.len(), 2);
        let paths: Vec<&str> = enc.violations.iter().map(|v| v.path.as_str()).collect();
        assert!(paths.contains(&"mock.len"));
        assert!(paths.contains(&"mock.checksum"));
        assert!(enc.violations[0].message.contains("actual"));
        // without strict: no violations, user values kept as written
        let enc2 = encode(
            &r,
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(enc2.violations.is_empty());
        assert_eq!(u16::from_be_bytes([enc2.bytes[2], enc2.bytes[3]]), 999);
        assert_eq!(u16::from_be_bytes([enc2.bytes[4], enc2.bytes[5]]), 0xdead);
    }

    #[test]
    fn strict_ok_when_consistent() {
        let r = mock_registry();
        // precompute consistent len/checksum by encoding once without strict
        let spec = mock_spec(&[("req", "1")]);
        let enc = encode(
            &r,
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        let len = u16::from_be_bytes([enc.bytes[2], enc.bytes[3]]);
        let ck = u16::from_be_bytes([enc.bytes[4], enc.bytes[5]]);
        let spec2 = mock_spec(&[
            ("req", "1"),
            ("len", &len.to_string()),
            ("checksum", &format!("0x{ck:04x}")),
        ]);
        let enc2 = encode(
            &r,
            &spec2,
            &EncodeOpts {
                autofill: true,
                strict: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(enc2.violations.is_empty());
    }

    #[test]
    fn no_autofill_zeros_defaults() {
        let r = mock_registry();
        let spec = mock_spec(&[("req", "1")]);
        let enc = encode(
            &r,
            &spec,
            &EncodeOpts {
                autofill: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(enc.bytes[0], 0); // id default 7 NOT applied
        assert_eq!(enc.bytes[1], 1); // req explicit
    }

    // --- direct helper coverage (pass-2 mutation kill-strength) -----------

    fn hfield(
        name: &'static str,
        kind: FieldKind,
        bit_names: &'static [&'static str],
        default: Value,
    ) -> FieldSchema {
        FieldSchema {
            name,
            kind,
            bit_names,
            default,
            required: false,
            doc: "",
        }
    }

    #[test]
    fn serialize_field_value_matrix() {
        let bytes = |b: &[u8]| Some(b.to_vec());
        // Numeric windows: BE, masked into ceil(bits/8) bytes.
        assert_eq!(
            serialize_field_value(FieldKind::U16, &[], 12, &Value::Int(0x0abc)),
            bytes(&[0x0a, 0xbc])
        );
        assert_eq!(
            serialize_field_value(FieldKind::U8, &[], 8, &Value::Int(0x1ff)),
            bytes(&[0xff])
        );
        // bits == 0 and bits > 16*8 never serialize (numeric kinds).
        assert_eq!(
            serialize_field_value(FieldKind::U8, &[], 0, &Value::Int(1)),
            None
        );
        assert_eq!(
            serialize_field_value(FieldKind::U8, &[], 129, &Value::Int(1)),
            None
        );
        // bits == 128: the full 16-byte window, mask = u128::MAX.
        assert_eq!(
            serialize_field_value(FieldKind::U128, &[], 128, &Value::Int(u128::MAX)),
            bytes(&u128::MAX.to_be_bytes())
        );
        // Bytes kinds: value splices at any width (no bit constraint).
        assert_eq!(
            serialize_field_value(
                FieldKind::Bytes,
                &[],
                200,
                &Value::Bytes(Bytes::from_static(&[1, 2, 3]))
            ),
            bytes(&[1, 2, 3])
        );
        assert_eq!(
            serialize_field_value(
                FieldKind::ByteList,
                &[],
                0,
                &Value::Bytes(Bytes::from_static(&[9]))
            ),
            bytes(&[9])
        );
        // Int on a Bytes kind: falls through to None.
        assert_eq!(
            serialize_field_value(FieldKind::Bytes, &[], 8, &Value::Int(1)),
            None
        );
        // Typed arms.
        assert_eq!(
            serialize_field_value(
                FieldKind::Ipv4,
                &[],
                32,
                &Value::Ipv4("1.2.3.4".parse().unwrap())
            ),
            bytes(&[1, 2, 3, 4])
        );
        assert_eq!(
            serialize_field_value(
                FieldKind::Ipv6,
                &[],
                128,
                &Value::Ipv6("::1".parse().unwrap())
            ),
            bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(
            serialize_field_value(FieldKind::Mac, &[], 48, &Value::Mac([1, 2, 3, 4, 5, 6])),
            bytes(&[1, 2, 3, 4, 5, 6])
        );
        assert_eq!(
            serialize_field_value(FieldKind::Str, &[], 16, &Value::Str("hi".into())),
            bytes(b"hi")
        );
        // FlagSet: raw int rides the numeric path.
        assert_eq!(
            serialize_field_value(FieldKind::FlagSet, &[], 8, &Value::Int(0xab)),
            bytes(&[0xab])
        );
        // FlagSet aggregate bit names (MSB-first unit convention):
        // syn = bit 1, ack = bit 0 → 0b11 in a 16-bit window.
        assert_eq!(
            serialize_field_value(
                FieldKind::FlagSet,
                &["syn", "ack"],
                16,
                &Value::List(vec![Value::Str("syn".into()), Value::Str("ack".into())])
            ),
            bytes(&[0x00, 0x03])
        );
        // Unknown / mistyped flag items: None.
        assert_eq!(
            serialize_field_value(
                FieldKind::FlagSet,
                &["syn"],
                16,
                &Value::List(vec![Value::Str("nope".into())])
            ),
            None
        );
        assert_eq!(
            serialize_field_value(
                FieldKind::FlagSet,
                &["syn"],
                16,
                &Value::List(vec![Value::Int(1)])
            ),
            None
        );
        assert_eq!(
            serialize_field_value(FieldKind::FlagSet, &["syn"], 16, &Value::Str("syn".into())),
            None
        );
        // Wide bit tables exercise the `n > 8*16` guard: 32 names fit
        // (b0 → 1<<31 → an 8-byte window), 128 names are the boundary.
        let names: &'static [&'static str] = Box::leak(
            (0..32)
                .map(|i| Box::leak(format!("b{i}").into_boxed_str()) as &'static str)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        assert_eq!(
            serialize_field_value(
                FieldKind::FlagSet,
                names,
                64,
                &Value::List(vec![Value::Str("b0".into())])
            ),
            bytes(&[0, 0, 0, 0, 0x80, 0, 0, 0])
        );
        let names128: &'static [&'static str] = Box::leak(
            (0..128)
                .map(|i| Box::leak(format!("b{i}").into_boxed_str()) as &'static str)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        assert_eq!(
            serialize_field_value(
                FieldKind::FlagSet,
                names128,
                128,
                &Value::List(vec![Value::Str("b0".into())])
            ),
            bytes(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        );
        // A >128-name unit has no consistent window (the second guard
        // clause): None, never a phantom shift.
        let names129: &'static [&'static str] = Box::leak(
            (0..129)
                .map(|i| Box::leak(format!("b{i}").into_boxed_str()) as &'static str)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        assert_eq!(
            serialize_field_value(
                FieldKind::FlagSet,
                names129,
                128,
                &Value::List(vec![Value::Str("b0".into())])
            ),
            None
        );
        // Type mismatches: None across kinds.
        assert_eq!(
            serialize_field_value(FieldKind::Str, &[], 16, &Value::Int(1)),
            None
        );
        assert_eq!(
            serialize_field_value(FieldKind::Ipv4, &[], 32, &Value::Str("x".into())),
            None
        );
        assert_eq!(
            serialize_field_value(
                FieldKind::U8,
                &[],
                8,
                &Value::Bytes(Bytes::from_static(&[1]))
            ),
            None
        );
        assert_eq!(
            serialize_field_value(FieldKind::Mac, &[], 48, &Value::Int(1)),
            None
        );
    }

    #[test]
    fn spec_accessors() {
        let f7 = hfield("id", FieldKind::U8, &[], Value::Int(7));
        let fstr = hfield("s", FieldKind::Str, &[], Value::Str("x".into()));
        let mut explicit = LayerSpec::new("mock");
        explicit.fields.insert("id".into(), Value::Int(9));
        let empty = LayerSpec::new("mock");
        // int_or_default: explicit wins (autofill on or off), default
        // applies only when autofilling, non-int default falls to 0.
        assert_eq!(int_or_default(&explicit, &f7, true), 9);
        assert_eq!(int_or_default(&explicit, &f7, false), 9);
        assert_eq!(int_or_default(&empty, &f7, true), 7);
        assert_eq!(int_or_default(&empty, &f7, false), 0);
        assert_eq!(int_or_default(&empty, &fstr, true), 0);
        assert_eq!(field_value(&explicit, "id"), Some(&Value::Int(9)));
        assert_eq!(field_value(&empty, "id"), None);
        assert_eq!(field_int(&explicit, "id"), Some(9));
        assert_eq!(field_int(&empty, "id"), None);
        explicit.fields.insert("s".into(), Value::Str("v".into()));
        assert_eq!(field_int(&explicit, "s"), None); // non-int is not an int
        // trunc helpers.
        assert_eq!(trunc_u8(0x1ff), 0xff);
        assert_eq!(trunc_u16(0x12345), 0x2345);
        // is_int_kind: exactly the U* kinds.
        assert!(is_int_kind(FieldKind::U8));
        assert!(is_int_kind(FieldKind::U16));
        assert!(is_int_kind(FieldKind::U32));
        assert!(is_int_kind(FieldKind::U64));
        assert!(is_int_kind(FieldKind::U128));
        assert!(!is_int_kind(FieldKind::FlagSet));
        assert!(!is_int_kind(FieldKind::Ipv4));
        assert!(!is_int_kind(FieldKind::Str));
    }

    #[test]
    fn flagset_aggregate_bits() {
        // df = bit 1, mf = bit 0 (MSB-first). Two observability phases —
        // a single default cannot cover both: for bit 0 the mutant
        // `1 >> bit` is *identical* to `1 << bit`, so each path needs a
        // bit-1 observation, and the set/clear state must come from the
        // default (a later insert *replaces* the earlier subpath key in
        // the map — there is no history).
        //
        // A. the SET path: default carries bit 0, a subpath sets bit 1.
        let ff_set = hfield("flags", FieldKind::FlagSet, &["df", "mf"], Value::Int(0b01));
        let mut spec = LayerSpec::new("mock");
        // The default applies only under autofill.
        assert_eq!(flagset_or_default(&spec, &ff_set, false), 0);
        assert_eq!(flagset_or_default(&spec, &ff_set, true), 0b01);
        spec.fields.insert("flags.df".into(), Value::Bool(true));
        // 0b01 | 0b10 = 0b11 — a right-shifted bit sets nothing.
        assert_eq!(flagset_or_default(&spec, &ff_set, true), 0b11);
        // Explicit aggregate wins over the default (no sub-bit paths:
        // the subbits otherwise determine the value).
        let mut explicit = LayerSpec::new("mock");
        explicit.fields.insert("flags".into(), Value::Int(0b01));
        assert_eq!(flagset_or_default(&explicit, &ff_set, true), 0b01);
        explicit.fields.insert("flags".into(), Value::Int(0b10));
        assert_eq!(flagset_or_default(&explicit, &ff_set, true), 0b10);

        // B. the CLEAR path: default carries bit 1, a subpath clears it.
        let ff_clr = hfield("flags", FieldKind::FlagSet, &["df", "mf"], Value::Int(0b10));
        let mut spec = LayerSpec::new("mock");
        assert_eq!(flagset_or_default(&spec, &ff_clr, true), 0b10);
        spec.fields.insert("flags.df".into(), Value::Bool(false));
        // 0b10 & !0b10 = 0b00 — a right-shifted mask clears nothing.
        assert_eq!(flagset_or_default(&spec, &ff_clr, true), 0b00);
        // Non-bool subpath counts as a clear, not a set (bit 1 again).
        spec.fields.insert("flags.df".into(), Value::Int(1));
        assert_eq!(flagset_or_default(&spec, &ff_clr, true), 0b00);
        // Setting the other bit leaves the cleared bit clear.
        spec.fields.insert("flags.mf".into(), Value::Bool(true));
        assert_eq!(flagset_or_default(&spec, &ff_clr, true), 0b01);
        // Unrelated prefixes never touch the aggregate.
        spec.fields.insert("nope.df".into(), Value::Bool(true));
        spec.fields.insert("flagsx".into(), Value::Bool(true));
        assert_eq!(flagset_or_default(&spec, &ff_clr, true), 0b01);
    }

    #[test]
    fn addr_and_bytes_accessors() {
        let fi = hfield(
            "src",
            FieldKind::Ipv4,
            &[],
            Value::Ipv4("10.0.0.9".parse().unwrap()),
        );
        let f6 = hfield(
            "src6",
            FieldKind::Ipv6,
            &[],
            Value::Ipv6("2001:db8::9".parse().unwrap()),
        );
        let fm = hfield("dst", FieldKind::Mac, &[], Value::Mac([9; 6]));
        let mut s = LayerSpec::new("mock");
        // Absent: zero / unspecified / empty.
        assert_eq!(ipv4_or_zero(&s, "src"), Ipv4Addr::UNSPECIFIED);
        assert_eq!(mac_or_zero(&s, "dst"), [0; 6]);
        assert_eq!(bytes_or_empty(&s, "opts"), Bytes::new());
        // Default applies only when autofilling.
        assert_eq!(
            ipv4_or_default(&s, &fi, true),
            "10.0.0.9".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(ipv4_or_default(&s, &fi, false), Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            ipv6_or_default(&s, &f6, true),
            "2001:db8::9".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(ipv6_or_default(&s, &f6, false), Ipv6Addr::UNSPECIFIED);
        assert_eq!(mac_or_default(&s, &fm, true, [1; 6]), [9; 6]);
        assert_eq!(mac_or_default(&s, &fm, false, [1; 6]), [1; 6]);
        // Explicit wins over everything.
        s.fields
            .insert("src".into(), Value::Ipv4("1.1.1.1".parse().unwrap()));
        assert_eq!(
            ipv4_or_zero(&s, "src"),
            "1.1.1.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            ipv4_or_default(&s, &fi, false),
            "1.1.1.1".parse::<Ipv4Addr>().unwrap()
        );
        s.fields
            .insert("dst".into(), Value::Mac([1, 2, 3, 4, 5, 6]));
        assert_eq!(mac_or_zero(&s, "dst"), [1, 2, 3, 4, 5, 6]);
        assert_eq!(mac_or_default(&s, &fm, false, [9; 6]), [1, 2, 3, 4, 5, 6]);
        s.fields
            .insert("src6".into(), Value::Ipv6("::2".parse().unwrap()));
        assert_eq!(
            ipv6_or_default(&s, &f6, false),
            "::2".parse::<Ipv6Addr>().unwrap()
        );
        s.fields
            .insert("opts".into(), Value::Bytes(Bytes::from_static(&[0xaa])));
        assert_eq!(bytes_or_empty(&s, "opts"), Bytes::from_static(&[0xaa]));
    }

    #[test]
    fn pseudo_facts_and_ctx_helpers() {
        let net4 = NetFacts::V4 {
            src: "1.1.1.1".parse().unwrap(),
            dst: "2.2.2.2".parse().unwrap(),
            proto: 17,
        };
        assert_eq!(net4.proto(), 17);
        let net6 = NetFacts::V6 {
            src: "::1".parse().unwrap(),
            dst: "::2".parse().unwrap(),
            next_header: 58,
        };
        assert_eq!(net6.proto(), 58);
        let (s4, d4) = ("1.1.1.1".parse().unwrap(), "2.2.2.2".parse().unwrap());
        let (s6, d6) = ("::1".parse().unwrap(), "::2".parse().unwrap());
        match l4_pseudo(net4, 6) {
            PseudoHeader::V4 { src, dst, proto } => {
                assert_eq!((src, dst, proto), (s4, d4, 6));
            }
            PseudoHeader::V6 { .. } => panic!("v4 facts must yield a v4 pseudo-header"),
        }
        match l4_pseudo(net6, 58) {
            PseudoHeader::V6 { src, dst, proto } => {
                assert_eq!((src, dst, proto), (s6, d6, 58));
            }
            PseudoHeader::V4 { .. } => panic!("v6 facts must yield a v6 pseudo-header"),
        }
        // EncodeCtx helpers: put_bytes appends, defer records, facts land.
        let mut buf = BytesMut::new();
        let mut ctx = EncodeCtx {
            buf: &mut buf,
            facts: Facts::default(),
            autofill: true,
            payload: None,
            next: None,
            deferred: Vec::new(),
        };
        put_bytes(&mut ctx, &[1, 2]);
        put_bytes(&mut ctx, &[3]);
        assert_eq!(&ctx.buf[..], &[1, 2, 3]);
        ctx.defer(Patch::MinByte {
            at: 0,
            min: 1,
            path: "t",
        });
        assert_eq!(ctx.deferred.len(), 1);
        record_net_facts(&mut ctx, net4);
        assert_eq!(ctx.facts.net, Some(net4));
    }

    // --- a second fixture codec: resolve_patches arm coverage -------------
    //
    // The 6-byte MOCK above never observes MinNibble/MinByte, the u16
    // length boundary, or a pseudo-headered checksum; RIG covers those.
    // RIG header (8 bytes): id u8 | req u8 | nib<<4 u8 | minb u8 |
    // len u16 @4 | checksum u16 @6.

    static RIG_FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "id",
            kind: FieldKind::U8,
            bit_names: &[],
            default: Value::Int(7),
            required: false,
            doc: "id",
        },
        FieldSchema {
            name: "req",
            kind: FieldKind::U8,
            bit_names: &[],
            default: Value::Int(0),
            required: true,
            doc: "required",
        },
        FieldSchema {
            name: "nib",
            kind: FieldKind::U8,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "MinNibble target",
        },
        FieldSchema {
            name: "minb",
            kind: FieldKind::U8,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "MinByte target",
        },
        FieldSchema {
            name: "len",
            kind: FieldKind::U16,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "len",
        },
        FieldSchema {
            name: "checksum",
            kind: FieldKind::U16,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "checksum",
        },
    ];

    static RIG_SCHEMA: LayerSchema = LayerSchema {
        kind: "rig",
        rank: 5,
        parents: &[],
        doc: "resolve-patches fixture",
        fields: RIG_FIELDS,
        records: &[],
    };

    struct RigCodec;

    impl Codec for RigCodec {
        fn schema(&self) -> &'static LayerSchema {
            &RIG_SCHEMA
        }
        fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
            Ok(8)
        }
        fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
            let start = ctx.buf.len();
            let id = int_or_default(spec, &RIG_FIELDS[0], ctx.autofill);
            ctx.buf.put_u8(trunc_u8(id));
            let req = field_int(spec, "req").unwrap_or(0);
            ctx.buf.put_u8(trunc_u8(req));
            let nib = int_or_default(spec, &RIG_FIELDS[2], ctx.autofill);
            // low nibble: the byte the MinNibble gate reads (`buf[at] & 0x0f`)
            ctx.buf.put_u8(trunc_u8(nib) & 0x0f);
            let minb = int_or_default(spec, &RIG_FIELDS[3], ctx.autofill);
            ctx.buf.put_u8(trunc_u8(minb));
            let at_len = ctx.buf.len();
            ctx.buf.put_u16(0);
            let len_explicit = spec.fields.contains_key("len");
            if len_explicit {
                let v = field_int(spec, "len").unwrap_or(0);
                ctx.buf[at_len..at_len + 2].copy_from_slice(&trunc_u16(v).to_be_bytes());
            }
            ctx.defer(Patch::Length {
                at: at_len,
                base: start,
                explicit: len_explicit,
                path: "rig.len",
            });
            // Absolute offsets (RIG may not be the first layer).
            ctx.defer(Patch::MinNibble {
                at: start + 2,
                min: 5,
                path: "rig.nib",
            });
            ctx.defer(Patch::MinByte {
                at: start + 3,
                min: 3,
                path: "rig.minb",
            });
            let at_ck = ctx.buf.len();
            ctx.buf.put_u16(0);
            let ck_explicit = spec.fields.contains_key("checksum");
            if ck_explicit {
                let v = field_int(spec, "checksum").unwrap_or(0);
                ctx.buf[at_ck..at_ck + 2].copy_from_slice(&trunc_u16(v).to_be_bytes());
            }
            ctx.defer(Patch::Checksum {
                at: at_ck,
                start,
                end: None,
                pseudo: Some(PseudoHeader::V4 {
                    src: "192.0.2.1".parse().unwrap(),
                    dst: "192.0.2.2".parse().unwrap(),
                    proto: 17,
                }),
                explicit: ck_explicit,
                path: "rig.checksum",
            });
            Ok(())
        }
        fn read<'a>(&self, _bytes: &'a [u8], _ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
            ReadOutcome::Empty
        }
    }

    // A one-byte preamble layer: "pa" writes a marker byte derived from
    // `ctx.next` (killing the `i + 1` layer-lookup mutation) and gives RIG
    // a nonzero start (killing the `start == 0` algebraic aliases).
    struct PaCodec;
    impl Codec for PaCodec {
        fn schema(&self) -> &'static LayerSchema {
            &PA_SCHEMA
        }
        fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
            Ok(1)
        }
        fn write(&self, _spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
            let marker = match ctx.next {
                Some("rig") => 0xd1,
                Some("pa") => 0xd2,
                Some(_) => 0xd3,
                None => 0xd0,
            };
            ctx.buf.put_u8(marker);
            Ok(())
        }
        fn read<'a>(&self, _bytes: &'a [u8], _ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
            ReadOutcome::Empty
        }
    }

    static PA_SCHEMA: LayerSchema = LayerSchema {
        kind: "pa",
        rank: 4,
        parents: &[],
        doc: "preamble fixture",
        fields: &[],
        records: &[],
    };

    static RIG: RigCodec = RigCodec;
    static PA: PaCodec = PaCodec;

    fn rig_registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&PA);
        r.register(&RIG);
        r
    }

    fn rig_spec(fields: &[(&str, &str)], payload: Option<&[u8]>) -> PacketSpec {
        let mut spec = LayerSpec::new("rig");
        for (k, v) in fields {
            let f = RIG_SCHEMA.field(k.split('.').next().unwrap()).unwrap();
            spec.fields
                .insert(k.to_string(), parse_value(f, v).unwrap());
        }
        PacketSpec::new(
            vec![spec],
            payload.map(|p| Value::Bytes(Bytes::copy_from_slice(p))),
        )
    }

    #[test]
    fn rig_header_len_and_preamble_next_marker() {
        let r = rig_registry();
        assert_eq!(RIG.header_len(&LayerSpec::new("rig")).unwrap(), 8);
        assert_eq!(PA.header_len(&LayerSpec::new("pa")).unwrap(), 1);
        // pa@0 sees next = rig → 0xd1; rig@1 is terminal → pa-marker
        // ordering proves the i+1 lookup.
        let mut rig = LayerSpec::new("rig");
        rig.fields.insert("req".into(), Value::Int(1));
        let spec = PacketSpec::new(vec![LayerSpec::new("pa"), rig], None);
        let enc = encode(
            &r,
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(enc.bytes[0], 0xd1);
    }

    #[test]
    fn rig_min_gates_strict_only() {
        let r = rig_registry();
        let enc = |fields: &[(&str, &str)], strict: bool| {
            encode(
                &r,
                &rig_spec(fields, Some(&[0xde, 0xad])),
                &EncodeOpts {
                    autofill: true,
                    strict,
                    ..Default::default()
                },
            )
            .unwrap()
        };
        let paths =
            |e: &Encoded| -> Vec<String> { e.violations.iter().map(|v| v.path.clone()).collect() };
        // nib == min and minb == min: no violations under strict.
        let ok = enc(&[("req", "1"), ("nib", "5"), ("minb", "3")], true);
        assert!(ok.violations.is_empty(), "{:?}", ok.violations);
        // nib < min: exactly the nib violation (minb == min here).
        let low = enc(&[("req", "1"), ("nib", "4"), ("minb", "3")], true);
        assert_eq!(paths(&low), ["rig.nib".to_string()]);
        // nib > min: none (the nibble high half is untouched by the gate).
        let high = enc(&[("req", "1"), ("nib", "6"), ("minb", "3")], true);
        assert!(high.violations.is_empty(), "{:?}", high.violations);
        // minb: 2 violates, 4 does not.
        let mlow = enc(&[("req", "1"), ("nib", "5"), ("minb", "2")], true);
        assert_eq!(paths(&mlow), ["rig.minb".to_string()]);
        let mhigh = enc(&[("req", "1"), ("nib", "5"), ("minb", "4")], true);
        assert!(mhigh.violations.is_empty(), "{:?}", mhigh.violations);
        // Without --strict: nothing is validated at all.
        let lax = enc(&[("req", "1"), ("nib", "4"), ("minb", "2")], false);
        assert!(lax.violations.is_empty(), "{:?}", lax.violations);
    }

    #[test]
    fn rig_length_u16_boundary() {
        let r = rig_registry();
        // 8-byte header + payload: 65535 total fits in u16 …
        let enc = encode(
            &r,
            &rig_spec(&[("req", "1")], Some(&[0u8; 65527])),
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(enc.violations.is_empty(), "{:?}", enc.violations);
        assert_eq!(u16::from_be_bytes([enc.bytes[4], enc.bytes[5]]), 0xffff);
        // … 65536 does not (a violation regardless of --strict).
        let enc = encode(
            &r,
            &rig_spec(&[("req", "1")], Some(&[0u8; 65528])),
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(enc.violations.len(), 1);
        assert_eq!(enc.violations[0].path, "rig.len");
        // The unwritable length stays zero (nothing partial lands).
        assert_eq!(&enc.bytes[4..6], &[0, 0]);
    }

    /// The engine's pseudo-headered checksum over the RIG frame,
    /// recomputed by hand from the same primitives (checksum at
    /// `start + 6`, covered region `[start, at)` ∪ `[at + 2, ..)`).
    fn rig_expected_checksum(frame: &[u8], start: usize) -> u16 {
        let at = start + 6;
        let mut acc = ChecksumAccumulator::new();
        PseudoHeader::V4 {
            src: "192.0.2.1".parse().unwrap(),
            dst: "192.0.2.2".parse().unwrap(),
            proto: 17,
        }
        .accumulate_into(&mut acc, frame.len() - start);
        acc.add_bytes(&frame[start..at]);
        acc.add_u16(0);
        acc.add_bytes(&frame[at + 2..]);
        acc.value()
    }

    #[test]
    fn rig_pseudo_checksum_matches_manual() {
        let r = rig_registry();
        let spec = PacketSpec::new(
            vec![LayerSpec::new("pa"), {
                let mut s = LayerSpec::new("rig");
                s.fields.insert("req".into(), Value::Int(1));
                s
            }],
            Some(Value::Bytes(Bytes::from_static(&[0xde, 0xad]))),
        );
        let enc = encode(
            &r,
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(enc.violations.is_empty());
        // RIG starts at 1 (after the pa preamble): the checksum at
        // 1+6..1+8, the covered region from `start`, the pseudo-header
        // segment length = end - start (nonzero start kills the alias).
        let frame = &enc.bytes[..];
        assert_eq!(
            u16::from_be_bytes([frame[7], frame[8]]),
            rig_expected_checksum(frame, 1)
        );
        // Explicit consistent checksum: no strict violation. The
        // expected value is derived from a lax pre-encode of the SAME
        // field bytes (nib/minb set) so the folds agree.
        let mut s2pre = LayerSpec::new("rig");
        s2pre.fields.insert("req".into(), Value::Int(1));
        s2pre.fields.insert("nib".into(), Value::Int(5));
        s2pre.fields.insert("minb".into(), Value::Int(3));
        let spec2pre = PacketSpec::new(
            vec![LayerSpec::new("pa"), s2pre.clone()],
            Some(Value::Bytes(Bytes::from_static(&[0xde, 0xad]))),
        );
        let pre = encode(
            &r,
            &spec2pre,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(pre.violations.is_empty());
        let ck = rig_expected_checksum(&pre.bytes, 1);
        let mut s2 = s2pre.clone();
        s2.fields.insert("checksum".into(), Value::Int(ck as u128));
        let spec2 = PacketSpec::new(
            vec![LayerSpec::new("pa"), s2],
            Some(Value::Bytes(Bytes::from_static(&[0xde, 0xad]))),
        );
        let enc2 = encode(
            &r,
            &spec2,
            &EncodeOpts {
                autofill: true,
                strict: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            enc2.violations
                .iter()
                .all(|v| v.path != "rig.nib" && v.path != "rig.minb"),
            "{:?}",
            enc2.violations
        );
        assert!(
            enc2.violations.iter().all(|v| v.path != "rig.checksum"),
            "{:?}",
            enc2.violations
        );
        // Explicit wrong checksum: strict flags it (and nothing else).
        let mut s3 = LayerSpec::new("rig");
        s3.fields.insert("req".into(), Value::Int(1));
        s3.fields.insert("nib".into(), Value::Int(5));
        s3.fields.insert("minb".into(), Value::Int(3));
        s3.fields.insert("checksum".into(), Value::Int(0xdead));
        let spec3 = PacketSpec::new(
            vec![LayerSpec::new("pa"), s3],
            Some(Value::Bytes(Bytes::from_static(&[0xde, 0xad]))),
        );
        let enc3 = encode(
            &r,
            &spec3,
            &EncodeOpts {
                autofill: true,
                strict: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(enc3.violations.len(), 1);
        assert_eq!(enc3.violations[0].path, "rig.checksum");
    }
}
