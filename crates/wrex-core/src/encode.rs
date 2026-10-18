//! Single-pass + backpatch encode engine.
//!
//! Layers are written outer→inner into one `BytesMut`; the engine appends
//! the terminal payload after the last codec's write, then resolves the
//! deferred [`Patch`] records (lengths, checksums) against the final buffer.
//! L4 checksums thereby cover the payload without reordering writes.

use std::net::Ipv4Addr;

use bytes::{Bytes, BytesMut};

use crate::checksum::ChecksumAccumulator;
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
    /// by the IPv4 pseudo-header `(src, dst, proto)`.
    Checksum {
        at: usize,
        start: usize,
        end: Option<usize>,
        pseudo: Option<(Ipv4Addr, Ipv4Addr, u8)>,
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
                if let Some((src, dst, proto)) = pseudo {
                    acc.add_ipv4(src);
                    acc.add_ipv4(dst);
                    acc.add_u16(u16::from_be_bytes([0, proto]));
                    acc.add_u16((region_end - start) as u16);
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

/// Record [`NetFacts`] into `ctx.facts` (called by the ipv4 codec before L4).
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
pub fn trunc_u8(v: u128) -> u8 {
    v as u8
}

pub fn trunc_u16(v: u128) -> u16 {
    v as u16
}

/// Is this field kind integer-comparable in filters?
pub fn is_int_kind(kind: FieldKind) -> bool {
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
}
