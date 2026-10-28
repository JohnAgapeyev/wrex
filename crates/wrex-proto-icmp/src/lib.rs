#![forbid(unsafe_code)]
//! wrex ICMP codec (type/code/checksum + echo id/seq for types 0/8, `rest`
//! raw 4 bytes otherwise; rank 30, parent ipv4).

use bytes::{BufMut, Bytes};

use wrex_core::dissect::LayerView;
use wrex_core::encode::{EncodeCtx, Patch, bytes_or_empty, int_or_default};
use wrex_core::error::DecodeError;
use wrex_core::schema::{
    ChecksumEnd, ChecksumStart, Derived, FieldKind, FieldSchema, LayerSchema, Layout, PseudoSource,
};
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;
use wrex_core::{Anomaly, Codec, DecodeCtx, EncodeError, Next, ReadOutcome};

const fn d(name: &'static str, kind: FieldKind, doc: &'static str, default: Value) -> FieldSchema {
    FieldSchema {
        name,
        kind,
        bit_names: &[],
        default,
        required: false,
        doc,
    }
}

static FIELDS: [FieldSchema; 6] = [
    d(
        "type",
        FieldKind::U8,
        "type (autofill: 8 echo request)",
        Value::Int(8),
    ),
    d("code", FieldKind::U8, "code (autofill: 0)", Value::Int(0)),
    d(
        "checksum",
        FieldKind::U16,
        "checksum over header+payload (autofill: computed)",
        Value::Int(0),
    ),
    d(
        "echo.id",
        FieldKind::U16,
        "echo identifier (types 0/8)",
        Value::Int(0),
    ),
    d(
        "echo.seq",
        FieldKind::U16,
        "echo sequence (types 0/8)",
        Value::Int(0),
    ),
    FieldSchema {
        name: "rest",
        kind: FieldKind::Bytes,
        bit_names: &[],
        default: Value::Bytes(Bytes::new()),
        required: false,
        doc: "raw 4-byte rest of header (non-echo types)",
    },
];

/// The kind string this codec implements (ADR 3): the vocabulary is
/// compile-checked and symmetric across codecs.
pub const KIND: &str = "icmp";

pub static SCHEMA: LayerSchema = LayerSchema {
    kind: KIND,
    rank: 30,
    parents: &[wrex_proto_ip::KIND],
    doc: "ICMP (RFC 792) over IPv4. type 0/8 (echo reply/request) expose echo.id and echo.seq plus payload; every other type renders the 4-byte rest of header as icmp.rest raw bytes. checksum autofilled (explicit wins).",
    fields: &FIELDS,
    records: &[],
};

/// ICMP codec unit. Register via [`register`] (the ADR-3 closure);
/// bespoke registries may use `&wrex_proto_icmp::CODEC` directly.
pub struct IcmpCodec;

pub static CODEC: IcmpCodec = IcmpCodec;

/// ADR 3 registration closure: register self (dedup-guarded via
/// [`Registry::get`]), then the parent crates'. Self-first keeps
/// `standard()`'s fixed registration order byte-identical —
/// presence, not order, is the guarantee.
pub fn register(r: &mut wrex_core::Registry) {
    if r.get(KIND).is_none() {
        r.register(&CODEC);
    }
    wrex_proto_ip::register(r);
}

const fn is_echo(icmp_type: u8) -> bool {
    icmp_type == 0 || icmp_type == 8
}

impl Codec for IcmpCodec {
    fn schema(&self) -> &'static LayerSchema {
        &SCHEMA
    }

    fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
        Ok(8)
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let start = ctx.buf.len();
        let icmp_type = int_or_default(spec, &FIELDS[0], af) as u8;
        ctx.buf.put_u8(icmp_type);
        ctx.buf.put_u8(int_or_default(spec, &FIELDS[1], af) as u8);
        let at_ck = ctx.buf.len();
        let ck_explicit = spec.fields.contains_key("checksum");
        if let Some(Value::Int(v)) = spec.fields.get("checksum") {
            ctx.buf.put_u16(*v as u16);
        } else {
            ctx.buf.put_u16(0); // checksum placeholder
        }
        // Rest of header: echo id/seq for echo types, else raw `rest` bytes.
        if is_echo(icmp_type) {
            ctx.buf.put_u16(int_or_default(spec, &FIELDS[3], af) as u16); // echo.id
            ctx.buf.put_u16(int_or_default(spec, &FIELDS[4], af) as u16); // echo.seq
        } else {
            let mut rest = [0u8; 4];
            let bytes = bytes_or_empty(spec, "rest");
            for (i, b) in bytes.iter().take(4).enumerate() {
                rest[i] = *b;
            }
            ctx.buf.extend_from_slice(&rest);
        }
        ctx.defer(Patch::Checksum {
            at: at_ck,
            start,
            end: None, // header + payload
            pseudo: None,
            explicit: ck_explicit,
            path: "icmp.checksum",
        });
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.is_empty() {
            return ReadOutcome::Empty;
        }
        if bytes.len() < 8 {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "icmp",
                    need: 8,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let icmp_type = bytes[0];
        let code = bytes[1];
        let found_ck = u16::from_be_bytes([bytes[2], bytes[3]]);
        // Checksum verify (non-fatal anomaly on mismatch), ck field
        // zeroed. SKIPPED on a fragment carrier: the checksum was
        // folded over the original unfragmented message (RFC 792) —
        // a single fragment can never verify (the kernel/tshark verify
        // post-reassembly; so does `replay --reassemble`).
        if !ctx.facts.fragmented {
            let mut acc = wrex_core::ChecksumAccumulator::new();
            acc.add_bytes(&bytes[..2]);
            acc.add_u16(0);
            acc.add_bytes(&bytes[4..]);
            let computed = acc.value();
            if found_ck != computed {
                ctx.anomalies.push(Anomaly::new(
                    "icmp.checksum",
                    format!("mismatch (computed 0x{computed:04x}, found 0x{found_ck:04x})"),
                ));
            }
        }
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("type".into(), Value::Int(icmp_type as u128));
        fields.insert("code".into(), Value::Int(code as u128));
        fields.insert("checksum".into(), Value::Int(found_ck as u128));
        if is_echo(icmp_type) {
            fields.insert(
                "echo.id".into(),
                Value::Int(u16::from_be_bytes([bytes[4], bytes[5]]) as u128),
            );
            fields.insert(
                "echo.seq".into(),
                Value::Int(u16::from_be_bytes([bytes[6], bytes[7]]) as u128),
            );
        } else {
            fields.insert(
                "rest".into(),
                Value::Bytes(Bytes::copy_from_slice(&bytes[4..8])),
            );
        }
        let view = LayerView {
            kind: "icmp",
            span: ctx.offset..ctx.offset + 8,
            field_spans: Default::default(),
            fields,
        };
        // ICMP is terminal (the payload follows).
        ReadOutcome::Layer(view, Some(Next::Payload))
    }

    /// Tranche 11b fixed layouts (type-dependent 4..8 tail: echo vs rest).
    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        &[
            ("type", Layout::Bytes { at: 0, len: 1 }),
            ("code", Layout::Bytes { at: 1, len: 1 }),
            ("checksum", Layout::Bytes { at: 2, len: 2 }),
            ("echo.id", Layout::Bytes { at: 4, len: 2 }),
            ("echo.seq", Layout::Bytes { at: 6, len: 2 }),
            ("rest", Layout::Bytes { at: 4, len: 4 }),
        ]
    }

    /// `checksum` covers header + payload (no pseudo-header over v4).
    fn derived(&self) -> &'static [Derived] {
        &[Derived::Checksum {
            field: "checksum",
            at: 2,
            start: ChecksumStart::Layer,
            end: ChecksumEnd::Frame,
            pseudo: PseudoSource::None,
        }]
    }
}

#[cfg(feature = "test-util")]
pub mod strategy {
    //! proptest strategies for `LayerSpec` (behind `test-util`).
    use proptest::prelude::*;
    use wrex_core::spec::LayerSpec;
    use wrex_core::value::Value;

    /// Valid icmp specs: echo types (id/seq) or other types (4 rest bytes).
    /// Fields stay consistent with the chosen type so roundtrips are exact.
    /// `code` randomizes (the G1 sweep: never sampled before; the
    /// tshark map compares it, so the differential gains the coverage).
    pub fn strategy() -> BoxedStrategy<LayerSpec> {
        let id = any::<u16>().prop_map(|v| Value::Int(v as u128));
        let rest = proptest::array::uniform4(any::<u8>())
            .prop_map(|b| Value::Bytes(bytes::Bytes::copy_from_slice(&b)));
        (
            proptest::bool::ANY,
            (0u8..=15),
            id.clone(),
            id,
            proptest::option::of(rest),
        )
            .prop_map(|(is_echo, code, id, seq, rest)| {
                let mut fields = std::collections::BTreeMap::new();
                fields.insert("code".into(), Value::Int(code as u128));
                if is_echo {
                    // default type 8 (echo request) → echo id/seq fields
                    fields.insert("type".into(), Value::Int(8));
                    fields.insert("echo.id".into(), id);
                    fields.insert("echo.seq".into(), seq);
                } else {
                    // non-echo type → raw 4-byte rest
                    fields.insert("type".into(), Value::Int(3));
                    if let Some(r) = rest {
                        fields.insert("rest".into(), r);
                    }
                }
                LayerSpec::with_fields("icmp", fields)
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    /// Schema invariant (const-eval pass): no duplicate field names in
    /// the table. `field_names_unique` is a const fn, but the table is a
    /// static (`Bytes` interior mutability blocks const eval), so the
    /// proof runs here instead of in a `const _`.
    #[test]
    fn schema_field_names_unique() {
        assert!(wrex_core::schema::field_names_unique(super::SCHEMA.fields));
    }

    /// Schema invariant (const-eval pass): no duplicate field names in
    /// any table — `field_names_unique` is a const fn, but the tables
    /// are statics (Bytes interior mutability blocks const eval), so
    /// the proof runs here instead.
    use super::*;
    use std::collections::BTreeMap;
    use wrex_core::Registry;
    use wrex_core::dissect::DecodeCtx;
    use wrex_core::encode::{EncodeOpts, encode};
    use wrex_core::spec::PacketSpec;
    use wrex_core::value::parse_value;

    fn f(name: &str) -> &'static FieldSchema {
        SCHEMA.field(name).unwrap()
    }

    fn icmp_spec(fields: &[(&str, &str)]) -> LayerSpec {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            if *k == "rest" {
                map.insert(
                    Cow::Owned(k.to_string()),
                    Value::Bytes(Bytes::from(
                        wrex_core::value::parse_hex_bytes(v.trim_start_matches("hex:")).unwrap(),
                    )),
                );
                continue;
            }
            map.insert(Cow::Owned(k.to_string()), parse_value(f(k), v).unwrap());
        }
        LayerSpec::with_fields("icmp", map)
    }

    fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&CODEC);
        r
    }

    /// ADR 3: ipv4 is a real parent dep, so this registers the actual
    /// ipv4 codec through the `register()` closure and dissects a
    /// crafted ipv4→icmp packet end to end — the string dispatch
    /// table can no longer drift from the kinds it names (no stand-in).
    #[test]
    fn ipv4_dispatches_into_icmp_with_real_codecs() {
        let mut r = wrex_core::Registry::empty();
        register(&mut r);
        let spec = wrex_core::spec::PacketSpec::new(
            vec![
                wrex_core::spec::LayerSpec::new(wrex_proto_ip::KIND),
                icmp_spec(&[]),
            ],
            None,
        );
        let enc = wrex_core::encode::encode(
            &r,
            &spec,
            &wrex_core::encode::EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, wrex_proto_ip::KIND);
        assert_eq!(
            p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec![wrex_proto_ip::KIND, KIND],
            "ipv4.proto 1 must chain into the real icmp codec"
        );
    }

    #[test]
    fn echo_request_default_vector() {
        // type/code default 8/0; checksum computed; id/seq 0
        let enc = encode(
            &registry(),
            &PacketSpec::new(
                vec![icmp_spec(&[])],
                Some(Value::Bytes(Bytes::from_static(&[0xde, 0xad]))),
            ),
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(enc.bytes[..2], [8, 0]);
        // checksum over 08 00 0000 0000 0000 dead
        let mut acc = wrex_core::ChecksumAccumulator::new();
        acc.add_bytes(&[8, 0, 0, 0, 0, 0, 0, 0]);
        acc.add_bytes(&[0xde, 0xad]);
        assert_eq!(
            u16::from_be_bytes([enc.bytes[2], enc.bytes[3]]),
            acc.value()
        );
        // dissect: no anomaly, echo fields present
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "icmp");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[0].fields.get("type"), Some(&Value::Int(8)));
        assert_eq!(p.layers[0].fields.get("echo.id"), Some(&Value::Int(0)));
    }

    #[test]
    fn echo_reply_with_id_seq() {
        let enc = encode(
            &registry(),
            &PacketSpec::new(
                vec![icmp_spec(&[
                    ("type", "0"),
                    ("echo.id", "4242"),
                    ("echo.seq", "7"),
                ])],
                None,
            ),
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(enc.bytes[0], 0);
        assert_eq!(u16::from_be_bytes([enc.bytes[4], enc.bytes[5]]), 4242);
        assert_eq!(u16::from_be_bytes([enc.bytes[6], enc.bytes[7]]), 7);
        // roundtrip
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "icmp");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[0].fields.get("echo.seq"), Some(&Value::Int(7)));
    }

    #[test]
    fn non_echo_rest_bytes() {
        let enc = encode(
            &registry(),
            &PacketSpec::new(
                vec![icmp_spec(&[("type", "3"), ("rest", "hex:01020304")])],
                None,
            ),
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(&enc.bytes[4..8], &[1, 2, 3, 4]);
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "icmp");
        match p.layers[0].fields.get("rest") {
            Some(Value::Bytes(b)) => assert_eq!(&b[..], &[1, 2, 3, 4]),
            other => panic!("rest: {other:?}"),
        }
        assert!(!p.layers[0].fields.contains_key("echo.id"));
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
    }

    #[test]
    fn truncation() {
        let mut ctx = DecodeCtx::new(0);
        assert!(matches!(
            CODEC.read(&[8, 0, 0, 0], &mut ctx),
            ReadOutcome::Anomaly(DecodeError::Truncated { kind: "icmp", .. }, _)
        ));
    }

    #[test]
    fn explicit_checksum_kept_and_strict_catches() {
        let spec = icmp_spec(&[("checksum", "0xdead")]);
        let ps = PacketSpec::new(vec![spec], None);
        let enc = encode(
            &registry(),
            &ps,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(u16::from_be_bytes([enc.bytes[2], enc.bytes[3]]), 0xdead);
        let strict = encode(
            &registry(),
            &ps,
            &EncodeOpts {
                autofill: true,
                strict: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(strict.violations.len(), 1);
        assert_eq!(strict.violations[0].path, "icmp.checksum");
    }
}
