#![forbid(unsafe_code)]
//! wrex ARP codec (Ethernet II hardware form: htype/ptype/hlen/plen/oper/
//! sha/spa/tha/tpa; rank 20, parent eth). `tpa` is required.

use bytes::BufMut;

use wrex_core::dissect::LayerView;
use wrex_core::encode::{EncodeCtx, int_or_default, ipv4_or_zero, mac_or_default};
use wrex_core::error::DecodeError;
use wrex_core::schema::{FieldKind, FieldSchema, LayerSchema, Layout};
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;
use wrex_core::{Codec, DecodeCtx, EncodeError, Next, ReadOutcome};

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

static FIELDS: [FieldSchema; 9] = [
    d(
        "htype",
        FieldKind::U16,
        "hardware type (autofill: 1 ethernet)",
        Value::Int(1),
    ),
    d(
        "ptype",
        FieldKind::U16,
        "protocol type (autofill: 0x0800 ipv4)",
        Value::Int(0x0800),
    ),
    d(
        "hlen",
        FieldKind::U8,
        "hardware address length (autofill: 6)",
        Value::Int(6),
    ),
    d(
        "plen",
        FieldKind::U8,
        "protocol address length (autofill: 4)",
        Value::Int(4),
    ),
    d(
        "oper",
        FieldKind::U16,
        "operation (autofill: 1 request)",
        Value::Int(1),
    ),
    d(
        "sha",
        FieldKind::Mac,
        "sender hardware address (autofill: 00:00:00:00:00:00)",
        Value::Mac([0; 6]),
    ),
    d(
        "spa",
        FieldKind::Ipv4,
        "sender protocol address",
        Value::Ipv4(std::net::Ipv4Addr::UNSPECIFIED),
    ),
    d(
        "tha",
        FieldKind::Mac,
        "target hardware address (autofill: 00:00:00:00:00:00)",
        Value::Mac([0; 6]),
    ),
    FieldSchema {
        name: "tpa",
        kind: FieldKind::Ipv4,
        bit_names: &[],
        default: Value::Ipv4(std::net::Ipv4Addr::UNSPECIFIED),
        required: true,
        doc: "target protocol address (required)",
    },
];

/// The kind string this codec implements (ADR 3): nothing references it
/// as a parent today, but the vocabulary stays compile-checked and
/// symmetric across codecs.
pub const KIND: &str = "arp";

pub static SCHEMA: LayerSchema = LayerSchema {
    kind: KIND,
    rank: 20,
    parents: &[wrex_proto_eth::KIND, wrex_proto_vlan::KIND],
    doc: "Address Resolution Protocol (RFC 826) for Ethernet: fixed 28-byte request/reply header (htype=1 Ethernet, ptype=0x0800 IPv4, hlen=6, plen=4). oper: 1=request, 2=reply. Terminal layer; carries no next-header chain. Stacks on eth or vlan (802.1Q tag). tpa is required: crafting without it is an Unfillable error.",
    fields: &FIELDS,
    records: &[],
};

/// ARP codec unit. Register via [`register`] (the ADR-3 closure);
/// bespoke registries may use `&wrex_proto_arp::CODEC` directly.
pub struct ArpCodec;

pub static CODEC: ArpCodec = ArpCodec;

/// ADR 3 registration closure: register self (dedup-guarded via
/// [`Registry::get`]), then the parent crates'. Self-first keeps
/// `standard()`'s fixed registration order byte-identical —
/// presence, not order, is the guarantee.
pub fn register(r: &mut wrex_core::Registry) {
    if r.get(KIND).is_none() {
        r.register(&CODEC);
    }
    wrex_proto_eth::register(r);
    wrex_proto_vlan::register(r);
}

impl Codec for ArpCodec {
    fn schema(&self) -> &'static LayerSchema {
        &SCHEMA
    }

    fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
        Ok(28)
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        ctx.buf.put_u16(int_or_default(spec, &FIELDS[0], af) as u16);
        ctx.buf.put_u16(int_or_default(spec, &FIELDS[1], af) as u16);
        ctx.buf.put_u8(int_or_default(spec, &FIELDS[2], af) as u8);
        ctx.buf.put_u8(int_or_default(spec, &FIELDS[3], af) as u8);
        ctx.buf.put_u16(int_or_default(spec, &FIELDS[4], af) as u16);
        ctx.buf
            .extend_from_slice(&mac_or_default(spec, &FIELDS[5], af, [0; 6]));
        ctx.buf
            .extend_from_slice(&ipv4_or_zero(spec, "spa").octets());
        ctx.buf
            .extend_from_slice(&mac_or_default(spec, &FIELDS[7], af, [0; 6]));
        ctx.buf
            .extend_from_slice(&ipv4_or_zero(spec, "tpa").octets());
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.is_empty() {
            return ReadOutcome::Empty;
        }
        if bytes.len() < 28 {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "arp",
                    need: 28,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let mut sha = [0u8; 6];
        sha.copy_from_slice(&bytes[8..14]);
        let mut tha = [0u8; 6];
        tha.copy_from_slice(&bytes[18..24]);
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "htype".into(),
            Value::Int(u16::from_be_bytes([bytes[0], bytes[1]]) as u128),
        );
        fields.insert(
            "ptype".into(),
            Value::Int(u16::from_be_bytes([bytes[2], bytes[3]]) as u128),
        );
        fields.insert("hlen".into(), Value::Int(bytes[4] as u128));
        fields.insert("plen".into(), Value::Int(bytes[5] as u128));
        fields.insert(
            "oper".into(),
            Value::Int(u16::from_be_bytes([bytes[6], bytes[7]]) as u128),
        );
        fields.insert("sha".into(), Value::Mac(sha));
        fields.insert(
            "spa".into(),
            Value::Ipv4(std::net::Ipv4Addr::new(
                bytes[14], bytes[15], bytes[16], bytes[17],
            )),
        );
        fields.insert("tha".into(), Value::Mac(tha));
        fields.insert(
            "tpa".into(),
            Value::Ipv4(std::net::Ipv4Addr::new(
                bytes[24], bytes[25], bytes[26], bytes[27],
            )),
        );
        let view = LayerView {
            kind: "arp",
            span: ctx.offset..ctx.offset + 28,
            field_spans: Default::default(),
            fields,
        };
        // ARP is terminal.
        ReadOutcome::Layer(view, Some(Next::Payload))
    }

    /// Tranche 11b fixed layouts (28-byte header).
    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        &[
            ("htype", Layout::Bytes { at: 0, len: 2 }),
            ("ptype", Layout::Bytes { at: 2, len: 2 }),
            ("hlen", Layout::Bytes { at: 4, len: 1 }),
            ("plen", Layout::Bytes { at: 5, len: 1 }),
            ("oper", Layout::Bytes { at: 6, len: 2 }),
            ("sha", Layout::Bytes { at: 8, len: 6 }),
            ("spa", Layout::Bytes { at: 14, len: 4 }),
            ("tha", Layout::Bytes { at: 18, len: 6 }),
            ("tpa", Layout::Bytes { at: 24, len: 4 }),
        ]
    }
}

#[cfg(feature = "test-util")]
pub mod strategy {
    //! proptest strategies for `LayerSpec` (behind `test-util`).
    use proptest::prelude::*;
    use wrex_core::spec::LayerSpec;
    use wrex_core::value::Value;

    /// Valid ARP specs: standard fixed header values + arbitrary addresses.
    pub fn strategy() -> BoxedStrategy<LayerSpec> {
        let oper =
            proptest::sample::select(vec![1u16, 2, 3, 4]).prop_map(|v| Value::Int(v as u128));
        let mac = proptest::array::uniform6(any::<u8>()).prop_map(Value::Mac);
        let ip = (any::<u32>()).prop_map(|v| Value::Ipv4(std::net::Ipv4Addr::from(v)));
        (oper, mac.clone(), ip.clone(), mac, ip)
            .prop_map(|(oper, sha, spa, tha, tpa)| {
                let mut fields = std::collections::BTreeMap::new();
                fields.insert("oper".into(), oper);
                fields.insert("sha".into(), sha);
                fields.insert("spa".into(), spa);
                fields.insert("tha".into(), tha);
                fields.insert("tpa".into(), tpa); // required: always set
                LayerSpec::with_fields("arp", fields)
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
    use wrex_core::dissect::DecodeCtx;
    use wrex_core::encode::{EncodeOpts, encode};
    use wrex_core::spec::PacketSpec;
    use wrex_core::value::parse_value;
    use wrex_core::{ReadOutcome, Registry};

    fn f(name: &str) -> &'static FieldSchema {
        SCHEMA.field(name).unwrap()
    }

    fn arp_spec(fields: &[(&str, &str)]) -> LayerSpec {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            map.insert(Cow::Owned(k.to_string()), parse_value(f(k), v).unwrap());
        }
        LayerSpec::with_fields("arp", map)
    }

    fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&CODEC);
        r
    }

    /// ADR 3: eth is a real parent dep, so this registers the actual
    /// eth codec through the `register()` closure and dissects a
    /// crafted eth→arp frame end to end — the string dispatch table
    /// can no longer drift from the kinds it names (no stand-in).
    #[test]
    fn eth_dispatches_into_arp_with_real_codecs() {
        let mut r = wrex_core::Registry::empty();
        register(&mut r);
        let spec = wrex_core::spec::PacketSpec::new(
            vec![
                wrex_core::spec::LayerSpec::new(wrex_proto_eth::KIND),
                arp_spec(&[("tpa", "10.0.0.1")]),
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
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, wrex_proto_eth::KIND);
        assert_eq!(
            p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec![wrex_proto_eth::KIND, KIND],
            "eth.type 0x0806 must chain into the real arp codec"
        );
    }

    #[test]
    fn standard_request_vector() {
        let spec = arp_spec(&[
            ("sha", "00:11:22:33:44:55"),
            ("spa", "192.168.1.1"),
            ("tha", "00:00:00:00:00:00"),
            ("tpa", "192.168.1.2"),
        ]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(enc.bytes.len(), 28);
        assert_eq!(&enc.bytes[0..2], &[0x00, 0x01]); // htype 1
        assert_eq!(&enc.bytes[2..4], &[0x08, 0x00]); // ptype ipv4
        assert_eq!(enc.bytes[4], 6); // hlen
        assert_eq!(enc.bytes[5], 4); // plen
        assert_eq!(&enc.bytes[6..8], &[0x00, 0x01]); // oper request
        assert_eq!(&enc.bytes[8..14], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(&enc.bytes[14..18], &[192, 168, 1, 1]);
        assert_eq!(&enc.bytes[18..24], &[0; 6]);
        assert_eq!(&enc.bytes[24..28], &[192, 168, 1, 2]);
    }

    #[test]
    fn standard_reply_vector() {
        let spec = arp_spec(&[
            ("oper", "2"),
            ("sha", "aa:bb:cc:dd:ee:ff"),
            ("spa", "10.0.0.2"),
            ("tha", "00:11:22:33:44:55"),
            ("tpa", "10.0.0.1"),
        ]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(&enc.bytes[6..8], &[0x00, 0x02]);
        assert_eq!(&enc.bytes[8..14], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(&enc.bytes[24..28], &[10, 0, 0, 1]);
    }

    #[test]
    fn tpa_required_unfillable() {
        let ps = PacketSpec::new(vec![LayerSpec::new("arp")], None);
        let err = encode(
            &registry(),
            &ps,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, wrex_core::EncodeError::Unfillable { field } if field == "arp.tpa"));
    }

    #[test]
    fn read_golden_and_truncated() {
        let bytes: Vec<u8> = [
            &[0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01][..],
            &[0xaa; 6],
            &[10, 0, 0, 1],
            &[0; 6],
            &[10, 0, 0, 2],
        ]
        .concat();
        let mut ctx = DecodeCtx::new(14);
        match CODEC.read(&bytes, &mut ctx) {
            ReadOutcome::Layer(view, Some(Next::Payload)) => {
                assert_eq!(view.kind, "arp");
                assert_eq!(view.span, 14..42);
                assert_eq!(view.fields.get("oper"), Some(&Value::Int(1)));
                assert_eq!(
                    view.fields.get("spa"),
                    Some(&Value::Ipv4("10.0.0.1".parse().unwrap()))
                );
            }
            other => panic!("expected layer, got {other:?}"),
        }
        let mut ctx = DecodeCtx::new(0);
        assert!(matches!(
            CODEC.read(&bytes[..27], &mut ctx),
            ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "arp",
                    need: 28,
                    have: 27
                },
                _
            )
        ));
    }
}
