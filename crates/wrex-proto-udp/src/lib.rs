#![forbid(unsafe_code)]
//! wrex UDP codec (sport/dport/length/checksum; rank 30, parent ipv4).
//! Checksum covers the IPv4 pseudo-header (RFC 768) + segment + payload;
//! `--udp-checksum=0` gives the scapy-style zero.

use std::sync::LazyLock;

use bytes::BufMut;

use wrex_core::dissect::LayerView;
use wrex_core::encode::{EncodeCtx, Patch, int_or_default};
use wrex_core::error::DecodeError;
use wrex_core::schema::{
    ChecksumEnd, Derived, FieldKind, FieldSchema, LayerSchema, Layout, LengthBase, PseudoSource,
};
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;
use wrex_core::{Anomaly, Codec, DecodeCtx, EncodeError, Next, ReadOutcome};

static FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
    let d = |name: &'static str, kind: FieldKind, doc: &'static str, default: Value| FieldSchema {
        name,
        kind,
        bit_names: &[],
        default,
        required: false,
        doc,
    };
    vec![
        d("sport", FieldKind::U16, "source port", Value::Int(0)),
        d("dport", FieldKind::U16, "destination port", Value::Int(0)),
        d(
            "length",
            FieldKind::U16,
            "length incl. header (autofill: computed)",
            Value::Int(0),
        ),
        d(
            "checksum",
            FieldKind::U16,
            "checksum over pseudo-header+segment (autofill: computed)",
            Value::Int(0),
        ),
    ]
});

pub static SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: "udp",
    rank: 30,
    parents: &["ipv4", "ipv6"],
    doc: "UDP (RFC 768): 8-byte header. length autofilled from header+payload (explicit wins); checksum computed over the pseudo-header (RFC 9293 v4 / RFC 8200 §8.1 v6, family follows the network-layer parent) plus the segment and payload. Explicit --udp-checksum=0 produces the scapy-style unchecked zero. Port-53 datagrams chain into the dns codec (tranche-3 dispatch), port-67/68 into the dhcp codec (tranche 7c); other ports are terminal (the payload follows).",
    fields: FIELDS.as_slice(),
    records: &[],
});

/// UDP codec unit. Register as `&wrex_proto_udp::CODEC`.
pub struct UdpCodec;

pub static CODEC: UdpCodec = UdpCodec;

impl Codec for UdpCodec {
    fn schema(&self) -> &'static LayerSchema {
        &SCHEMA
    }

    fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
        Ok(8)
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let start = ctx.buf.len();
        ctx.buf.put_u16(int_or_default(spec, &FIELDS[0], af) as u16);
        ctx.buf.put_u16(int_or_default(spec, &FIELDS[1], af) as u16);
        let at_len = ctx.buf.len();
        let len_explicit = spec.fields.contains_key("length");
        if let Some(Value::Int(v)) = spec.fields.get("length") {
            ctx.buf.put_u16(*v as u16);
        } else {
            ctx.buf.put_u16(0); // length placeholder
        }
        let at_ck = ctx.buf.len();
        let ck_explicit = spec.fields.contains_key("checksum");
        if let Some(Value::Int(v)) = spec.fields.get("checksum") {
            ctx.buf.put_u16(*v as u16);
        } else {
            ctx.buf.put_u16(0); // checksum placeholder
        }
        // Pseudo-header from NetFacts recorded by the network-layer
        // parent (family-aware; proto 17).
        let pseudo = ctx.facts.net.map(|n| wrex_core::encode::l4_pseudo(n, 17));
        ctx.defer(Patch::Length {
            at: at_len,
            base: start,
            explicit: len_explicit,
            path: "udp.length",
        });
        ctx.defer(Patch::Checksum {
            at: at_ck,
            start,
            end: None,
            pseudo,
            explicit: ck_explicit,
            path: "udp.checksum",
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
                    kind: "udp",
                    need: 8,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let sport = u16::from_be_bytes([bytes[0], bytes[1]]);
        let dport = u16::from_be_bytes([bytes[2], bytes[3]]);
        let length = u16::from_be_bytes([bytes[4], bytes[5]]);
        let found_ck = u16::from_be_bytes([bytes[6], bytes[7]]);
        // Length-vs-actual (non-fatal).
        if length != 0 && length as usize != bytes.len() {
            ctx.anomalies.push(Anomaly::new(
                "udp.length",
                format!(
                    "mismatch (expected {length} (0x{length:04x}), found {} bytes)",
                    bytes.len()
                ),
            ));
        }
        // Checksum verify (non-fatal): pseudo-header (when NetFacts were
        // recorded by a network-layer parent) + segment, ck field zeroed.
        if let Some(net) = ctx.facts.net {
            let mut acc = wrex_core::ChecksumAccumulator::new();
            wrex_core::encode::l4_pseudo(net, 17).accumulate_into(&mut acc, bytes.len());
            acc.add_bytes(&bytes[..6]);
            acc.add_u16(0);
            acc.add_bytes(&bytes[8..]);
            let computed = acc.value();
            if found_ck != computed {
                ctx.anomalies.push(Anomaly::new(
                    "udp.checksum",
                    format!("mismatch (computed 0x{computed:04x}, found 0x{found_ck:04x})"),
                ));
            }
        }
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("sport".into(), Value::Int(sport as u128));
        fields.insert("dport".into(), Value::Int(dport as u128));
        fields.insert("length".into(), Value::Int(length as u128));
        fields.insert("checksum".into(), Value::Int(found_ck as u128));
        let view = LayerView {
            kind: "udp",
            span: ctx.offset..ctx.offset + 8,
            field_spans: Default::default(),
            fields,
        };
        // Port-53 datagrams chain into the dns codec when registered
        // (tranche 3: tshark-parity dispatch); port-67/68 datagrams
        // chain into the dhcp codec (tranche 7c: the same pattern).
        // Otherwise the engine synthesizes the usual `unknown` layer
        // for the payload when the kind is not registered.
        let next = if sport == 53 || dport == 53 {
            Next::Kind("dns")
        } else if sport == 67 || sport == 68 || dport == 67 || dport == 68 {
            Next::Kind("dhcp")
        } else {
            Next::Payload
        };
        ReadOutcome::Layer(view, Some(next))
    }

    /// Tranche 11b fixed layouts (8-byte header).
    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        &[
            ("sport", Layout::Bytes { at: 0, len: 2 }),
            ("dport", Layout::Bytes { at: 2, len: 2 }),
            ("length", Layout::Bytes { at: 4, len: 2 }),
            ("checksum", Layout::Bytes { at: 6, len: 2 }),
        ]
    }

    /// `length` = frame end − layer start; `checksum` covers the
    /// segment to the frame end over the pseudo-header from the net
    /// facts (family follows the parent).
    fn derived(&self) -> &'static [Derived] {
        &[
            Derived::Length {
                field: "length",
                at: 4,
                base: LengthBase::LayerStart,
            },
            Derived::Checksum {
                field: "checksum",
                at: 6,
                end: ChecksumEnd::Frame,
                pseudo: PseudoSource::FromFacts,
            },
        ]
    }
}

#[cfg(feature = "test-util")]
pub mod strategy {
    //! proptest strategies for `LayerSpec` (behind `test-util`).
    use proptest::prelude::*;
    use wrex_core::spec::LayerSpec;
    use wrex_core::value::Value;

    /// Valid udp specs: any ports; derived length/checksum stay unset.
    pub fn strategy() -> BoxedStrategy<LayerSpec> {
        (any::<u16>(), any::<u16>())
            .prop_map(|(sport, dport)| {
                let mut fields = std::collections::BTreeMap::new();
                fields.insert("sport".to_string(), Value::Int(sport as u128));
                fields.insert("dport".to_string(), Value::Int(dport as u128));
                LayerSpec::with_fields("udp", fields)
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use wrex_core::Registry;
    use wrex_core::dissect::{DecodeCtx, Facts, NetFacts};
    use wrex_core::encode::{EncodeOpts, encode};
    use wrex_core::spec::PacketSpec;
    use wrex_core::value::parse_value;

    fn f(name: &str) -> &'static FieldSchema {
        SCHEMA.field(name).unwrap()
    }

    fn udp_spec(fields: &[(&str, &str)]) -> LayerSpec {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            map.insert(k.to_string(), parse_value(f(k), v).unwrap());
        }
        LayerSpec::with_fields("udp", map)
    }

    fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&CODEC);
        r
    }

    fn lo_opts() -> EncodeOpts {
        // The integration golden's NetFacts (127.0.0.1 ↔ 127.0.0.1, udp).
        EncodeOpts {
            autofill: true,
            strict: false,
            facts: Facts {
                net: Some(NetFacts::V4 {
                    src: "127.0.0.1".parse().unwrap(),
                    dst: "127.0.0.1".parse().unwrap(),
                    proto: 17,
                }),
                ..Default::default()
            },
        }
    }

    /// The plan's golden L4 numbers, reproduced independently:
    /// IP cksum 0x7ccb, UDP cksum 0x3d27 over the pseudo-header.
    #[test]
    fn golden_udp_checksum_over_pseudo_header() {
        let spec = udp_spec(&[("sport", "4444"), ("dport", "5555")]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(
                vec![spec],
                Some(Value::Bytes(bytes::Bytes::from_static(&[
                    0xde, 0xad, 0xbe, 0xef,
                ]))),
            ),
            &lo_opts(),
        )
        .unwrap();
        // The plan's golden L4 segment (UDP cksum 0x3d27) + payload.
        assert_eq!(
            &enc.bytes[..],
            &[
                0x11, 0x5c, 0x15, 0xb3, 0x00, 0x0c, 0x3d, 0x27, 0xde, 0xad, 0xbe, 0xef
            ][..]
        );
        let mut acc = wrex_core::ChecksumAccumulator::new();
        acc.add_bytes(&[0x7f, 0x00, 0x00, 0x01]);
        acc.add_bytes(&[0x7f, 0x00, 0x00, 0x01]);
        acc.add_u16(u16::from_be_bytes([0, 17]));
        acc.add_u16(12);
        acc.add_bytes(&enc.bytes[..6]);
        acc.add_u16(0);
        acc.add_bytes(&[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(
            u16::from_be_bytes([enc.bytes[6], enc.bytes[7]]),
            acc.value()
        );
    }

    #[test]
    fn explicit_checksum_zero_kept() {
        let spec = udp_spec(&[("sport", "1"), ("dport", "2"), ("checksum", "0")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        assert_eq!(u16::from_be_bytes([enc.bytes[6], enc.bytes[7]]), 0);
    }

    #[test]
    fn read_verifies_and_flags_mismatch() {
        // Build a correct segment, then corrupt the checksum byte.
        let spec = udp_spec(&[("sport", "4444"), ("dport", "5555")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        let mut ctx = DecodeCtx::new(0);
        ctx.facts.net = lo_opts().facts.net;
        match CODEC.read(&enc.bytes, &mut ctx) {
            ReadOutcome::Layer(view, Some(Next::Payload)) => {
                assert_eq!(view.fields.get("length"), Some(&Value::Int(8)));
                assert!(ctx.anomalies.is_empty(), "{:?}", ctx.anomalies);
            }
            other => panic!("expected layer, got {other:?}"),
        }
        let mut corrupt = enc.bytes.to_vec();
        corrupt[6] ^= 0xff;
        let mut ctx = DecodeCtx::new(0);
        ctx.facts.net = lo_opts().facts.net;
        let _ = CODEC.read(&corrupt, &mut ctx);
        assert_eq!(ctx.anomalies.len(), 1);
        assert!(ctx.anomalies[0].path.starts_with("udp.checksum"));
    }

    #[test]
    fn length_mismatch_anomaly() {
        // explicit bogus length: kept on write (no strict), anomaly on read
        let spec = udp_spec(&[("sport", "1"), ("dport", "2"), ("length", "999")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        assert_eq!(u16::from_be_bytes([enc.bytes[4], enc.bytes[5]]), 999);
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "udp");
        assert!(p.layers[0].kind == "udp");
        assert!(
            p.anomalies.iter().any(|a| a.path == "udp.length"),
            "{:?}",
            p.anomalies
        );
    }

    #[test]
    fn truncation() {
        let mut ctx = DecodeCtx::new(0);
        assert!(matches!(
            CODEC.read(&[0x00; 7], &mut ctx),
            ReadOutcome::Anomaly(DecodeError::Truncated { kind: "udp", .. }, _)
        ));
    }

    /// A minimal stand-in `dns` codec so the port-53 dispatch test does
    /// not need a cross-crate dependency (proto crates stay isolated).
    mod dns_dispatch {
        use super::*;
        use std::collections::BTreeMap;
        use std::sync::LazyLock;

        static DNS_FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(Vec::new);
        static DNS_SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
            kind: "dns",
            rank: 40,
            parents: &["udp"],
            doc: "dispatch stand-in",
            fields: DNS_FIELDS.as_slice(),
            records: &[],
        });

        struct DnsStub;
        impl Codec for DnsStub {
            fn schema(&self) -> &'static LayerSchema {
                &DNS_SCHEMA
            }
            fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
                Ok(0)
            }
            fn write(&self, _spec: &LayerSpec, _ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
                Ok(())
            }
            fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
                let mut fields = BTreeMap::new();
                fields.insert(
                    "stub".to_string(),
                    Value::Bytes(bytes::Bytes::copy_from_slice(bytes)),
                );
                ReadOutcome::Layer(
                    LayerView {
                        kind: "dns",
                        span: ctx.offset..ctx.offset + bytes.len(),
                        field_spans: Default::default(),
                        fields,
                    },
                    Some(Next::Payload),
                )
            }
        }

        static DNS_STUB: DnsStub = DnsStub;

        fn dns_registry() -> Registry {
            let mut r = Registry::empty();
            r.register(&CODEC);
            r.register(&DNS_STUB);
            r
        }

        #[test]
        fn port53_chains_into_dns() {
            let spec = udp_spec(&[("sport", "40000"), ("dport", "53")]);
            let enc = encode(
                &dns_registry(),
                &PacketSpec::new(vec![spec], None),
                &lo_opts(),
            )
            .unwrap();
            let p = wrex_core::dissect::dissect(&dns_registry(), &enc.bytes, "udp");
            assert_eq!(
                p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
                vec!["udp", "dns"],
                "port 53 must chain into the dns codec"
            );
            // source side too
            let spec = udp_spec(&[("sport", "53"), ("dport", "40000")]);
            let enc = encode(
                &dns_registry(),
                &PacketSpec::new(vec![spec], None),
                &lo_opts(),
            )
            .unwrap();
            let p = wrex_core::dissect::dissect(&dns_registry(), &enc.bytes, "udp");
            assert_eq!(
                p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
                vec!["udp", "dns"]
            );
            // other ports stay terminal
            let spec = udp_spec(&[("sport", "1"), ("dport", "2")]);
            let enc = encode(
                &dns_registry(),
                &PacketSpec::new(vec![spec], None),
                &lo_opts(),
            )
            .unwrap();
            let p = wrex_core::dissect::dissect(&dns_registry(), &enc.bytes, "udp");
            assert_eq!(
                p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
                vec!["udp"]
            );
        }

        #[test]
        fn port53_without_dns_codec_stays_terminal() {
            // slim registry: the engine synthesizes the usual `unknown`
            // layer for the remainder — port 53 payloads never vanish.
            let spec = udp_spec(&[("sport", "1"), ("dport", "53")]);
            let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
            let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "udp");
            assert_eq!(
                p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
                vec!["udp", "unknown"]
            );
        }
    }

    /// A minimal stand-in `dhcp` codec so the port-67/68 dispatch test
    /// does not need a cross-crate dependency (proto crates stay
    /// isolated — the tranche-7c mirror of the dns_dispatch module).
    mod dhcp_dispatch {
        use super::*;
        use std::collections::BTreeMap;
        use std::sync::LazyLock;

        static DHCP_FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(Vec::new);
        static DHCP_SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
            kind: "dhcp",
            rank: 40,
            parents: &["udp"],
            doc: "dispatch stand-in",
            fields: DHCP_FIELDS.as_slice(),
            records: &[],
        });

        struct DhcpStub;
        impl Codec for DhcpStub {
            fn schema(&self) -> &'static LayerSchema {
                &DHCP_SCHEMA
            }
            fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
                Ok(0)
            }
            fn write(&self, _spec: &LayerSpec, _ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
                Ok(())
            }
            fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
                let mut fields = BTreeMap::new();
                fields.insert(
                    "stub".to_string(),
                    Value::Bytes(bytes::Bytes::copy_from_slice(bytes)),
                );
                ReadOutcome::Layer(
                    LayerView {
                        kind: "dhcp",
                        span: ctx.offset..ctx.offset + bytes.len(),
                        field_spans: Default::default(),
                        fields,
                    },
                    Some(Next::Payload),
                )
            }
        }

        static DHCP_STUB: DhcpStub = DhcpStub;

        fn dhcp_registry() -> Registry {
            let mut r = Registry::empty();
            r.register(&CODEC);
            r.register(&DHCP_STUB);
            r
        }

        #[test]
        fn ports_67_68_chain_into_dhcp() {
            // client→server (68→67), server→client (67→68), and each
            // port alone on either side.
            for (sport, dport) in [(68, 67), (67, 68), (68, 40000), (40000, 67)] {
                let spec =
                    udp_spec(&[("sport", &sport.to_string()), ("dport", &dport.to_string())]);
                let enc = encode(
                    &dhcp_registry(),
                    &PacketSpec::new(vec![spec], None),
                    &lo_opts(),
                )
                .unwrap();
                let p = wrex_core::dissect::dissect(&dhcp_registry(), &enc.bytes, "udp");
                assert_eq!(
                    p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
                    vec!["udp", "dhcp"],
                    "{sport}→{dport} must chain into the dhcp codec"
                );
            }
            // other ports stay terminal
            let spec = udp_spec(&[("sport", "1"), ("dport", "2")]);
            let enc = encode(
                &dhcp_registry(),
                &PacketSpec::new(vec![spec], None),
                &lo_opts(),
            )
            .unwrap();
            let p = wrex_core::dissect::dissect(&dhcp_registry(), &enc.bytes, "udp");
            assert_eq!(
                p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
                vec!["udp"]
            );
        }

        #[test]
        fn ports_67_68_without_dhcp_codec_stays_terminal() {
            // slim registry: the engine synthesizes the usual `unknown`
            // layer for the remainder — port 67/68 payloads never vanish.
            let spec = udp_spec(&[("sport", "68"), ("dport", "67")]);
            let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
            let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "udp");
            assert_eq!(
                p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
                vec!["udp", "unknown"]
            );
        }
    }
}
