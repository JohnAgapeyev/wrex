#![forbid(unsafe_code)]
//! wrex UDP codec (sport/dport/length/checksum; rank 30, parent ipv4).
//! Checksum covers the IPv4 pseudo-header (RFC 768) + segment + payload;
//! `--udp-checksum=0` gives the scapy-style zero.

use bytes::BufMut;

use wrex_core::dissect::LayerView;
use wrex_core::encode::{EncodeCtx, Patch, int_or_default};
use wrex_core::error::DecodeError;
use wrex_core::schema::{
    ChecksumEnd, ChecksumStart, Derived, FieldKind, FieldSchema, LayerSchema, Layout, LengthBase,
    LengthUnits, PseudoSource,
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

static FIELDS: [FieldSchema; 4] = [
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
];

/// The kind string this codec implements (ADR 3): children (dns, dhcp)
/// reference `wrex_proto_udp::KIND` in their `parents` instead of
/// hand-written strings, so the registry vocabulary is compile-checked.
pub const KIND: &str = "udp";

pub static SCHEMA: LayerSchema = LayerSchema {
    kind: KIND,
    rank: 30,
    parents: &[
        wrex_proto_ip::KIND,
        wrex_proto_ip6::KIND,
        // Tranche 17a: the stackable v6 ext headers (esp/nonext are
        // terminal — nothing stacks on them).
        wrex_proto_ip6ext::KIND_HOPOPTS,
        wrex_proto_ip6ext::KIND_ROUTING,
        wrex_proto_ip6ext::KIND_FRAG,
        wrex_proto_ip6ext::KIND_DSTOPTS,
        wrex_proto_ip6ext::KIND_AH,
    ],
    doc: "UDP (RFC 768): 8-byte header. length autofilled from header+payload (explicit wins); checksum computed over the pseudo-header (RFC 9293 v4 / RFC 8200 §8.1 v6, family follows the network-layer parent) plus the segment and payload. Explicit --udp-checksum=0 produces the scapy-style unchecked zero. Port-53 datagrams chain into the dns codec (tranche-3 dispatch), port-67/68 into the dhcp codec (tranche 7c); mDNS rides 5353 on both ends and LLMNR 5355 either side (tranche 20b); other ports are terminal (the payload follows).",
    fields: &FIELDS,
    records: &[],
};

/// UDP codec unit. Register via [`register`] (the ADR-3 closure);
/// bespoke registries may use `&wrex_proto_udp::CODEC` directly.
pub struct UdpCodec;

pub static CODEC: UdpCodec = UdpCodec;

/// ADR 3 registration closure: register self (dedup-guarded via
/// [`Registry::get`]), then the parent crates'. Self-first keeps
/// `standard()`'s fixed registration order byte-identical —
/// presence, not order, is the guarantee.
pub fn register(r: &mut wrex_core::Registry) {
    if r.get(KIND).is_none() {
        r.register(&CODEC);
    }
    wrex_proto_ip::register(r);
    wrex_proto_ip6::register(r);
    // Tranche 17a: the ext family is a parent now (udp stacks on the
    // five non-terminal kinds — ADR 3: parents are deps).
    wrex_proto_ip6ext::register(r);
}

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
        // The pseudo-header length is the L4 message length — the
        // upper-layer packet EXCLUDES any v6 extension headers (RFC
        // 8200 §8.1 as every real stack implements it; the HP3-b
        // foreign-capture corpus caught the ext-inclusive T17a fold
        // disagreeing with the kernel's own MLD frames by a constant
        // 0x4000). The fold starts at this layer's own header.
        let ck_start = start;
        ctx.defer(Patch::Checksum {
            at: at_ck,
            start: ck_start,
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
        // recorded by a network-layer parent) + the upper-layer packet
        // (tranche 17a: v6 ext headers included, RFC 8200 §8.1), ck
        // field zeroed. With the engine's frame lookback + a recorded
        // upper_start the range starts at the first ext header; the
        // legacy `bytes` slice otherwise (identical on ext-free
        // stacks — `frame[offset..] == bytes`).
        // SKIPPED on a fragment carrier: the pseudo-header length covers
        // the ORIGINAL unfragmented packet — a single fragment can
        // never verify (the HP3-b foreign-fragment corpus drove the
        // skip; the reassembled datagram verifies instead).
        if let (Some(net), false) = (ctx.facts.net, ctx.facts.fragmented) {
            // The fold covers the L4 message only (the pseudo length is
            // bytes.len(); the data starts at this layer — ext headers
            // excluded, the kernel/interop reading of RFC 8200 §8.1).
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
        // chain into the dhcp codec (tranche 7c: the same pattern);
        // 546/547 into dhcp6 (tranche 17c). Tranche 20b: mDNS (RFC 6762)
        // rides 5353 on BOTH ends (queries are 5353→5353; the unicast
        // response 5353→ephemeral would kidnap every ephemeral sport
        // otherwise); LLMNR (RFC 4795, dissect only) rides 5355 either
        // side. Otherwise the engine synthesizes the usual `unknown`
        // layer for the payload when the kind is not registered.
        let next = if sport == 53 || dport == 53 {
            Next::Kind("dns")
        } else if sport == 67 || sport == 68 || dport == 67 || dport == 68 {
            Next::Kind("dhcp")
        } else if sport == 546 || sport == 547 || dport == 546 || dport == 547 {
            Next::Kind("dhcp6")
        } else if (sport == 5353 && dport == 5353) || sport == 5355 || dport == 5355 {
            Next::Kind("dns")
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
                units: LengthUnits::Bytes,
            },
            Derived::Checksum {
                field: "checksum",
                at: 6,
                start: ChecksumStart::UpperPacket,
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
                fields.insert("sport".into(), Value::Int(sport as u128));
                fields.insert("dport".into(), Value::Int(dport as u128));
                LayerSpec::with_fields("udp", fields)
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
            map.insert(Cow::Owned(k.to_string()), parse_value(f(k), v).unwrap());
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
    /// ADR 3: ipv4/ipv6 are real parent deps, so this registers the
    /// actual IP codecs through the `register()` closure and dissects
    /// crafted ip→udp packets end to end, both families — the string
    /// dispatch table can no longer drift from the kinds it names.
    #[test]
    fn ip_dispatches_into_udp_with_real_codecs() {
        let mut r = wrex_core::Registry::empty();
        register(&mut r);
        for parent in [wrex_proto_ip::KIND, wrex_proto_ip6::KIND] {
            // Non-dispatching ports: 53/67/68 would chain into the
            // absent dns/dhcp (children — the stub-covered direction in
            // this crate's own dispatch tests); this test pins the
            // parent→udp edge only.
            let spec = wrex_core::spec::PacketSpec::new(
                vec![
                    wrex_core::spec::LayerSpec::new(parent),
                    udp_spec(&[("sport", "40000"), ("dport", "40001")]),
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
            let p = wrex_core::dissect::dissect(&r, &enc.bytes, parent);
            assert_eq!(
                p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
                vec![parent, KIND],
                "{parent} proto/next_header 17 must chain into the real udp codec"
            );
        }
    }

    /// The udp checksum covers the L4 message ONLY — the hopopts bytes
    /// are excluded from both the pseudo-header length and the fold
    /// (RFC 8200 §8.1 as the kernel and every real stack implement it;
    /// the HP3-b foreign-capture corpus caught the ext-inclusive T17a
    /// fold disagreeing with the kernel's own MLD frames by a
    /// constant). Craft → dissect through the real ipv6 + hopopts
    /// codecs, no anomalies, and the wire checksum matches the
    /// independent fold (the io::ndp lineage).
    #[test]
    fn checksum_covers_ext_chain() {
        let mut r = wrex_core::Registry::empty();
        register(&mut r);
        let mut hf = std::collections::BTreeMap::new();
        hf.insert(
            "options".into(),
            wrex_core::Value::Bytes(bytes::Bytes::from_static(&[
                0x01, 0x04, 0x00, 0x00, 0x00, 0x00,
            ])),
        );
        let spec = PacketSpec::new(
            vec![
                wrex_core::spec::LayerSpec::new(wrex_proto_ip6::KIND),
                wrex_core::spec::LayerSpec::with_fields(wrex_proto_ip6ext::KIND_HOPOPTS, hf),
                // Non-dispatching ports: 53 would chain into the absent
                // dns (children — stub-covered in this crate's own
                // dispatch tests); this test pins the ext seam.
                udp_spec(&[("sport", "40000"), ("dport", "40001")]),
            ],
            Some(wrex_core::Value::Bytes(bytes::Bytes::from_static(&[
                0xde, 0xad,
            ]))),
        );
        let enc = encode(
            &r,
            &spec,
            &wrex_core::encode::EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, wrex_proto_ip6::KIND);
        assert_eq!(
            p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec![wrex_proto_ip6::KIND, wrex_proto_ip6ext::KIND_HOPOPTS, "udp"],
            "the ext chain must dissect through the real codecs"
        );
        // The dissect-side verify (frame lookback) agrees: no anomaly.
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        // Independent fold over the L4 message ONLY (src/dst ::1, the
        // ipv6 defaults; len = the udp message length, proto 17): the
        // hopopts bytes are excluded — the kernel/interop reading.
        let l4 = &enc.bytes[40 + 8..]; // past ipv6(40) + hopopts(8)
        let mut acc = wrex_core::ChecksumAccumulator::new();
        acc.add_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        acc.add_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        acc.add_bytes(&(l4.len() as u32).to_be_bytes());
        acc.add_bytes(&[0, 17]);
        acc.add_bytes(&l4[..6]);
        acc.add_u16(0);
        acc.add_bytes(&l4[8..]);
        let ck = u16::from_be_bytes([enc.bytes[40 + 8 + 6], enc.bytes[40 + 8 + 7]]);
        assert_eq!(
            ck,
            acc.value(),
            "the wire checksum must match the independent L4-message fold"
        );
    }

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

    /// A minimal stand-in `dns` codec: dispatch *targets* stay
    /// registry strings (ADR 3 — udp⇄dns would cycle as Cargo deps),
    /// so dispatch-out tests still stub their children. Parents, by
    /// contrast, are real deps now; the dns crate's own register test
    /// covers dispatch-in with the real udp.
    mod dns_dispatch {
        use super::*;
        use std::collections::BTreeMap;

        static DNS_FIELDS: &[FieldSchema] = &[];
        static DNS_SCHEMA: LayerSchema = LayerSchema {
            kind: "dns",
            rank: 40,
            parents: &["udp"],
            doc: "dispatch stand-in",
            fields: DNS_FIELDS,
            records: &[],
        };

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
                    "stub".into(),
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

        /// Tranche 20b: mDNS (5353→5353, RFC 6762 — both ends) and
        /// LLMNR (5355 either side, RFC 4795 — dissect only) chain into
        /// dns; a 5353 sport alone must NOT kidnap an ephemeral reply.
        #[test]
        fn mdns_llmnr_ports_chain_into_dns() {
            for (sport, dport, want) in [
                (5353, 5353, true),
                (40000, 5355, true),
                (5355, 40000, true),
                (40000, 5353, false),
                (5353, 40000, false),
            ] {
                let spec =
                    udp_spec(&[("sport", &sport.to_string()), ("dport", &dport.to_string())]);
                let enc = encode(
                    &dns_registry(),
                    &PacketSpec::new(vec![spec], None),
                    &lo_opts(),
                )
                .unwrap();
                let p = wrex_core::dissect::dissect(&dns_registry(), &enc.bytes, "udp");
                let kinds: Vec<&str> = p.layers.iter().map(|l| l.kind).collect();
                if want {
                    assert_eq!(
                        kinds,
                        vec!["udp", "dns"],
                        "{sport}->{dport} must chain into the dns codec"
                    );
                } else {
                    assert_eq!(kinds, vec!["udp"], "{sport}->{dport} must stay terminal");
                }
            }
        }
    }

    /// A minimal stand-in `dhcp` codec (ADR 3: dispatch targets stay
    /// registry strings — udp⇄dhcp would cycle as deps; the tranche-7c
    /// mirror of the dns_dispatch module).
    mod dhcp_dispatch {
        use super::*;
        use std::collections::BTreeMap;

        static DHCP_FIELDS: &[FieldSchema] = &[];
        static DHCP_SCHEMA: LayerSchema = LayerSchema {
            kind: "dhcp",
            rank: 40,
            parents: &["udp"],
            doc: "dispatch stand-in",
            fields: DHCP_FIELDS,
            records: &[],
        };

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
                    "stub".into(),
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
