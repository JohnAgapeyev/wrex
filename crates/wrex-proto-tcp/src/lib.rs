#![forbid(unsafe_code)]
//! wrex TCP codec (sport/dport/seq/ack/data_offset/flags/window/checksum/
//! urgent/options; rank 30, parent ipv4). Flags expose the aggregate
//! (`tcp.flags`) and per-bit subpaths (`tcp.flags.syn`).

mod options;

use std::sync::LazyLock;

use bytes::{BufMut, Bytes};

use wrex_core::dissect::LayerView;
use wrex_core::encode::{EncodeCtx, Patch, flagset_or_default, int_or_default};
use wrex_core::error::DecodeError;
use wrex_core::schema::{FieldKind, FieldSchema, LayerSchema};
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;
use wrex_core::{Anomaly, Codec, DecodeCtx, EncodeError, Next, ReadOutcome};

static FLAGS: &[&str] = &["cwr", "ece", "urg", "ack", "psh", "rst", "syn", "fin"];

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
        d("seq", FieldKind::U32, "sequence number", Value::Int(0)),
        d(
            "ack",
            FieldKind::U32,
            "acknowledgment number",
            Value::Int(0),
        ),
        d(
            "data_off",
            FieldKind::U8,
            "data offset in 32-bit words (autofill: derived)",
            Value::Int(0),
        ),
        FieldSchema {
            name: "flags",
            kind: FieldKind::FlagSet,
            bit_names: FLAGS,
            default: Value::Int(0),
            required: false,
            doc: "flag aggregate [cwr,ece,urg,ack,psh,rst,syn,fin]; subpaths flags.<bit>",
        },
        d(
            "window",
            FieldKind::U16,
            "window (autofill: 64240)",
            Value::Int(64240),
        ),
        d(
            "checksum",
            FieldKind::U16,
            "checksum over pseudo-header+segment (autofill: computed)",
            Value::Int(0),
        ),
        d("urgent", FieldKind::U16, "urgent pointer", Value::Int(0)),
        FieldSchema {
            name: "options",
            kind: FieldKind::Bytes,
            bit_names: &[],
            default: Value::Bytes(Bytes::new()),
            required: false,
            doc: "options: eol,nop,mss:1460,ws:7,sackok,sack:L,R,…, or hex:…",
        },
    ]
});

pub static SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: "tcp",
    rank: 30,
    parents: &["ipv4"],
    fields: FIELDS.as_slice(),
});

/// TCP codec unit. Register as `&wrex_proto_tcp::CODEC`.
pub struct TcpCodec;

pub static CODEC: TcpCodec = TcpCodec;

/// Options bytes for a spec (Str list grammar or raw Bytes), zero-padded.
fn options_region(spec: &LayerSpec) -> Result<Vec<u8>, EncodeError> {
    let raw = match spec.fields.get("options") {
        Some(Value::Str(s)) => options::parse_options(s)?,
        Some(Value::Bytes(b)) => b.to_vec(),
        _ => Vec::new(),
    };
    let mut raw = raw;
    raw.extend(std::iter::repeat_n(0u8, options::pad_len(raw.len())));
    Ok(raw)
}

impl Codec for TcpCodec {
    fn schema(&self) -> &'static LayerSchema {
        &SCHEMA
    }

    fn header_len(&self, spec: &LayerSpec) -> Result<usize, EncodeError> {
        Ok(20 + options_region(spec)?.len())
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let start = ctx.buf.len();
        let opts = options_region(spec)?;
        ctx.buf.put_u16(int_or_default(spec, &FIELDS[0], af) as u16);
        ctx.buf.put_u16(int_or_default(spec, &FIELDS[1], af) as u16);
        ctx.buf.put_u32(int_or_default(spec, &FIELDS[2], af) as u32);
        ctx.buf.put_u32(int_or_default(spec, &FIELDS[3], af) as u32);
        let at_doff = ctx.buf.len();
        let doff_explicit = spec.fields.contains_key("data_off");
        let doff = if doff_explicit {
            (int_or_default(spec, &FIELDS[4], af) as u8 & 0x0f) << 4
        } else {
            ((5 + opts.len() / 4) as u8) << 4
        };
        ctx.buf.put_u8(doff);
        ctx.defer(Patch::MinByte {
            at: at_doff,
            min: 0x50,
            path: "tcp.data_off",
        });
        let flags = flagset_or_default(spec, &FIELDS[5], af) as u8;
        ctx.buf.put_u8(flags);
        ctx.buf.put_u16(int_or_default(spec, &FIELDS[6], af) as u16); // window
        let at_ck = ctx.buf.len();
        let ck_explicit = spec.fields.contains_key("checksum");
        if let Some(Value::Int(v)) = spec.fields.get("checksum") {
            ctx.buf.put_u16(*v as u16);
        } else {
            ctx.buf.put_u16(0); // checksum placeholder
        }
        ctx.buf.put_u16(int_or_default(spec, &FIELDS[8], af) as u16); // urgent
        ctx.buf.extend_from_slice(&opts);
        let pseudo = ctx.facts.net.map(|n| (n.src, n.dst, 6u8));
        ctx.defer(Patch::Checksum {
            at: at_ck,
            start,
            end: None,
            pseudo,
            explicit: ck_explicit,
            path: "tcp.checksum",
        });
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.is_empty() {
            return ReadOutcome::Empty;
        }
        if bytes.len() < 20 {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "tcp",
                    need: 20,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let doff = bytes[12] >> 4;
        if doff < 5 {
            ctx.anomalies.push(Anomaly::new("tcp.data_off", "below 5"));
            return ReadOutcome::Anomaly(
                DecodeError::BadField {
                    path: "tcp.data_off".into(),
                    reason: format!("data offset {doff} below 5"),
                },
                Next::Payload,
            );
        }
        let hlen = doff as usize * 4;
        if bytes.len() < hlen {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "tcp",
                    need: hlen,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let sport = u16::from_be_bytes([bytes[0], bytes[1]]);
        let dport = u16::from_be_bytes([bytes[2], bytes[3]]);
        let seq = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let ack = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let flags_byte = bytes[13];
        let window = u16::from_be_bytes([bytes[14], bytes[15]]);
        let found_ck = u16::from_be_bytes([bytes[16], bytes[17]]);
        let urgent = u16::from_be_bytes([bytes[18], bytes[19]]);

        // Checksum verify (non-fatal): pseudo-header + segment, ck zeroed.
        if let Some(net) = ctx.facts.net {
            let mut acc = wrex_core::ChecksumAccumulator::new();
            acc.add_ipv4(net.src);
            acc.add_ipv4(net.dst);
            acc.add_u16(u16::from_be_bytes([0, net.proto]));
            acc.add_u16(bytes.len() as u16);
            acc.add_bytes(&bytes[..16]);
            acc.add_u16(0);
            acc.add_bytes(&bytes[18..]);
            let computed = acc.value();
            if found_ck != computed {
                ctx.anomalies.push(Anomaly::new(
                    "tcp.checksum",
                    format!("mismatch (computed 0x{computed:04x}, found 0x{found_ck:04x})"),
                ));
            }
        }

        // Flag names for the aggregate (MSB-first bit_names).
        let mut names: Vec<Value> = Vec::new();
        for (i, name) in FLAGS.iter().enumerate() {
            if flags_byte & (1 << (7 - i)) != 0 {
                names.push(Value::Str((*name).into()));
            }
        }

        let mut fields = std::collections::BTreeMap::new();
        fields.insert("sport".into(), Value::Int(sport as u128));
        fields.insert("dport".into(), Value::Int(dport as u128));
        fields.insert("seq".into(), Value::Int(seq as u128));
        fields.insert("ack".into(), Value::Int(ack as u128));
        fields.insert("data_off".into(), Value::Int(doff as u128));
        fields.insert("flags".into(), Value::List(names));
        fields.insert("window".into(), Value::Int(window as u128));
        fields.insert("checksum".into(), Value::Int(found_ck as u128));
        fields.insert("urgent".into(), Value::Int(urgent as u128));
        fields.insert(
            "options".into(),
            Value::Bytes(Bytes::copy_from_slice(&bytes[20..hlen])),
        );
        let view = LayerView {
            kind: "tcp",
            span: ctx.offset..ctx.offset + hlen,
            fields,
        };
        // TCP is terminal (the payload follows).
        ReadOutcome::Layer(view, Some(Next::Payload))
    }
}

#[cfg(feature = "test-util")]
pub mod strategy {
    //! proptest strategies for `LayerSpec` (behind `test-util`).
    use proptest::prelude::*;
    use wrex_core::spec::LayerSpec;
    use wrex_core::value::Value;

    /// Valid tcp specs: any numeric fields, any flag mask, valid options.
    pub fn strategy() -> BoxedStrategy<LayerSpec> {
        let flags = any::<u8>().prop_map(|v| Value::Int(v as u128));
        let opts = proptest::option::of(proptest::sample::select(vec![
            "eol".to_string(),
            "nop,nop".to_string(),
            "mss:1460".to_string(),
            "ws:7".to_string(),
            "sackok".to_string(),
            "sack:1,2".to_string(),
            "hex:01020304".to_string(),
        ]));
        (
            any::<u16>(),
            any::<u16>(),
            any::<u32>(),
            any::<u32>(),
            flags,
            any::<u16>(),
            any::<u16>(),
            opts,
        )
            .prop_map(|(sport, dport, seq, ack, flags, window, urgent, opts)| {
                let mut fields = std::collections::BTreeMap::new();
                fields.insert("sport".to_string(), Value::Int(sport as u128));
                fields.insert("dport".to_string(), Value::Int(dport as u128));
                fields.insert("seq".to_string(), Value::Int(seq as u128));
                fields.insert("ack".to_string(), Value::Int(ack as u128));
                fields.insert("flags".to_string(), flags);
                fields.insert("window".to_string(), Value::Int(window as u128));
                fields.insert("urgent".to_string(), Value::Int(urgent as u128));
                if let Some(o) = opts {
                    fields.insert("options".to_string(), Value::Str(o));
                }
                LayerSpec::with_fields("tcp", fields)
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

    fn tcp_spec(fields: &[(&str, &str)]) -> LayerSpec {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            if *k == "options" {
                map.insert(k.to_string(), Value::Str((*v).to_string()));
                continue;
            }
            let value = match SCHEMA.resolve(k) {
                Some(wrex_core::ResolvedField::Field(fs)) => parse_value(fs, v).unwrap(),
                Some(wrex_core::ResolvedField::FlagBit { .. }) => {
                    wrex_core::parse_bool(v).map(Value::Bool).unwrap()
                }
                None => panic!("no field {k}"),
            };
            map.insert(k.to_string(), value);
        }
        LayerSpec::with_fields("tcp", map)
    }

    fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&CODEC);
        r
    }

    fn lo_opts() -> EncodeOpts {
        EncodeOpts {
            autofill: true,
            strict: false,
            facts: Facts {
                net: Some(NetFacts {
                    src: "127.0.0.1".parse().unwrap(),
                    dst: "127.0.0.1".parse().unwrap(),
                    proto: 6,
                }),
                ..Default::default()
            },
        }
    }

    #[test]
    fn header_autofill_defaults() {
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![tcp_spec(&[("flags", "syn")])], None),
            &lo_opts(),
        )
        .unwrap();
        assert_eq!(enc.bytes.len(), 20);
        assert_eq!(enc.bytes[12], 5 << 4); // data_off
        assert_eq!(enc.bytes[13], 0x02); // syn = bit 1
        assert_eq!(u16::from_be_bytes([enc.bytes[14], enc.bytes[15]]), 64240);
    }

    #[test]
    fn per_bit_flag_subpaths() {
        // aggregate + per-bit subpath merge
        let spec = tcp_spec(&[
            ("flags", "syn"),
            ("flags.ack", "true"),
            ("flags.syn", "false"),
        ]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        // syn set then cleared, ack set: 0x10
        assert_eq!(enc.bytes[13], 0x10);
        let spec2 = tcp_spec(&[("flags", "0")]);
        let enc2 = encode(&registry(), &PacketSpec::new(vec![spec2], None), &lo_opts()).unwrap();
        assert_eq!(enc2.bytes[13], 0);
    }

    #[test]
    fn options_roundtrip() {
        let spec = tcp_spec(&[("options", "nop,mss:1460,ws:7,sackok,sack:1,2,nop")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        // nop(1) + mss(4) + ws(3→padded to 4) + sackok(2→padded 4) + sack(2+8=10→pad 12?) ...
        // verify by dissection instead of hardcoding: options hex region round-trips
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "tcp");
        match p.layers[0].fields.get("options") {
            Some(Value::Bytes(b)) => assert_eq!(&b[..], &enc.bytes[20..]),
            other => panic!("options: {other:?}"),
        }
        assert_eq!(
            p.layers[0].fields.get("data_off"),
            Some(&Value::Int((enc.bytes.len() / 4) as u128))
        );
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
    }

    #[test]
    fn checksum_covers_payload() {
        let spec = tcp_spec(&[("sport", "1"), ("dport", "2"), ("flags", "syn,ack")]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(
                vec![spec],
                Some(Value::Bytes(bytes::Bytes::from_static(&[0xaa, 0xbb]))),
            ),
            &lo_opts(),
        )
        .unwrap();
        let mut acc = wrex_core::ChecksumAccumulator::new();
        acc.add_ipv4("127.0.0.1".parse().unwrap());
        acc.add_ipv4("127.0.0.1".parse().unwrap());
        acc.add_u16(u16::from_be_bytes([0, 6]));
        acc.add_u16(22);
        acc.add_bytes(&enc.bytes[..16]);
        acc.add_u16(0);
        acc.add_bytes(&enc.bytes[18..]);
        assert_eq!(
            u16::from_be_bytes([enc.bytes[16], enc.bytes[17]]),
            acc.value()
        );
    }

    #[test]
    fn read_flags_names_and_checksum_anomaly() {
        let spec = tcp_spec(&[("flags", "syn,ack"), ("sport", "4444")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "tcp");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        match p.layers[0].fields.get("flags") {
            Some(Value::List(names)) => {
                let got: Vec<&str> = names
                    .iter()
                    .filter_map(|v| match v {
                        Value::Str(s) => Some(s.as_str()),
                        _ => None,
                    })
                    .collect();
                assert_eq!(got, vec!["ack", "syn"]); // sorted
            }
            other => panic!("flags: {other:?}"),
        }
        // corrupt checksum → anomaly via read (verify needs NetFacts)
        let mut bad = enc.bytes.to_vec();
        bad[16] ^= 0xff;
        let mut ctx = DecodeCtx::new(0);
        ctx.facts.net = lo_opts().facts.net;
        let _ = CODEC.read(&bad, &mut ctx);
        assert!(
            ctx.anomalies.iter().any(|a| a.path == "tcp.checksum"),
            "{:?}",
            ctx.anomalies
        );
    }

    #[test]
    fn bad_data_offset_and_truncation() {
        let mut ctx = DecodeCtx::new(0);
        assert!(matches!(
            CODEC.read(&[0u8; 19], &mut ctx),
            ReadOutcome::Anomaly(DecodeError::Truncated { kind: "tcp", .. }, _)
        ));
        // data_off=4 → BadField
        let mut hdr = vec![0u8; 20];
        hdr[12] = 0x40;
        let mut ctx = DecodeCtx::new(0);
        match CODEC.read(&hdr, &mut ctx) {
            ReadOutcome::Anomaly(DecodeError::BadField { path, .. }, _) => {
                assert_eq!(path, "tcp.data_off");
            }
            other => panic!("expected badfield, got {other:?}"),
        }
    }
}
