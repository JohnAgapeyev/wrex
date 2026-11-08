#![forbid(unsafe_code)]
//! wrex IEEE 802.11 dissect-only codec (tranche 23a, ADR-0004): the
//! management-frame view of a `tcpdump -i wlan0 -y IEEE802_11` capture
//! (LINKTYPE_IEEE802_11 105). Dissection walks the frame control word
//! (version/type/subtype + the DS/retry/order bit aggregates), duration,
//! addresses 1-3 (+4 under to_ds|from_ds) and the sequence word (seq/frag);
//! a MANAGEMENT body renders as the dissect-only `elt` record section —
//! one indexed record per information-element TLV (`elt.0.ssid`,
//! `elt.1.chan`, …) with the raw id/len/value wire truth beside the typed
//! subset. Control and data bodies stay payload (ADR-0004: monitor-mode
//! injection and radiotap are recorded won't-dos).
//!
//! Craft covers the fixed header (the frame control aggregate derives from
//! version/type/subtype/`flags` bit names); the element region rides the
//! payload verbatim (`--payload`), the deliberate typing boundary —
//! `elt.N.*` is dissect-only, the raw bytes are the wire truth.

use bytes::BufMut;

use wrex_core::dissect::LayerView;
use wrex_core::encode::EncodeCtx;
use wrex_core::error::DecodeError;
use wrex_core::schema::{FieldKind, FieldSchema, LayerSchema, Layout, RecordSchema};
use wrex_core::spec::LayerSpec;
use wrex_core::str_eq;
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

/// The kind string this codec implements (ADR 3).
pub const KIND: &str = "dot11";

/// 802.11 frame type names (`t` in the frame-control word).
pub const TYPES: [&str; 4] = ["mgmt", "ctrl", "data", "ext"];

/// Management subtype names (the common management set; other subtypes
/// render as bare numbers).
pub const MGMT_SUBTYPES: [(&str, u8); 15] = [
    ("assoc_req", 0),
    ("assoc_resp", 1),
    ("reassoc_req", 2),
    ("reassoc_resp", 3),
    ("probe_req", 4),
    ("probe_resp", 5),
    ("beacon", 8),
    ("atim", 9),
    ("disassoc", 10),
    ("auth", 11),
    ("deauth", 12),
    ("action", 13),
    ("action_no_ack", 14),
    ("reserved6", 6),
    ("reserved7", 7),
];

/// Frame-control byte 1 bit names, LSB first (to_ds..order).
pub const FC1_FLAGS: [&str; 8] = [
    "to_ds",
    "from_ds",
    "more_frag",
    "retry",
    "pwr_mgt",
    "more_data",
    "protected",
    "order",
];

static FIELDS: [FieldSchema; 10] = [
    d(
        "version",
        FieldKind::U8,
        "protocol version (2 bits; 0)",
        Value::Int(0),
    ),
    d(
        "type",
        FieldKind::Str,
        "frame type: mgmt|ctrl|data|ext or a bare 0-3 number",
        Value::Str(std::borrow::Cow::Borrowed("mgmt")),
    ),
    d(
        "subtype",
        FieldKind::U8,
        "frame subtype (4 bits; the management names: 8 = beacon, 4 = probe_req, …)",
        Value::Int(0),
    ),
    d(
        "flags",
        FieldKind::FlagSet,
        "frame-control byte 1 bit aggregate: to_ds,from_ds,more_frag,retry,pwr_mgt,more_data,protected,order",
        Value::Int(0),
    ),
    d(
        "duration",
        FieldKind::U16,
        "duration/ID (µs, or the PS-Poll AID)",
        Value::Int(0),
    ),
    d(
        "addr1",
        FieldKind::Mac,
        "address 1 (receiver)",
        Value::Mac([0; 6]),
    ),
    d(
        "addr2",
        FieldKind::Mac,
        "address 2 (transmitter)",
        Value::Mac([0; 6]),
    ),
    d(
        "addr3",
        FieldKind::Mac,
        "address 3 (bssid/filter)",
        Value::Mac([0; 6]),
    ),
    d(
        "seq",
        FieldKind::U16,
        "sequence control: 12-bit sequence number + 4-bit fragment (see frag)",
        Value::Int(0),
    ),
    d(
        "frag",
        FieldKind::U8,
        "fragment number (high 4 bits of the sequence word)",
        Value::Int(0),
    ),
];

static ELT_FIELDS: [FieldSchema; 5] = [
    d(
        "id",
        FieldKind::U8,
        "element id (0 = ssid, 1 = rates, 3 = channel/ds)",
        Value::Int(0),
    ),
    d(
        "len",
        FieldKind::U8,
        "element length (autofill: the value region)",
        Value::Int(0),
    ),
    d(
        "ssid",
        FieldKind::Str,
        "typed view of a 0-ssid element (the broadcast empty ssid is empty)",
        Value::Str(std::borrow::Cow::Borrowed("")),
    ),
    d(
        "chan",
        FieldKind::U8,
        "typed view of a 3-ds-channel element (the first value byte)",
        Value::Int(0),
    ),
    d(
        "value",
        FieldKind::Bytes,
        "raw element value bytes (the wire truth)",
        Value::Bytes(bytes::Bytes::new()),
    ),
];

static RECORDS: [RecordSchema; 1] = [RecordSchema {
    name: "elt",
    fields: &ELT_FIELDS,
    settable: false,
    max: None,
    doc: "management information-element TLVs (dissect-only; indexed paths elt.0.*, …). Control/data bodies stay payload.",
}];

pub static SCHEMA: LayerSchema = LayerSchema {
    kind: KIND,
    rank: 10,
    parents: &[],
    doc: "IEEE 802.11 MAC frame (LINKTYPE_IEEE802_11, no radiotap): frame control (version 2 bits, type, subtype, the to_ds..order flag aggregate), duration, addresses 1-3 (+ address 4 under to_ds+from_ds), sequence (12-bit seq + 4-bit frag). A management body dissects into the elt record section (elt.0.ssid, elt.0.chan, …); control/data bodies stay payload. Management element crafting rides the payload verbatim (dissect-only typing). Root layer (rank 10).",
    fields: &FIELDS,
    records: &RECORDS,
};

pub struct Dot11Codec;
pub static CODEC: Dot11Codec = Dot11Codec;

/// ADR 3 registration closure (self only — dot11 has no parents).
pub fn register(r: &mut wrex_core::Registry) {
    if r.get(KIND).is_none() {
        r.register(&CODEC);
    }
}

/// Fixed header: FC(2) + duration(2) + addr1..addr3(18) + seq(2) = 24,
/// + addr4(6) under to_ds|from_ds.
const HEADER_MIN: usize = 24;
const ADDR4_AT: usize = 24;

fn type_name(v: u8) -> Value {
    if (v as usize) < TYPES.len() {
        Value::Str(TYPES[v as usize].into())
    } else {
        Value::Int(v as u128)
    }
}

fn type_num(v: &Value) -> u8 {
    match v {
        Value::Str(s) => {
            for (i, n) in TYPES.iter().enumerate() {
                if str_eq(s, n) {
                    return i as u8;
                }
            }
            s.parse().unwrap_or(0)
        }
        Value::Int(n) => *n as u8,
        _ => 0,
    }
}

fn subtype_value(v: u8, ty: u8) -> Value {
    if ty == 0 {
        for (name, num) in MGMT_SUBTYPES.iter() {
            if *num == v {
                return Value::Str((*name).into());
            }
        }
    }
    Value::Int(v as u128)
}

impl Codec for Dot11Codec {
    fn schema(&self) -> &'static LayerSchema {
        &SCHEMA
    }

    fn header_len(&self, spec: &LayerSpec) -> Result<usize, EncodeError> {
        let flags = match spec.fields.get("flags") {
            Some(Value::Int(v)) => *v as u8,
            Some(Value::List(items)) => {
                let mut f = 0u8;
                for it in items {
                    if let Value::Str(s) = it
                        && let Some(p) = FC1_FLAGS.iter().position(|n| str_eq(s, n))
                    {
                        f |= 1 << p;
                    }
                }
                f
            }
            _ => 0,
        };
        if flags & 0b11 == 0b11 {
            Ok(HEADER_MIN + 6)
        } else {
            Ok(HEADER_MIN)
        }
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let version = match spec.fields.get("version") {
            Some(Value::Int(v)) => *v as u8,
            _ => 0,
        };
        let ty = spec.fields.get("type").map(type_num).unwrap_or(0);
        let subtype = match spec.fields.get("subtype") {
            Some(Value::Str(s)) => s.parse().unwrap_or(0),
            Some(Value::Int(v)) => *v as u8,
            _ => 0,
        };
        let flags = match spec.fields.get("flags") {
            Some(Value::Int(v)) => *v as u8,
            Some(Value::List(items)) => {
                let mut f = 0u8;
                for it in items {
                    if let Value::Str(s) = it
                        && let Some(p) = FC1_FLAGS.iter().position(|n| str_eq(s, n))
                    {
                        f |= 1 << p;
                    }
                }
                f
            }
            _ => 0,
        };
        let fc0 = (version & 3) | ((ty & 3) << 2) | (subtype << 4);
        ctx.buf.put_u8(fc0);
        ctx.buf.put_u8(flags);
        let duration = match spec.fields.get("duration") {
            Some(Value::Int(v)) => *v as u16,
            _ => 0,
        };
        ctx.buf.put_u16(duration);
        for (name, def) in [("addr1", [0xff; 6]), ("addr2", [0; 6]), ("addr3", [0; 6])] {
            let m = match spec.fields.get(name) {
                Some(Value::Mac(m)) => *m,
                _ => {
                    if af {
                        def
                    } else {
                        [0; 6]
                    }
                }
            };
            ctx.buf.extend_from_slice(&m);
        }
        let seq = match spec.fields.get("seq") {
            Some(Value::Int(v)) => *v as u16,
            _ => 0,
        };
        // The sequence word packs frag (high 4) + seq (low 12) — both
        // craftable, one wire u16.
        let frag = match spec.fields.get("frag") {
            Some(Value::Int(v)) => (*v as u16) << 12,
            _ => 0,
        };
        ctx.buf.put_u16(frag | (seq & 0x0fff));
        if flags & 0b11 == 0b11 {
            let addr4 = match spec.fields.get("addr4") {
                Some(Value::Mac(m)) => *m,
                _ => [0; 6],
            };
            ctx.buf.extend_from_slice(&addr4);
        }
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.is_empty() {
            return ReadOutcome::Empty;
        }
        if bytes.len() < HEADER_MIN {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: KIND,
                    need: HEADER_MIN,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let fc0 = bytes[0];
        let flags = bytes[1];
        let version = fc0 & 3;
        let ty = (fc0 >> 2) & 3;
        let subtype = fc0 >> 4;
        let duration = u16::from_be_bytes([bytes[2], bytes[3]]);
        let mut addr = [[0u8; 6]; 4];
        // addr1..3 live in the 24-byte common header; addr4 only under
        // to_ds+from_ds (checked below before its copy).
        for (i, a) in addr.iter_mut().take(3).enumerate() {
            a.copy_from_slice(&bytes[4 + i * 6..4 + (i + 1) * 6]);
        }
        let seqw = u16::from_be_bytes([bytes[22], bytes[23]]);
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("version".into(), Value::Int(version as u128));
        fields.insert("type".into(), type_name(ty));
        fields.insert("subtype".into(), subtype_value(subtype, ty));
        let set_names: Vec<Value> = (0..8)
            .filter(|b| flags & (1 << b) != 0)
            .map(|b| Value::Str(FC1_FLAGS[b as usize].into()))
            .collect();
        fields.insert("flags".into(), Value::List(set_names));
        fields.insert("duration".into(), Value::Int(duration as u128));
        fields.insert("addr1".into(), Value::Mac(addr[0]));
        fields.insert("addr2".into(), Value::Mac(addr[1]));
        fields.insert("addr3".into(), Value::Mac(addr[2]));
        fields.insert("seq".into(), Value::Int((seqw & 0x0fff) as u128));
        fields.insert("frag".into(), Value::Int((seqw >> 12) as u128));
        let mut span_end = HEADER_MIN;
        if flags & 0b11 == 0b11 {
            if bytes.len() < HEADER_MIN + 6 {
                ctx.anomalies.push(wrex_core::dissect::Anomaly::new(
                    format!("{KIND}.addr4"),
                    "truncated address 4 (to_ds+from_ds set)",
                ));
            } else {
                addr[3].copy_from_slice(&bytes[ADDR4_AT..ADDR4_AT + 6]);
                fields.insert("addr4".into(), Value::Mac(addr[3]));
                span_end = HEADER_MIN + 6;
            }
        }
        if ty == 0 {
            // Management: the body is the information-element region —
            // dissect-only `elt` records (id/len/value + typed ssid/chan
            // views). A malformed element stops the walk never-fatal;
            // the remainder stays payload.
            let body = &bytes[span_end..];
            let mut off = 0usize;
            let mut idx = 0usize;
            while off + 2 <= body.len() {
                let id = body[off];
                let len = body[off + 1] as usize;
                let vstart = off + 2;
                if vstart + len > body.len() {
                    ctx.anomalies.push(wrex_core::dissect::Anomaly::new(
                        format!("{KIND}.elt.{idx}"),
                        "element length overruns the frame (trailing bytes stay payload)",
                    ));
                    break;
                }
                let value = &body[vstart..vstart + len];
                fields.insert(format!("elt.{idx}.id").into(), Value::Int(id as u128));
                fields.insert(format!("elt.{idx}.len").into(), Value::Int(len as u128));
                fields.insert(
                    format!("elt.{idx}.value").into(),
                    Value::Bytes(bytes::Bytes::copy_from_slice(value)),
                );
                if id == 0 {
                    fields.insert(
                        format!("elt.{idx}.ssid").into(),
                        Value::Str(String::from_utf8_lossy(value).into_owned().into()),
                    );
                }
                if id == 3 && !value.is_empty() {
                    fields.insert(
                        format!("elt.{idx}.chan").into(),
                        Value::Int(value[0] as u128),
                    );
                }
                off = vstart + len;
                idx += 1;
            }
            // A clean walk consumes the whole body into the layer.
            if off == body.len() {
                span_end += off;
            } else if off + 2 > body.len() && !body.is_empty() && off < body.len() {
                // dangling tail (<2 bytes): payload
            }
        }
        let view = LayerView {
            kind: KIND,
            span: ctx.offset..ctx.offset + span_end,
            field_spans: Default::default(),
            fields,
        };
        ReadOutcome::Layer(view, Some(Next::Payload))
    }

    /// Tranche 23a fixed layouts: the frame-control bit windows (byte 0
    /// and byte 1), duration, addresses and the sequence word.
    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        &[
            (
                "version",
                Layout::Bits {
                    at: 0,
                    shift: 0,
                    width: 2,
                },
            ),
            (
                "type",
                Layout::Bits {
                    at: 0,
                    shift: 2,
                    width: 2,
                },
            ),
            (
                "subtype",
                Layout::Bits {
                    at: 0,
                    shift: 4,
                    width: 4,
                },
            ),
            (
                "flags",
                Layout::Bits {
                    at: 1,
                    shift: 0,
                    width: 8,
                },
            ),
            ("duration", Layout::Bytes { at: 2, len: 2 }),
            ("addr1", Layout::Bytes { at: 4, len: 6 }),
            ("addr2", Layout::Bytes { at: 10, len: 6 }),
            ("addr3", Layout::Bytes { at: 16, len: 6 }),
            (
                "seq",
                Layout::Bits {
                    at: 22,
                    shift: 0,
                    width: 12,
                },
            ),
            (
                "frag",
                Layout::Bits {
                    at: 22,
                    shift: 12,
                    width: 4,
                },
            ),
        ]
    }
}

#[cfg(feature = "test-util")]
pub mod strategy {
    //! proptest strategies for `LayerSpec` (behind `test-util`).
    use proptest::prelude::*;
    use wrex_core::spec::LayerSpec;
    use wrex_core::value::Value;

    /// Valid dot11 specs: any version/type/subtype/flags, arbitrary
    /// addresses, duration and seq; DS bits pick the addr4 shape.
    pub fn strategy() -> BoxedStrategy<LayerSpec> {
        let flags = proptest::sample::select(vec![
            Value::Int(0),
            Value::Int(0b0000_0001),
            Value::Int(0b0000_0010),
            Value::Int(0b0000_0011),
            Value::Int(0b0100_0100),
        ]);
        (
            0u8..4,
            proptest::sample::select(vec![
                Value::Str(std::borrow::Cow::Borrowed("mgmt")),
                Value::Str("ctrl".into()),
                Value::Str("data".into()),
                Value::Int(3),
            ]),
            0u8..16,
            flags,
            any::<u16>(),
            proptest::array::uniform6(any::<u8>()),
            proptest::array::uniform6(any::<u8>()),
            proptest::array::uniform6(any::<u8>()),
            0u16..4096,
            0u8..16,
        )
            .prop_map(
                |(version, ty, subtype, flags, duration, a1, a2, a3, seq, frag)| {
                    let mut fields = std::collections::BTreeMap::new();
                    fields.insert("version".into(), Value::Int(version as u128));
                    fields.insert("type".into(), ty);
                    fields.insert("subtype".into(), Value::Int(subtype as u128));
                    fields.insert("flags".into(), flags);
                    fields.insert("duration".into(), Value::Int(duration as u128));
                    fields.insert("addr1".into(), Value::Mac(a1));
                    fields.insert("addr2".into(), Value::Mac(a2));
                    fields.insert("addr3".into(), Value::Mac(a3));
                    fields.insert("seq".into(), Value::Int(seq as u128));
                    fields.insert("frag".into(), Value::Int(frag.into()));
                    LayerSpec::with_fields("dot11", fields)
                },
            )
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wrex_core::Registry;
    use wrex_core::encode::{EncodeOpts, encode};
    use wrex_core::spec::PacketSpec;

    #[test]
    fn schema_field_names_unique() {
        assert!(wrex_core::schema::field_names_unique(SCHEMA.fields));
        for r in SCHEMA.records {
            assert!(wrex_core::schema::field_names_unique(r.fields));
        }
    }

    fn spec(fields: &[(&str, Value)]) -> LayerSpec {
        let mut map = std::collections::BTreeMap::new();
        for (k, v) in fields {
            map.insert((*k).to_string().into(), v.clone());
        }
        LayerSpec::with_fields(KIND, map)
    }

    /// A beacon header + SSID element: craft → dissect round-trip with
    /// the element TLVs rendering typed.
    #[test]
    fn beacon_roundtrip_with_ssid() {
        let reg = {
            let mut r = Registry::empty();
            register(&mut r);
            r
        };
        let s = spec(&[
            ("type", Value::Str(std::borrow::Cow::Borrowed("mgmt"))),
            ("subtype", Value::Int(8)),
            ("duration", Value::Int(0)),
            ("addr1", Value::Mac([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])),
            ("addr2", Value::Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
            ("addr3", Value::Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
            ("seq", Value::Int(7)),
        ]);
        // payload: SSID "wrex" (0x04 len) + channel 6 element
        let payload = [0x00, 0x04, b'w', b'r', b'e', b'x', 0x03, 0x01, 0x06];
        let ps = PacketSpec::new(vec![s], Some(Value::Bytes(payload.to_vec().into())));
        let enc = encode(&reg, &ps, &EncodeOpts::default()).unwrap();
        assert_eq!(enc.bytes.len(), 24 + payload.len());
        assert_eq!(enc.bytes[0], 0x80); // subtype 8 << 4 | type 0 | ver 0
        let p = wrex_core::dissect::dissect(&reg, &enc.bytes, KIND);
        let f = &p.layers[0].fields;
        assert_eq!(
            f.get("type"),
            Some(&Value::Str(std::borrow::Cow::Borrowed("mgmt")))
        );
        assert_eq!(f.get("subtype"), Some(&Value::Str("beacon".into())));
        assert_eq!(f.get("elt.0.ssid"), Some(&Value::Str("wrex".into())));
        assert_eq!(f.get("elt.1.chan"), Some(&Value::Int(6)));
        assert_eq!(f.get("elt.1.id"), Some(&Value::Int(3)));
        // clean walk: the elements are inside the layer span
        assert_eq!(p.layers[0].span, 0..33);
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
    }

    /// to_ds+from_ds grows the header by addr4; a truncated addr4 is a
    /// never-fatal anomaly.
    #[test]
    fn addr4_shape_and_truncation() {
        let mut ctx = wrex_core::dissect::DecodeCtx::new(0);
        let mut frame = vec![0u8; 24];
        frame[1] = 0b0000_0011; // to_ds | from_ds
        frame[22] = 0x12;
        frame[23] = 0x34;
        match CODEC.read(&frame, &mut ctx) {
            ReadOutcome::Layer(view, _) => {
                assert_eq!(view.span.end, 24); // addr4 did not fit
                assert!(!view.fields.contains_key("addr4"));
            }
            other => panic!("expected layer, got {other:?}"),
        }
        assert!(
            ctx.anomalies.iter().any(|a| a.path.contains("addr4")),
            "{:?}",
            ctx.anomalies
        );
        frame.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        let mut ctx = wrex_core::dissect::DecodeCtx::new(0);
        match CODEC.read(&frame, &mut ctx) {
            ReadOutcome::Layer(view, _) => {
                assert_eq!(view.span.end, 30);
                assert_eq!(
                    view.fields.get("addr4"),
                    Some(&Value::Mac([1, 2, 3, 4, 5, 6]))
                );
            }
            other => panic!("expected layer, got {other:?}"),
        }
    }

    /// An overrunning element stops the walk never-fatal; the trailing
    /// bytes stay payload.
    #[test]
    fn overrun_element_stops_never_fatal() {
        let mut frame = vec![0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00];
        frame.extend_from_slice(&[0; 16]); // pad to 24
        frame.extend_from_slice(&[0x00, 0x40, 0x00]); // ssid id 0, len 64, overruns
        let mut ctx = wrex_core::dissect::DecodeCtx::new(0);
        match CODEC.read(&frame, &mut ctx) {
            ReadOutcome::Layer(view, Some(Next::Payload)) => {
                assert_eq!(view.span.end, 24);
                assert!(!view.fields.contains_key("elt.0.ssid"));
            }
            other => panic!("expected layer, got {other:?}"),
        }
        assert!(
            ctx.anomalies.iter().any(|a| a.path.contains("elt.0")),
            "{:?}",
            ctx.anomalies
        );
    }

    #[test]
    fn truncation_and_empty() {
        let mut ctx = wrex_core::dissect::DecodeCtx::new(0);
        assert!(matches!(
            CODEC.read(&[0u8; 23], &mut ctx),
            ReadOutcome::Anomaly(_, _)
        ));
        let mut ctx = wrex_core::dissect::DecodeCtx::new(0);
        assert!(matches!(CODEC.read(&[], &mut ctx), ReadOutcome::Empty));
    }

    /// Control/data frames keep the body as payload (no elt records).
    #[test]
    fn data_body_stays_payload() {
        let mut frame = vec![0u8; 24];
        frame[0] = 0x20; // type 2 (data)
        frame.extend_from_slice(&[0xaa, 0xbb]);
        let mut ctx = wrex_core::dissect::DecodeCtx::new(0);
        match CODEC.read(&frame, &mut ctx) {
            ReadOutcome::Layer(view, Some(Next::Payload)) => {
                assert_eq!(view.span.end, 24);
                assert!(view.fields.keys().all(|k| !k.contains("elt")));
            }
            other => panic!("expected layer, got {other:?}"),
        }
    }
}
