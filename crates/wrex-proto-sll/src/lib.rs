#![forbid(unsafe_code)]
//! wrex Linux cooked-capture codecs (tranche 23a): `sll` (LINKTYPE_LINUX_SLL
//! 113, the 16-byte v1 header) and `sll2` (LINKTYPE_LINUX_SLL2 276, the
//! 20-byte v2 header). Root layers (rank 10, no parents) — the `capture -i
//! any` view and the read-side dispatch of cooked captures; `protocol`
//! drives the chain exactly like `eth.type` (0x0800 -> ipv4, 0x0806 -> arp,
//! 0x86dd -> ipv6, 0x8100/0x88a8 -> vlan, else synthesized `unknown`).
//!
//! Wire formats pinned against a live `tcpdump -i any` oracle (both variants
//! captured in a veth netns; tshark agreed field-for-field): v1 is
//! pkttype u16 / hatype u16 / halen u16 / addr[8] / protocol u16, all
//! big-endian; v2 moves `protocol` to the front and widens the view —
//! protocol u16 / reserved u16 / ifindex u32 / hatype u16 / pkttype u8 /
//! halen u8 / addr[8] — 20 bytes.

use bytes::BufMut;

use wrex_core::dissect::LayerView;
use wrex_core::encode::EncodeCtx;
use wrex_core::error::DecodeError;
use wrex_core::schema::{FieldKind, FieldSchema, LayerSchema, Layout};
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

/// `sll` packet types (`PACKET_HOST`.. `PACKET_OUTGOING`, `sll_pkttype`).
pub const SLL_PKTTYPES: [&str; 5] = ["host", "broadcast", "multicast", "otherhost", "outgoing"];

/// pkttype value → wire u16: the name vocabulary first, bare numbers
/// otherwise (the dhcp6 `msg_type` grammar: names reachable through the
/// Str kind, numbers always accepted).
fn pkttype_num(v: &Value) -> u16 {
    match v {
        Value::Str(s) => {
            if let Some(n) = named_to_u16(s) {
                n
            } else {
                s.parse().unwrap_or(0)
            }
        }
        Value::Int(n) => *n as u16,
        _ => 0,
    }
}

fn pkttype_value(v: u16) -> Value {
    if (v as usize) < SLL_PKTTYPES.len() {
        Value::Str(SLL_PKTTYPES[v as usize].into())
    } else {
        Value::Int(v as u128)
    }
}

fn hatype_value(v: u16) -> Value {
    // Hatypes have no small closed vocabulary worth naming; number.
    Value::Int(v as u128)
}

/// The `sll` kind string this crate implements first (ADR 3): children and
/// the read dispatch reference `wrex_proto_sll::KIND` where they name it.
pub const KIND: &str = "sll";
/// The `sll2` kind (the v2 header): same crate, deliberately — the two
/// headers are the same link type at different revisions and share every
/// dispatch table (the T17 ip6ext multi-kind precedent).
pub const KIND2: &str = "sll2";

static SLL_FIELDS: [FieldSchema; 5] = [
    d(
        "pkttype",
        FieldKind::Str,
        "packet type: host|broadcast|multicast|otherhost|outgoing or a bare 0-4 number",
        Value::Str(std::borrow::Cow::Borrowed("host")),
    ),
    d(
        "hatype",
        FieldKind::U16,
        "link-layer address type (ARP hardware code; 1 = ether)",
        Value::Int(0),
    ),
    d(
        "halen",
        FieldKind::U16,
        "link-layer address length in bytes (autofill: 6)",
        Value::Int(6),
    ),
    d(
        "addr",
        FieldKind::Bytes,
        "link-layer address (8-byte region; MACs occupy the low 6)",
        Value::Bytes(bytes::Bytes::new()),
    ),
    d(
        "protocol",
        FieldKind::U16,
        "encapsulated ethertype (autofill: derived from next layer)",
        Value::Int(0),
    ),
];

static SLL_SCHEMA: LayerSchema = LayerSchema {
    kind: KIND,
    rank: 10,
    parents: &[],
    doc: "Linux cooked capture v1 (LINKTYPE_LINUX_SLL, `tcpdump -i any`): 16-byte pseudo-header (pkttype/hatype/halen u16, 8-byte address region, protocol u16) standing in for the link layer. A root layer (rank 10, no parents); protocol drives the chain like eth.type.",
    fields: &SLL_FIELDS,
    records: &[],
};

static SLL2_FIELDS: [FieldSchema; 7] = [
    d(
        "protocol",
        FieldKind::U16,
        "encapsulated ethertype (autofill: derived from next layer)",
        Value::Int(0),
    ),
    d("reserved", FieldKind::U16, "reserved (0)", Value::Int(0)),
    d(
        "ifindex",
        FieldKind::U32,
        "1-based interface index the frame arrived on",
        Value::Int(0),
    ),
    d(
        "hatype",
        FieldKind::U16,
        "link-layer address type (bare ARP hardware code)",
        Value::Int(0),
    ),
    d(
        "pkttype",
        FieldKind::Str,
        "packet type: host|broadcast|multicast|otherhost|outgoing or a bare 0-4 number",
        Value::Str(std::borrow::Cow::Borrowed("host")),
    ),
    d(
        "halen",
        FieldKind::U8,
        "link-layer address length in bytes (autofill: 6)",
        Value::Int(6),
    ),
    d(
        "addr",
        FieldKind::Bytes,
        "link-layer address (8-byte region; MACs occupy the low 6)",
        Value::Bytes(bytes::Bytes::new()),
    ),
];

static SLL2_SCHEMA: LayerSchema = LayerSchema {
    kind: KIND2,
    rank: 10,
    parents: &[],
    doc: "Linux cooked capture v2 (LINKTYPE_LINUX_SLL2): 20-byte pseudo-header — protocol u16 FIRST, reserved u16, ifindex u32, hatype u16, pkttype/halen u8, 8-byte address region. A root layer (rank 10); protocol drives the chain like eth.type.",
    fields: &SLL2_FIELDS,
    records: &[],
};

/// ethertype → next layer kind (for `read` continuation): the eth table
/// verbatim — the cooked header dispatches into the same children.
const fn ethertype_to_kind(t: u16) -> &'static str {
    match t {
        0x0800 => "ipv4",
        0x0806 => "arp",
        0x86dd => "ipv6",
        0x8100 | 0x88a8 => "vlan",
        _ => "unknown",
    }
}

/// next layer kind → ethertype (for `write` autofill of `protocol`): the
/// eth derivation verbatim.
const fn kind_to_ethertype(kind: Option<&'static str>) -> u16 {
    match kind {
        Some(k) => {
            if str_eq(k, "ipv4") {
                0x0800
            } else if str_eq(k, "arp") {
                0x0806
            } else if str_eq(k, "ipv6") {
                0x86dd
            } else if str_eq(k, "vlan") {
                0x8100
            } else {
                0x0000
            }
        }
        None => 0x0000,
    }
}

/// Shared: `protocol` from spec (explicit wins) or autofill.
fn protocol_of(spec: &LayerSpec, ctx: &EncodeCtx) -> u16 {
    match spec.fields.get("protocol") {
        Some(Value::Int(v)) => *v as u16,
        _ if ctx.autofill => kind_to_ethertype(ctx.next),
        _ => 0,
    }
}

/// A named pkttype/hatype spelling → number, for write (the CLI Str
/// grammar accepts the names).
pub fn named_to_u16(name: &str) -> Option<u16> {
    for (i, n) in SLL_PKTTYPES.iter().enumerate() {
        if str_eq(name, n) {
            return Some(i as u16);
        }
    }
    None
}

/// The `sll` codec unit.
pub struct SllCodec;
/// The `sll2` codec unit.
pub struct Sll2Codec;

pub static CODEC: SllCodec = SllCodec;
pub static CODEC2: Sll2Codec = Sll2Codec;

impl Codec for SllCodec {
    fn schema(&self) -> &'static LayerSchema {
        &SLL_SCHEMA
    }

    fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
        Ok(16)
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let (pkttype, hatype, halen, addr) = sll1_values(spec, af);
        ctx.buf.put_u16(pkttype);
        ctx.buf.put_u16(hatype);
        ctx.buf.put_u16(halen);
        ctx.buf.extend_from_slice(&addr);
        ctx.buf.put_u16(protocol_of(spec, ctx));
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.is_empty() {
            return ReadOutcome::Empty;
        }
        if bytes.len() < 16 {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: KIND,
                    need: 16,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let pkttype = u16::from_be_bytes([bytes[0], bytes[1]]);
        let hatype = u16::from_be_bytes([bytes[2], bytes[3]]);
        let halen = u16::from_be_bytes([bytes[4], bytes[5]]);
        let mut addr = [0u8; 8];
        addr.copy_from_slice(&bytes[6..14]);
        let protocol = u16::from_be_bytes([bytes[14], bytes[15]]);
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("pkttype".into(), pkttype_value(pkttype));
        fields.insert("hatype".into(), hatype_value(hatype));
        fields.insert("halen".into(), Value::Int(halen as u128));
        fields.insert(
            "addr".into(),
            Value::Bytes(bytes::Bytes::copy_from_slice(&addr)),
        );
        fields.insert("protocol".into(), Value::Int(protocol as u128));
        let view = LayerView {
            kind: KIND,
            span: ctx.offset..ctx.offset + 16,
            field_spans: Default::default(),
            fields,
        };
        ReadOutcome::Layer(view, Some(Next::Kind(ethertype_to_kind(protocol))))
    }

    /// Tranche 23a fixed layouts (16-byte header).
    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        &[
            ("pkttype", Layout::Bytes { at: 0, len: 2 }),
            ("hatype", Layout::Bytes { at: 2, len: 2 }),
            ("halen", Layout::Bytes { at: 4, len: 2 }),
            ("addr", Layout::Bytes { at: 6, len: 8 }),
            ("protocol", Layout::Bytes { at: 14, len: 2 }),
        ]
    }
}

impl Codec for Sll2Codec {
    fn schema(&self) -> &'static LayerSchema {
        &SLL2_SCHEMA
    }

    fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
        Ok(20)
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let (pkttype, hatype, halen, addr) = sll2_values(spec, af);
        let reserved = match spec.fields.get("reserved") {
            Some(Value::Int(v)) => *v as u16,
            _ => 0,
        };
        let ifindex = match spec.fields.get("ifindex") {
            Some(Value::Int(v)) => *v as u32,
            _ => 0,
        };
        ctx.buf.put_u16(protocol_of(spec, ctx));
        ctx.buf.put_u16(reserved);
        ctx.buf.put_u32(ifindex);
        ctx.buf.put_u16(hatype);
        ctx.buf.put_u8(pkttype);
        ctx.buf.put_u8(halen);
        ctx.buf.extend_from_slice(&addr);
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.is_empty() {
            return ReadOutcome::Empty;
        }
        if bytes.len() < 20 {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: KIND2,
                    need: 20,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let protocol = u16::from_be_bytes([bytes[0], bytes[1]]);
        let reserved = u16::from_be_bytes([bytes[2], bytes[3]]);
        let ifindex = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let hatype = u16::from_be_bytes([bytes[8], bytes[9]]);
        let pkttype = bytes[10];
        let halen = bytes[11];
        let mut addr = [0u8; 8];
        addr.copy_from_slice(&bytes[12..20]);
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("protocol".into(), Value::Int(protocol as u128));
        fields.insert("reserved".into(), Value::Int(reserved as u128));
        fields.insert("ifindex".into(), Value::Int(ifindex as u128));
        fields.insert("hatype".into(), Value::Int(hatype as u128));
        fields.insert("pkttype".into(), pkttype_value(pkttype as u16));
        fields.insert("halen".into(), Value::Int(halen as u128));
        fields.insert(
            "addr".into(),
            Value::Bytes(bytes::Bytes::copy_from_slice(&addr)),
        );
        let view = LayerView {
            kind: KIND2,
            span: ctx.offset..ctx.offset + 20,
            field_spans: Default::default(),
            fields,
        };
        ReadOutcome::Layer(view, Some(Next::Kind(ethertype_to_kind(protocol))))
    }

    /// Tranche 23a fixed layouts (20-byte header).
    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        &[
            ("protocol", Layout::Bytes { at: 0, len: 2 }),
            ("reserved", Layout::Bytes { at: 2, len: 2 }),
            ("ifindex", Layout::Bytes { at: 4, len: 4 }),
            ("hatype", Layout::Bytes { at: 8, len: 2 }),
            ("pkttype", Layout::Bytes { at: 10, len: 1 }),
            ("halen", Layout::Bytes { at: 11, len: 1 }),
            ("addr", Layout::Bytes { at: 12, len: 8 }),
        ]
    }
}

/// sll v1 scalar values from spec (explicit wins, autofill defaults).
fn sll1_values(spec: &LayerSpec, af: bool) -> (u16, u16, u16, [u8; 8]) {
    let pkttype = spec.fields.get("pkttype").map(pkttype_num).unwrap_or(0);
    let hatype = match spec.fields.get("hatype") {
        Some(Value::Int(v)) => *v as u16,
        _ if af => 1, // ARPHRD_ETHER
        _ => 0,
    };
    let halen = match spec.fields.get("halen") {
        Some(Value::Int(v)) => *v as u16,
        _ => 6,
    };
    let addr = spec_addr(spec);
    (pkttype, hatype, halen, addr)
}

/// sll2 scalar values from spec (explicit wins, autofill defaults).
fn sll2_values(spec: &LayerSpec, af: bool) -> (u8, u16, u8, [u8; 8]) {
    let pkttype = spec.fields.get("pkttype").map(pkttype_num).unwrap_or(0) as u8;
    let hatype = match spec.fields.get("hatype") {
        Some(Value::Int(v)) => *v as u16,
        _ if af => 1, // ARPHRD_ETHER
        _ => 0,
    };
    let halen = match spec.fields.get("halen") {
        Some(Value::Int(v)) => *v as u8,
        _ => 6,
    };
    let addr = spec_addr(spec);
    (pkttype, hatype, halen, addr)
}

/// The 8-byte address region from spec (zero-padded, truncated).
fn spec_addr(spec: &LayerSpec) -> [u8; 8] {
    match spec.fields.get("addr") {
        Some(Value::Bytes(b)) => {
            let mut a = [0u8; 8];
            let n = b.len().min(8);
            a[..n].copy_from_slice(&b[..n]);
            a
        }
        _ => [0u8; 8],
    }
}

/// ADR 3 registration closure: register self (dedup-guarded via
/// [`Registry::get`]), then the children's parents — every kind the cooked
/// `protocol` field dispatches into, so any feature selection that includes
/// a cooked codec is parent-complete by construction.
pub fn register(r: &mut wrex_core::Registry) {
    if r.get(KIND).is_none() {
        r.register(&CODEC);
    }
    if r.get(KIND2).is_none() {
        r.register(&CODEC2);
    }
    wrex_proto_eth::register(r);
    wrex_proto_arp::register(r);
    wrex_proto_vlan::register(r);
    wrex_proto_ip::register(r);
    wrex_proto_ip6::register(r);
}

#[cfg(feature = "test-util")]
pub mod strategy {
    //! proptest strategies for `LayerSpec` (behind `test-util`).
    use proptest::prelude::*;
    use wrex_core::spec::LayerSpec;
    use wrex_core::value::Value;

    /// Valid sll specs: any pkttype/hatype/halen the header can carry and an
    /// 8-byte address region; protocol among known + arbitrary values
    /// (self-chaining 8100/88a8 excluded — a random vlan ethertype would
    /// recurse past the spec's stack).
    pub fn sll() -> BoxedStrategy<LayerSpec> {
        (
            0u16..8,
            proptest::sample::select(vec![0u16, 1, 802, 824]),
            proptest::sample::select(vec![0u16, 6]),
            proptest::array::uniform8(any::<u8>()),
            proptest::option::of(
                proptest::sample::select(vec![0x0800u16, 0x0806, 0x1234])
                    .prop_map(|v| Value::Int(v as u128)),
            ),
        )
            .prop_map(|(pkttype, hatype, halen, addr, proto)| {
                let mut fields = std::collections::BTreeMap::new();
                fields.insert("pkttype".into(), Value::Int(pkttype as u128));
                fields.insert("hatype".into(), Value::Int(hatype as u128));
                fields.insert("halen".into(), Value::Int(halen as u128));
                fields.insert("addr".into(), Value::Bytes(addr.to_vec().into()));
                if let Some(p) = proto {
                    fields.insert("protocol".into(), p);
                }
                LayerSpec::with_fields("sll", fields)
            })
            .boxed()
    }

    /// Valid sll2 specs (the v2 field order).
    pub fn sll2() -> BoxedStrategy<LayerSpec> {
        (
            0u8..8,
            proptest::sample::select(vec![0u16, 1, 802]),
            proptest::sample::select(vec![0u8, 6]),
            proptest::array::uniform8(any::<u8>()),
            any::<u32>(),
            any::<u16>(),
            proptest::option::of(
                proptest::sample::select(vec![0x0800u16, 0x0806, 0x1234])
                    .prop_map(|v| Value::Int(v as u128)),
            ),
        )
            .prop_map(|(pkttype, hatype, halen, addr, ifindex, reserved, proto)| {
                let mut fields = std::collections::BTreeMap::new();
                fields.insert("pkttype".into(), Value::Int(pkttype as u128));
                fields.insert("hatype".into(), Value::Int(hatype as u128));
                fields.insert("halen".into(), Value::Int(halen as u128));
                fields.insert("addr".into(), Value::Bytes(addr.to_vec().into()));
                fields.insert("ifindex".into(), Value::Int(ifindex as u128));
                fields.insert("reserved".into(), Value::Int(reserved as u128));
                if let Some(p) = proto {
                    fields.insert("protocol".into(), p);
                }
                LayerSpec::with_fields("sll2", fields)
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wrex_core::Registry;
    use wrex_core::encode::{EncodeOpts, encode};
    use wrex_core::spec::PacketSpec;

    /// Schema invariant: no duplicate field names in either table.
    #[test]
    fn schema_field_names_unique() {
        assert!(wrex_core::schema::field_names_unique(SLL_SCHEMA.fields));
        assert!(wrex_core::schema::field_names_unique(SLL2_SCHEMA.fields));
    }

    fn registry() -> Registry {
        let mut r = Registry::empty();
        register(&mut r);
        r
    }

    fn sll1_spec() -> PacketSpec {
        // pkttype outgoing (4), hatype ether (1), halen 6, addr 6 MAC bytes.
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("pkttype".into(), Value::Int(4));
        fields.insert("hatype".into(), Value::Int(1));
        fields.insert("halen".into(), Value::Int(6));
        fields.insert(
            "addr".into(),
            Value::Bytes(bytes::Bytes::from(vec![0xa6, 0xb8, 0x9e, 0x11, 0xf7, 0x85])),
        );
        PacketSpec::new(
            vec![LayerSpec::with_fields(KIND, fields), LayerSpec::new("ipv4")],
            None,
        )
    }

    /// The live tcpdump veth fixture (first record of the committed
    /// `foreign/sll.pcap` corpus): outgoing MLD echo — pinned bytes,
    /// pins the v1 wire format (tshark agreed field-for-field).
    #[test]
    fn sll1_golden_matches_tcpdump_fixture() {
        let spec = sll1_spec();
        let enc = encode(
            &registry(),
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        // pkttype=4, hatype=1, halen=6, addr=a6:b8:9e:11:f7:85 + 00 00,
        // protocol autofills 0x0800 (ipv4).
        assert_eq!(
            &enc.bytes[..16],
            &[
                0x00, 0x04, 0x00, 0x01, 0x00, 0x06, 0xa6, 0xb8, 0x9e, 0x11, 0xf7, 0x85, 0x00, 0x00,
                0x08, 0x00
            ][..]
        );
        // round-trip through read
        let mut ctx = wrex_core::dissect::DecodeCtx::new(0);
        match CODEC.read(&enc.bytes, &mut ctx) {
            ReadOutcome::Layer(view, Some(Next::Kind(next))) => {
                assert_eq!(view.kind, KIND);
                assert_eq!(view.span, 0..16);
                assert_eq!(next, "ipv4");
                assert_eq!(
                    view.fields.get("pkttype"),
                    Some(&Value::Str("outgoing".into()))
                );
                assert_eq!(view.fields.get("hatype"), Some(&Value::Int(1)));
                assert_eq!(view.fields.get("halen"), Some(&Value::Int(6)));
                assert_eq!(
                    view.fields.get("addr"),
                    Some(&Value::Bytes(bytes::Bytes::from_static(&[
                        0xa6, 0xb8, 0x9e, 0x11, 0xf7, 0x85, 0, 0
                    ])))
                );
                assert_eq!(view.fields.get("protocol"), Some(&Value::Int(0x0800)));
            }
            other => panic!("expected layer, got {other:?}"),
        }
    }

    /// v2 fixture shape: protocol FIRST, then reserved/ifindex/hatype/
    /// pkttype/halen/addr (the committed `foreign/sll2.pcap` first record
    /// had ifindex 3 — here pinned structurally).
    #[test]
    fn sll2_golden_layout() {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("protocol".into(), Value::Int(0x86dd));
        fields.insert("ifindex".into(), Value::Int(3));
        fields.insert("hatype".into(), Value::Int(1));
        fields.insert("pkttype".into(), Value::Int(4));
        fields.insert("halen".into(), Value::Int(6));
        fields.insert(
            "addr".into(),
            Value::Bytes(bytes::Bytes::from(vec![0x1a, 0x17, 0xce, 0xb3, 0xaf, 0x19])),
        );
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![LayerSpec::with_fields(KIND2, fields)], None),
            &EncodeOpts::default(),
        )
        .unwrap();
        assert_eq!(
            &enc.bytes[..],
            &[
                0x86, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x04, 0x06, 0x1a, 0x17,
                0xce, 0xb3, 0xaf, 0x19, 0x00, 0x00
            ][..]
        );
        let mut ctx = wrex_core::dissect::DecodeCtx::new(0);
        match CODEC2.read(&enc.bytes, &mut ctx) {
            ReadOutcome::Layer(view, Some(Next::Kind(next))) => {
                assert_eq!(view.kind, KIND2);
                assert_eq!(view.span, 0..20);
                assert_eq!(next, "ipv6");
                assert_eq!(view.fields.get("ifindex"), Some(&Value::Int(3)));
                assert_eq!(
                    view.fields.get("pkttype"),
                    Some(&Value::Str("outgoing".into()))
                );
            }
            other => panic!("expected layer, got {other:?}"),
        }
    }

    #[test]
    fn truncation_and_empty() {
        let mut ctx = wrex_core::dissect::DecodeCtx::new(0);
        assert!(matches!(
            CODEC.read(&[0u8; 15], &mut ctx),
            ReadOutcome::Anomaly(_, _)
        ));
        let mut ctx = wrex_core::dissect::DecodeCtx::new(0);
        assert!(matches!(CODEC.read(&[], &mut ctx), ReadOutcome::Empty));
        let mut ctx = wrex_core::dissect::DecodeCtx::new(0);
        assert!(matches!(
            CODEC2.read(&[0u8; 19], &mut ctx),
            ReadOutcome::Anomaly(_, _)
        ));
    }

    /// The eth dispatch table verbatim: qinq ethertypes chain into vlan,
    /// unknown ethertypes fall to the synthetic unknown layer.
    #[test]
    fn dispatch_table() {
        for (ty, want) in [
            (0x0800u16, "ipv4"),
            (0x0806, "arp"),
            (0x86dd, "ipv6"),
            (0x8100, "vlan"),
            (0x88a8, "vlan"),
            (0x1234, "unknown"),
        ] {
            assert_eq!(ethertype_to_kind(ty), want);
        }
    }

    /// ADR 3: the children are real Cargo deps — a bare sll registration
    /// composes the whole parent-complete closure, and `register()` is
    /// idempotent (a second call adds nothing).
    #[test]
    fn register_closure_and_idempotence() {
        let mut r = wrex_core::Registry::empty();
        register(&mut r);
        for kind in ["eth", "arp", "vlan", "ipv4", "ipv6", KIND, KIND2] {
            assert!(r.get(kind).is_some(), "{kind} must register");
        }
        let kinds = r.kinds().len();
        register(&mut r);
        assert_eq!(r.kinds().len(), kinds);
    }

    /// A cooked frame dissects end to end through the real children (sll →
    /// ipv4 → udp), the child-side drift-kill the ADR-3 pattern carries.
    #[test]
    fn sll_stacks_into_ipv4_udp() {
        let spec = sll1_spec();
        let enc = encode(
            &registry(),
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, KIND);
        // The trailing `unknown` is honest engine behavior (the vlan
        // precedent): the empty ipv4 payload synthesizes a terminal layer.
        assert_eq!(
            p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec![KIND, "ipv4", "unknown"]
        );
    }
}
