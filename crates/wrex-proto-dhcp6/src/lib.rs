#![forbid(unsafe_code)]
//! wrex DHCPv6 codec (tranche 17c slice 1; RFC 8415): the 4-byte
//! fixed header — `msg_type` (1–13) + `trans_id` (3 bytes). The
//! options region (u16 code, u16 len TLVs, nested sub-options) is
//! the recorded next slice; udp dispatches 546/547 both sides (the
//! 67/68 pattern).

use bytes::BufMut;
use std::sync::LazyLock;
use wrex_core::dissect::{DecodeCtx, LayerView};
use wrex_core::error::DecodeError;
use wrex_core::schema::{FieldKind, FieldSchema, LayerSchema};
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;
use wrex_core::{Codec, EncodeError, Next, ReadOutcome};

/// The kind string this codec implements (ADR 3).
pub const KIND: &str = "dhcp6";

fn f(name: &'static str, kind: FieldKind, doc: &'static str, default: Value) -> FieldSchema {
    FieldSchema {
        name,
        kind,
        bit_names: &[],
        default,
        required: false,
        doc,
    }
}

static FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
    vec![
        f(
            "msg_type",
            FieldKind::U8,
            "message type (1 solicit, 2 advertise, 3 request, 4 reply, 5 release, 6 decline, 8 info_req, 9 renew, 10 rebind, 12 relay_forward, 13 relay_reply; raw numbers kept)",
            Value::Int(1),
        ),
        f(
            "trans_id",
            FieldKind::U32,
            "transaction id (3 bytes on the wire; over-wide values mask)",
            Value::Int(0),
        ),
    ]
});

pub static SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: KIND,
    rank: 40,
    parents: &[wrex_proto_udp::KIND],
    doc: "DHCPv6 (RFC 8415) over UDP 546/547: the 4-byte fixed header (msg_type 1-13 + the 3-byte trans_id) — everything else is options (u16 code, u16 len TLVs; the options grammar with nested sub-options is the recorded tranche-17c tail). udp dispatches ports 546/547 into this codec.",
    fields: FIELDS.as_slice(),
    records: &[],
});

pub struct Dhcp6Codec;
pub static CODEC: Dhcp6Codec = Dhcp6Codec;

/// ADR 3 registration closure: self first, then the parent crate's.
pub fn register(r: &mut wrex_core::Registry) {
    if r.get(KIND).is_none() {
        r.register(&CODEC);
    }
    wrex_proto_udp::register(r);
}

impl Codec for Dhcp6Codec {
    fn schema(&self) -> &'static LayerSchema {
        &SCHEMA
    }
    fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
        Ok(4)
    }
    fn write(
        &self,
        spec: &LayerSpec,
        ctx: &mut wrex_core::encode::EncodeCtx,
    ) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        ctx.buf
            .put_u8(wrex_core::encode::int_or_default(spec, &FIELDS[0], af) as u8);
        let tid = wrex_core::encode::int_or_default(spec, &FIELDS[1], af) as u32;
        ctx.buf
            .extend_from_slice(&(tid & 0xff_ffff).to_be_bytes()[1..4]);
        Ok(())
    }
    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.is_empty() {
            return ReadOutcome::Empty;
        }
        if bytes.len() < 4 {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: KIND,
                    need: 4,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("msg_type".into(), Value::Int(bytes[0] as u128));
        fields.insert(
            "trans_id".into(),
            Value::Int(u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as u128),
        );
        // Relay shapes (tranche 17c, RFC 8415 §7.1): msg-type 12/13
        // carry the 33-byte extended fixed header — hop-count,
        // link-address, peer-address (dissect-only fields; the
        // nested relay-message option is the recorded tail).
        if (bytes[0] == 12 || bytes[0] == 13) && bytes.len() >= 34 {
            // Relay header: msg-type(1), hop-count(1), link(16),
            // peer(16) — hop-count at byte 1, not the trans_id slot.
            fields.insert("hop_count".into(), Value::Int(bytes[1] as u128));
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&bytes[2..18]);
            fields.insert("link_addr".into(), Value::Ipv6(addr.into()));
            addr.copy_from_slice(&bytes[18..34]);
            fields.insert("peer_addr".into(), Value::Ipv6(addr.into()));
            let view = LayerView {
                kind: KIND,
                span: ctx.offset..ctx.offset + 34,
                field_spans: Default::default(),
                fields,
            };
            return ReadOutcome::Layer(view, Some(Next::Payload));
        }
        let view = LayerView {
            kind: KIND,
            span: ctx.offset..ctx.offset + 4,
            field_spans: Default::default(),
            fields,
        };
        // Terminal for the slice: the options region stays payload.
        ReadOutcome::Layer(view, Some(Next::Payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wrex_core::Registry;
    use wrex_core::encode::encode;
    use wrex_core::spec::PacketSpec;

    #[test]
    fn header_roundtrip_and_udp_dispatch() {
        let mut r = Registry::empty();
        register(&mut r);
        let mut uf = std::collections::BTreeMap::new();
        uf.insert("sport".to_string(), Value::Int(546));
        uf.insert("dport".to_string(), Value::Int(547));
        let spec = PacketSpec::new(
            vec![
                wrex_core::spec::LayerSpec::with_fields(wrex_proto_udp::KIND, uf),
                wrex_core::spec::LayerSpec::with_fields(
                    KIND,
                    [
                        ("msg_type".to_string(), Value::Int(1)),
                        ("trans_id".to_string(), Value::Int(0x112233)),
                    ]
                    .into_iter()
                    .collect(),
                ),
            ],
            None,
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
        assert_eq!(&enc.bytes[8..], &[1, 0x11, 0x22, 0x33][..]);
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, wrex_proto_udp::KIND);
        assert_eq!(
            p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec![wrex_proto_udp::KIND, KIND],
            "port 546/547 must chain into the real dhcp6 codec"
        );
        assert_eq!(
            p.layers[1].fields.get("trans_id"),
            Some(&Value::Int(0x112233))
        );
    }

    /// Tranche 17c: the relay shapes (12/13) dissect with their
    /// 33-byte extended fixed header — hop-count, link-address,
    /// peer-address (dissect-only; crafting relay messages stays
    /// deferred per the charter).
    #[test]
    fn relay_header_dissects() {
        let mut r = Registry::empty();
        register(&mut r);
        let mut frame = vec![12u8, 0x0a];
        frame.extend_from_slice(&[0u8; 32]); // link + peer (::)
        frame.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0xde, 0xad]); // a TLV tail
        let p = wrex_core::dissect::dissect(&r, &frame, KIND);
        assert_eq!(p.layers[0].kind, KIND);
        assert_eq!(p.layers[0].fields.get("hop_count"), Some(&Value::Int(10)));
        assert_eq!(p.layers[0].span, 0..34);
        // The TLV tail stays payload (the options grammar is the tail).
        assert_eq!(&p.payload[..], &[0x00, 0x01, 0x00, 0x02, 0xde, 0xad][..]);
        // A SOLICIT-family type keeps the 4-byte header.
        let plain = [1u8, 0x11, 0x22, 0x33, 0xde];
        let p = wrex_core::dissect::dissect(&r, &plain, KIND);
        assert_eq!(p.layers[0].span, 0..4);
    }

    #[test]
    fn trans_id_masks_and_roundtrips() {
        let mut r = Registry::empty();
        register(&mut r);
        // Over-wide trans_id (u32) writes only its low 3 bytes.
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("msg_type".to_string(), Value::Int(1));
        fields.insert("trans_id".to_string(), Value::Int(0xaa_112233));
        let spec = PacketSpec::new(
            vec![wrex_core::spec::LayerSpec::with_fields(KIND, fields)],
            None,
        );
        let enc = encode(&r, &spec, &Default::default()).unwrap();
        assert_eq!(&enc.bytes[..], &[1, 0x11, 0x22, 0x33]);
        // And dissects back as the masked value.
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, KIND);
        assert_eq!(
            p.layers[0].fields.get("trans_id"),
            Some(&Value::Int(0x112233))
        );
    }

    #[test]
    fn truncated_and_empty_inputs_are_anomalies() {
        let mut r = Registry::empty();
        register(&mut r);
        // 1-3 bytes: truncated → anomaly; the rest lands in the synthetic
        // `unknown` layer as partial data (never fatal).
        let p = wrex_core::dissect::dissect(&r, &[1, 0x11], KIND);
        assert_eq!(p.layers.len(), 1);
        assert_eq!(p.layers[0].kind, "unknown", "partial data is synthetic");
        assert_eq!(
            p.anomalies.len(),
            1,
            "one truncation anomaly: {:?}",
            p.anomalies
        );
        // Empty: the Empty outcome, no anomaly.
        let p = wrex_core::dissect::dissect(&r, &[], KIND);
        assert!(p.layers.is_empty() && p.anomalies.is_empty());
        // A relay type on a short (<34-byte) frame keeps the plain header.
        let p = wrex_core::dissect::dissect(&r, &[12, 1, 0, 0, 0, 0], KIND);
        assert_eq!(p.layers[0].span, 0..4);
        assert_eq!(p.layers[0].fields.get("hop_count"), None);
    }

    #[test]
    fn udp_dispatch_is_port_keyed() {
        let mut r = Registry::empty();
        register(&mut r);
        let mut uf = std::collections::BTreeMap::new();
        uf.insert("sport".to_string(), Value::Int(546));
        uf.insert("dport".to_string(), Value::Int(9999)); // not 546/547
        let spec = PacketSpec::new(
            vec![wrex_core::spec::LayerSpec::with_fields(
                wrex_proto_udp::KIND,
                uf,
            )],
            None,
        );
        let enc = encode(&r, &spec, &Default::default()).unwrap();
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, wrex_proto_udp::KIND);
        assert_eq!(
            p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec![wrex_proto_udp::KIND],
            "a non-546/547 port must not chain into dhcp6"
        );
    }
}
