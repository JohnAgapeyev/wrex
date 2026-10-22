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
        let view = LayerView {
            kind: KIND,
            span: ctx.offset..ctx.offset + 4,
            field_spans: Default::default(),
            fields,
        };
        // Terminal for slice 1: the options region stays payload.
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
}
