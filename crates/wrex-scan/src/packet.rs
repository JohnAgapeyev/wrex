//! Probe and follow-up packet builders over the wrex-core encode
//! engine. All packets are `[ipv4, tcp|udp|icmp]` stacks (IP-start:
//! the [`wrex_io::RawIpDriver`] injects datagrams with `IP_HDRINCL` and
//! the kernel routes). Checksums, lengths and the IPv4 `proto` derive
//! from the stack via autofill — no codec or engine changes.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use bytes::Bytes;
use wrex_core::encode::{EncodeOpts, encode};
use wrex_core::spec::{LayerSpec, PacketSpec};
use wrex_core::value::Value;
use wrex_core::{EncodeError, Registry};

/// TCP flag mask bits (MSB-first `[cwr,ece,urg,ack,psh,rst,syn,fin]`).
pub const FLAG_SYN: u128 = 1 << (7 - 6); // syn = bit index 6 → 0x02
pub const FLAG_ACK: u128 = 1 << (7 - 3); // ack = bit index 3 → 0x10
pub const FLAG_RST: u128 = 1 << (7 - 5); // rst = bit index 5 → 0x04

fn fields(pairs: &[(&str, Value)]) -> BTreeMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

fn encode_stack(
    registry: &Registry,
    layers: Vec<LayerSpec>,
    payload: Option<Value>,
) -> Result<Bytes, EncodeError> {
    let spec = PacketSpec::new(layers, payload);
    let encoded = encode(
        registry,
        &spec,
        &EncodeOpts {
            autofill: true,
            ..Default::default()
        },
    )?;
    Ok(encoded.bytes)
}

/// One TCP segment: `seq`/`ack` (ack `None` → 0), flag mask, our
/// addresses as the source 4-tuple.
#[allow(clippy::too_many_arguments)]
pub fn tcp(
    registry: &Registry,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: Option<u32>,
    flags: u128,
) -> Result<Bytes, EncodeError> {
    let ip = LayerSpec::with_fields(
        "ipv4",
        fields(&[
            ("src", Value::Ipv4(src)),
            ("dst", Value::Ipv4(dst)),
            // 64 is the codec default; explicit so probes never inherit
            // caller-side surprises.
            ("ttl", Value::Int(64)),
        ]),
    );
    let mut tcp_fields = vec![
        ("sport", Value::Int(sport as u128)),
        ("dport", Value::Int(dport as u128)),
        ("seq", Value::Int(seq as u128)),
        ("flags", Value::Int(flags)),
    ];
    if let Some(a) = ack {
        tcp_fields.push(("ack", Value::Int(a as u128)));
    }
    let tcp = LayerSpec::with_fields("tcp", fields(&tcp_fields));
    encode_stack(registry, vec![ip, tcp], None)
}

/// One empty UDP datagram (the classic UDP scan probe).
pub fn udp(
    registry: &Registry,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
) -> Result<Bytes, EncodeError> {
    let ip = LayerSpec::with_fields(
        "ipv4",
        fields(&[
            ("src", Value::Ipv4(src)),
            ("dst", Value::Ipv4(dst)),
            ("ttl", Value::Int(64)),
        ]),
    );
    let udp = LayerSpec::with_fields(
        "udp",
        fields(&[
            ("sport", Value::Int(sport as u128)),
            ("dport", Value::Int(dport as u128)),
        ]),
    );
    encode_stack(registry, vec![ip, udp], None)
}

/// One ICMP echo message: type 8 (request) from the scan probes, type 0
/// (reply) in tests — the scan replies mirror the probe identity.
pub fn icmp_echo(
    registry: &Registry,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    typ: u8,
    id: u16,
    seq: u16,
) -> Result<Bytes, EncodeError> {
    let ip = LayerSpec::with_fields(
        "ipv4",
        fields(&[
            ("src", Value::Ipv4(src)),
            ("dst", Value::Ipv4(dst)),
            ("ttl", Value::Int(64)),
        ]),
    );
    let icmp = LayerSpec::with_fields(
        "icmp",
        fields(&[
            ("type", Value::Int(typ as u128)),
            ("echo.id", Value::Int(id as u128)),
            ("echo.seq", Value::Int(seq as u128)),
        ]),
    );
    encode_stack(registry, vec![ip, icmp], None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wrex_core::dissect::dissect;

    fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&wrex_proto_ip::CODEC);
        r.register(&wrex_proto_tcp::CODEC);
        r.register(&wrex_proto_udp::CODEC);
        r.register(&wrex_proto_icmp::CODEC);
        r
    }

    #[test]
    fn syn_probe_dissects_back() {
        let reg = registry();
        let src: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let bytes = tcp(&reg, src, src, 40000, 443, 0x11223344, None, FLAG_SYN).unwrap();
        let p = dissect(&reg, &bytes, "ipv4");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[0].fields.get("proto"), Some(&Value::Int(6)));
        let tcp = &p.layers[1];
        assert_eq!(
            tcp.fields.get("flags"),
            Some(&Value::List(vec![Value::Str("syn".into())]))
        );
        assert_eq!(tcp.fields.get("seq"), Some(&Value::Int(0x11223344)));
    }

    #[test]
    fn udp_and_icmp_probes_build() {
        let reg = registry();
        let src: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let bytes = udp(&reg, src, src, 40001, 53).unwrap();
        let p = dissect(&reg, &bytes, "ipv4");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[1].kind, "udp");
        let bytes = icmp_echo(&reg, src, src, 8, 0x4242, 7).unwrap();
        let p = dissect(&reg, &bytes, "ipv4");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[1].fields.get("echo.id"), Some(&Value::Int(0x4242)));
    }

    #[test]
    fn unknown_kinds_fail_encode() {
        let mut reg = Registry::empty();
        reg.register(&wrex_proto_ip::CODEC);
        let src: Ipv4Addr = "127.0.0.1".parse().unwrap();
        assert!(tcp(&reg, src, src, 1, 2, 3, None, FLAG_SYN).is_err());
    }
}
