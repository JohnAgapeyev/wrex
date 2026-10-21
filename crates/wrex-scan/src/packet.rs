//! Probe and follow-up packet builders over the wrex-core encode
//! engine. All packets are `[ipv4|ipv6, tcp|udp|icmp|icmpv6]` stacks
//! (IP-start: the [`wrex_io::RawIpDriver`] injects v4 datagrams with
//! `IP_HDRINCL`, the [`wrex_io::RawIpv6Driver`] injects v6 datagrams as
//! full `0x86dd` frames — the kernel routes both). Checksums, lengths
//! and the network-layer protocol derive from the stack via autofill —
//! no codec or engine changes.

use std::collections::BTreeMap;

use bytes::Bytes;
use wrex_core::encode::{EncodeOpts, encode};
use wrex_core::spec::{LayerSpec, PacketSpec};
use wrex_core::value::Value;
use wrex_core::{EncodeError, Registry};

use crate::target::ScanAddr;

/// TCP flag mask bits (MSB-first `[cwr,ece,urg,ack,psh,rst,syn,fin]`).
pub const FLAG_SYN: u128 = 1 << (7 - 6); // syn = bit index 6 → 0x02
pub const FLAG_ACK: u128 = 1 << (7 - 3); // ack = bit index 3 → 0x10
pub const FLAG_RST: u128 = 1 << (7 - 5); // rst = bit index 5 → 0x04

/// ICMPv6 echo request type (the v6 icmp-mode probe).
pub const ICMPV6_ECHO_REQ: u8 = 128;
/// ICMPv6 echo reply type.
pub const ICMPV6_ECHO_REPLY: u8 = 129;

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

/// The network-layer spec for a probe (family-aware kind + addresses).
fn ip_layer(src: ScanAddr, dst: ScanAddr) -> Result<LayerSpec, EncodeError> {
    match (src, dst) {
        (ScanAddr::V4(s), ScanAddr::V4(d)) => Ok(LayerSpec::with_fields(
            "ipv4",
            fields(&[
                ("src", Value::Ipv4(s)),
                ("dst", Value::Ipv4(d)),
                // 64 is the codec default; explicit so probes never
                // inherit caller-side surprises.
                ("ttl", Value::Int(64)),
            ]),
        )),
        (ScanAddr::V6(s), ScanAddr::V6(d)) => Ok(LayerSpec::with_fields(
            "ipv6",
            fields(&[
                ("src", Value::Ipv6(s)),
                ("dst", Value::Ipv6(d)),
                ("hop_limit", Value::Int(64)),
            ]),
        )),
        // The target grammar rejects mixed families per scan.
        _ => Err(EncodeError::IncompatibleStack {
            detail: "mixed address families in one probe".into(),
        }),
    }
}

/// One TCP segment: `seq`/`ack` (ack `None` → 0), flag mask, our
/// addresses as the source 4-tuple.
#[allow(clippy::too_many_arguments)]
pub fn tcp(
    registry: &Registry,
    src: ScanAddr,
    dst: ScanAddr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: Option<u32>,
    flags: u128,
) -> Result<Bytes, EncodeError> {
    let ip = ip_layer(src, dst)?;
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
    src: ScanAddr,
    dst: ScanAddr,
    sport: u16,
    dport: u16,
) -> Result<Bytes, EncodeError> {
    let ip = ip_layer(src, dst)?;
    let udp = LayerSpec::with_fields(
        "udp",
        fields(&[
            ("sport", Value::Int(sport as u128)),
            ("dport", Value::Int(dport as u128)),
        ]),
    );
    encode_stack(registry, vec![ip, udp], None)
}

/// One ICMP/ICMPv6 echo message: type 8/128 (request) from the scan
/// probes, type 0/129 (reply) in tests — the scan replies mirror the
/// probe identity.
pub fn icmp_echo(
    registry: &Registry,
    src: ScanAddr,
    dst: ScanAddr,
    typ: u8,
    id: u16,
    seq: u16,
) -> Result<Bytes, EncodeError> {
    let ip = ip_layer(src, dst)?;
    // v6 targets speak icmpv6 (echo types 128/129); v4 stays icmp.
    let layer = match src {
        ScanAddr::V4(_) => LayerSpec::with_fields(
            "icmp",
            fields(&[
                ("type", Value::Int(typ as u128)),
                ("echo.id", Value::Int(id as u128)),
                ("echo.seq", Value::Int(seq as u128)),
            ]),
        ),
        ScanAddr::V6(_) => LayerSpec::with_fields(
            "icmpv6",
            fields(&[
                ("type", Value::Int(typ as u128)),
                ("echo.id", Value::Int(id as u128)),
                ("echo.seq", Value::Int(seq as u128)),
            ]),
        ),
    };
    encode_stack(registry, vec![ip, layer], None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wrex_core::dissect::dissect;

    fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&wrex_proto_ip::CODEC);
        r.register(&wrex_proto_ip6::CODEC);
        r.register(&wrex_proto_icmp::CODEC);
        r.register(&wrex_proto_icmpv6::CODEC);
        r.register(&wrex_proto_udp::CODEC);
        r.register(&wrex_proto_tcp::CODEC);
        r
    }

    fn src4() -> ScanAddr {
        ScanAddr::V4("127.0.0.1".parse().unwrap())
    }

    fn src6() -> ScanAddr {
        ScanAddr::V6("::1".parse().unwrap())
    }

    #[test]
    fn syn_probe_dissects_back() {
        let reg = registry();
        let bytes = tcp(&reg, src4(), src4(), 40000, 443, 0x11223344, None, FLAG_SYN).unwrap();
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
    fn v6_syn_probe_dissects_back() {
        let reg = registry();
        let bytes = tcp(&reg, src6(), src6(), 40000, 443, 0x11223344, None, FLAG_SYN).unwrap();
        let p = dissect(&reg, &bytes, "ipv6");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[0].kind, "ipv6");
        assert_eq!(p.layers[0].fields.get("next_header"), Some(&Value::Int(6)));
        assert_eq!(p.layers[1].kind, "tcp");
        // payload_len covers the tcp segment
        assert_eq!(p.layers[0].fields.get("payload_len"), Some(&Value::Int(20)));
    }

    #[test]
    fn udp_and_icmp_probes_build() {
        let reg = registry();
        let bytes = udp(&reg, src4(), src4(), 40001, 53).unwrap();
        let p = dissect(&reg, &bytes, "ipv4");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[1].kind, "udp");
        let bytes = icmp_echo(&reg, src4(), src4(), 8, 0x4242, 7).unwrap();
        let p = dissect(&reg, &bytes, "ipv4");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[1].fields.get("echo.id"), Some(&Value::Int(0x4242)));
    }

    #[test]
    fn v6_udp_and_echo_probes_build() {
        let reg = registry();
        let bytes = udp(&reg, src6(), src6(), 40001, 53).unwrap();
        let p = dissect(&reg, &bytes, "ipv6");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[1].kind, "udp");
        // v6 icmp-mode probe: icmpv6 echo request 128
        let bytes = icmp_echo(&reg, src6(), src6(), ICMPV6_ECHO_REQ, 0x4242, 7).unwrap();
        let p = dissect(&reg, &bytes, "ipv6");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[1].kind, "icmpv6");
        assert_eq!(p.layers[1].fields.get("type"), Some(&Value::Int(128)));
        assert_eq!(p.layers[1].fields.get("echo.id"), Some(&Value::Int(0x4242)));
    }

    #[test]
    fn unknown_kinds_fail_encode() {
        let mut reg = Registry::empty();
        reg.register(&wrex_proto_ip::CODEC);
        assert!(tcp(&reg, src4(), src4(), 1, 2, 3, None, FLAG_SYN).is_err());
        // mixed families are rejected by the target grammar; the packet
        // builder refuses them too.
        let full = registry();
        assert!(tcp(&full, src4(), src6(), 1, 2, 3, None, FLAG_SYN).is_err());
    }
}
