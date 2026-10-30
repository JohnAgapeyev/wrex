//! Probe and follow-up packet builders over the wrex-core encode
//! engine. All packets are `[ipv4|ipv6, tcp|udp|icmp|icmpv6]` stacks
//! (IP-start: the [`wrex_io::RawIpDriver`] injects v4 datagrams with
//! `IP_HDRINCL`, the [`wrex_io::RawIpv6Driver`] injects v6 datagrams as
//! full `0x86dd` frames — the kernel routes both). Checksums, lengths
//! and the network-layer protocol derive from the stack via autofill —
//! no codec or engine changes.

use std::borrow::Cow;
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
pub const FLAG_FIN: u128 = 1; // fin = bit index 7 → 0x01
pub const FLAG_PSH: u128 = 1 << (7 - 4); // psh = bit index 4 → 0x08
pub const FLAG_URG: u128 = 1 << (7 - 2); // urg = bit index 2 → 0x20
/// NULL scan: no flags set at all.
pub const FLAG_NONE: u128 = 0;
/// XMAS scan: FIN|PSH|URG (nmap's "lights on").
pub const FLAG_XMAS: u128 = FLAG_FIN | FLAG_PSH | FLAG_URG;

/// ICMP time-exceeded type (v4, the traceroute quote reply).
pub const ICMP_TIME_EXCEEDED: u8 = 11;
/// ICMPv6 time-exceeded type (RFC 4443 §3.3, the traceroute quote).
pub const ICMPV6_TIME_EXCEEDED: u8 = 3;

/// ICMPv6 echo request type (the v6 icmp-mode probe).
pub const ICMPV6_ECHO_REQ: u8 = 128;
/// ICMPv6 echo reply type.
pub const ICMPV6_ECHO_REPLY: u8 = 129;

fn fields(pairs: &[(&str, Value)]) -> BTreeMap<Cow<'static, str>, Value> {
    pairs
        .iter()
        .map(|(k, v)| (Cow::Owned(k.to_string()), v.clone()))
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
    ip_layer_ttl(src, dst, 64)
}

/// The network-layer spec with an explicit TTL/hop-limit (the
/// traceroute walk — every other caller wants the 64 default).
fn ip_layer_ttl(src: ScanAddr, dst: ScanAddr, ttl: u8) -> Result<LayerSpec, EncodeError> {
    match (src, dst) {
        (ScanAddr::V4(s), ScanAddr::V4(d)) => Ok(LayerSpec::with_fields(
            "ipv4",
            fields(&[
                ("src", Value::Ipv4(s)),
                ("dst", Value::Ipv4(d)),
                // 64 is the codec default; explicit so probes never
                // inherit caller-side surprises.
                ("ttl", Value::Int(ttl as u128)),
            ]),
        )),
        (ScanAddr::V6(s), ScanAddr::V6(d)) => Ok(LayerSpec::with_fields(
            "ipv6",
            fields(&[
                ("src", Value::Ipv6(s)),
                ("dst", Value::Ipv6(d)),
                ("hop_limit", Value::Int(ttl as u128)),
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

/// One ARP request frame (the `--mode arp` probe): a full Ethernet
/// frame — broadcast destination, our MAC and address as sender, the
/// target protocol address asked for. Injected through the Ethernet
/// driver (`AF_PACKET`); replies arrive as ARP replies with
/// `spa == target`.
pub fn arp_probe(
    registry: &Registry,
    src: std::net::Ipv4Addr,
    mac: [u8; 6],
    target: ScanAddr,
) -> Result<Bytes, EncodeError> {
    let ScanAddr::V4(target) = target else {
        return Err(EncodeError::IncompatibleStack {
            detail: "arp mode is v4-only (the target grammar enforces it)".into(),
        });
    };
    let eth = LayerSpec::with_fields(
        "eth",
        fields(&[("dst", Value::Mac([0xff; 6])), ("src", Value::Mac(mac))]),
    );
    let arp = LayerSpec::with_fields(
        "arp",
        fields(&[
            ("oper", Value::Int(1)),
            ("sha", Value::Mac(mac)),
            ("spa", Value::Ipv4(src)),
            ("tpa", Value::Ipv4(target)),
        ]),
    );
    encode_stack(registry, vec![eth, arp], None)
}

/// One unicast NDP Neighbor Solicitation (the `--mode ndp` probe):
/// `[ipv6, icmpv6]` with type 135, `ndp.target` = the target and a
/// source link-layer address option when our MAC is known. The v6
/// driver injects the datagram (the kernel synthesizes the frame).
pub fn ndp_probe(
    registry: &Registry,
    src: ScanAddr,
    mac: Option<[u8; 6]>,
    target: ScanAddr,
) -> Result<Bytes, EncodeError> {
    let (ScanAddr::V6(s), ScanAddr::V6(t)) = (src, target) else {
        return Err(EncodeError::IncompatibleStack {
            detail: "ndp mode is v6-only (the target grammar enforces it)".into(),
        });
    };
    let ip = LayerSpec::with_fields(
        "ipv6",
        fields(&[
            ("src", Value::Ipv6(s)),
            ("dst", Value::Ipv6(t)),
            ("hop_limit", Value::Int(255)),
        ]),
    );
    let mut ns_fields = vec![("type", Value::Int(135)), ("ndp.target", Value::Ipv6(t))];
    if let Some(mac) = mac {
        // SLLA option through the icmpv6 options list grammar.
        ns_fields.push(("options", Value::Str(mac_option(mac).into())));
    }
    let ns = LayerSpec::with_fields("icmpv6", fields(&ns_fields));
    encode_stack(registry, vec![ip, ns], None)
}

/// One MLDv1 query (the `--mode mld` probe): `[ipv6, icmpv6]` with
/// type 130 (max-response rides the code field, 1/10s units) asking
/// after the target multicast group. Members answer with reports
/// (type 131) naming the group in `mld.addr`.
pub fn mld_query(
    registry: &Registry,
    src: ScanAddr,
    target: ScanAddr,
) -> Result<Bytes, EncodeError> {
    let (ScanAddr::V6(s), ScanAddr::V6(t)) = (src, target) else {
        return Err(EncodeError::IncompatibleStack {
            detail: "mld mode is v6-only (the target grammar enforces it)".into(),
        });
    };
    let ip = LayerSpec::with_fields(
        "ipv6",
        fields(&[
            ("src", Value::Ipv6(s)),
            ("dst", Value::Ipv6(t)),
            ("hop_limit", Value::Int(1)),
        ]),
    );
    let query = LayerSpec::with_fields(
        "icmpv6",
        fields(&[
            ("type", Value::Int(130)),
            ("code", Value::Int(0)),
            ("mld.addr", Value::Ipv6(t)),
        ]),
    );
    encode_stack(registry, vec![ip, query], None)
}

/// MAC rendered in the icmpv6 options-list grammar spelling
/// (`slla:AA:BB:…`).
fn mac_option(mac: [u8; 6]) -> String {
    format!(
        "slla:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

// --- traceroute probes (T21b): the same builders with an explicit TTL -------

/// One TCP segment with an explicit TTL (the traceroute probe).
#[allow(clippy::too_many_arguments)]
pub fn tcp_ttl(
    registry: &Registry,
    src: ScanAddr,
    dst: ScanAddr,
    sport: u16,
    dport: u16,
    seq: u32,
    ack: Option<u32>,
    flags: u128,
    ttl: u8,
) -> Result<Bytes, EncodeError> {
    let ip = ip_layer_ttl(src, dst, ttl)?;
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

/// One empty UDP datagram with an explicit TTL (the traceroute probe).
pub fn udp_ttl(
    registry: &Registry,
    src: ScanAddr,
    dst: ScanAddr,
    sport: u16,
    dport: u16,
    ttl: u8,
) -> Result<Bytes, EncodeError> {
    let ip = ip_layer_ttl(src, dst, ttl)?;
    let udp = LayerSpec::with_fields(
        "udp",
        fields(&[
            ("sport", Value::Int(sport as u128)),
            ("dport", Value::Int(dport as u128)),
        ]),
    );
    encode_stack(registry, vec![ip, udp], None)
}

/// One ICMP/ICMPv6 echo message with an explicit TTL (the traceroute
/// probe).
pub fn icmp_echo_ttl(
    registry: &Registry,
    src: ScanAddr,
    dst: ScanAddr,
    typ: u8,
    id: u16,
    seq: u16,
    ttl: u8,
) -> Result<Bytes, EncodeError> {
    let ip = ip_layer_ttl(src, dst, ttl)?;
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

    fn eth_registry() -> Registry {
        let mut r = registry();
        r.register(&wrex_proto_eth::CODEC);
        r.register(&wrex_proto_arp::CODEC);
        r
    }

    const TEST_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    #[test]
    fn flag_constants_match_bit_order() {
        assert_eq!(FLAG_SYN, 0x02);
        assert_eq!(FLAG_ACK, 0x10);
        assert_eq!(FLAG_RST, 0x04);
        assert_eq!(FLAG_FIN, 0x01);
        assert_eq!(FLAG_PSH, 0x08);
        assert_eq!(FLAG_URG, 0x20);
        assert_eq!(FLAG_XMAS, 0x29);
        assert_eq!(FLAG_NONE, 0);
    }

    #[test]
    fn arp_probe_is_a_broadcast_request() {
        let reg = eth_registry();
        let bytes = arp_probe(&reg, "10.0.0.9".parse().unwrap(), TEST_MAC, src4()).unwrap();
        // full frame: dissect from eth
        let p = dissect(&reg, &bytes, "eth");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[0].kind, "eth");
        assert_eq!(p.layers[0].fields.get("type"), Some(&Value::Int(0x0806)));
        assert_eq!(p.layers[0].fields.get("dst"), Some(&Value::Mac([0xff; 6])));
        let arp = &p.layers[1];
        assert_eq!(arp.kind, "arp");
        assert_eq!(arp.fields.get("oper"), Some(&Value::Int(1)));
        assert_eq!(arp.fields.get("sha"), Some(&Value::Mac(TEST_MAC)));
        assert_eq!(
            arp.fields.get("spa"),
            Some(&Value::Ipv4("10.0.0.9".parse().unwrap()))
        );
        assert_eq!(
            arp.fields.get("tpa"),
            Some(&Value::Ipv4("127.0.0.1".parse().unwrap()))
        );
        // v6 target refused
        assert!(arp_probe(&reg, "10.0.0.9".parse().unwrap(), TEST_MAC, src6()).is_err());
    }

    #[test]
    fn ndp_probe_solicits_with_slla() {
        let reg = eth_registry();
        let bytes = ndp_probe(&reg, src6(), Some(TEST_MAC), src6()).unwrap();
        let p = dissect(&reg, &bytes, "ipv6");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        let icmp6 = &p.layers[1];
        assert_eq!(icmp6.kind, "icmpv6");
        assert_eq!(icmp6.fields.get("type"), Some(&Value::Int(135)));
        assert_eq!(
            icmp6.fields.get("ndp.target"),
            Some(&Value::Ipv6("::1".parse().unwrap()))
        );
        // SLLA rendered as an indexed opt record
        assert_eq!(
            icmp6.fields.get("opt.0.addr"),
            Some(&Value::Mac(TEST_MAC)),
            "{:?}",
            icmp6.fields
        );
        // without a MAC: no options region
        let bare = ndp_probe(&reg, src6(), None, src6()).unwrap();
        let bp = dissect(&reg, &bare, "ipv6");
        assert!(bp.anomalies.is_empty(), "{:?}", bp.anomalies);
        assert!(!bp.layers[1].fields.contains_key("opt.0.addr"));
        // v4 target refused
        assert!(ndp_probe(&reg, src4(), Some(TEST_MAC), src4()).is_err());
    }

    #[test]
    fn mld_query_names_the_group() {
        let reg = eth_registry();
        let group: ScanAddr = ScanAddr::V6("ff02::1".parse().unwrap());
        let bytes = mld_query(&reg, src6(), group).unwrap();
        let p = dissect(&reg, &bytes, "ipv6");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[0].fields.get("hop_limit"), Some(&Value::Int(1)));
        assert_eq!(
            p.layers[0].fields.get("dst"),
            Some(&Value::Ipv6("ff02::1".parse().unwrap()))
        );
        let icmp6 = &p.layers[1];
        assert_eq!(icmp6.fields.get("type"), Some(&Value::Int(130)));
        assert_eq!(icmp6.fields.get("code"), Some(&Value::Int(0)));
        assert_eq!(
            icmp6.fields.get("mld.addr"),
            Some(&Value::Ipv6("ff02::1".parse().unwrap()))
        );
        assert!(mld_query(&reg, src4(), src4()).is_err());
    }
}
