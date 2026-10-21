//! Stack strategies: aggregate the per-proto `test-util` strategies into
//! packet specs. New protocols plug in by adding a stack name here.

use proptest::prelude::*;
use wrex_core::spec::{LayerSpec, PacketSpec};
use wrex_core::value::Value;

/// Stack names supported by [`packet_strategy`].
pub const STACKS: &[&str] = &[
    "eth",
    "eth-arp",
    "eth-vlan",
    "eth-vlan-vlan",
    "eth-vlan-ipv4-udp",
    "eth-vlan-ipv4-tcp",
    "eth-vlan-ipv4-icmp",
    "eth-vlan-ipv6-udp",
    "eth-vlan-ipv6-tcp",
    "eth-vlan-ipv6-icmpv6",
    "eth-ipv4-udp",
    "eth-ipv4-tcp",
    "eth-ipv4-icmp",
    "eth-ipv6-udp",
    "eth-ipv6-tcp",
    "eth-ipv6-icmpv6",
    "ipv4",
    "ipv6",
];

pub fn stacks() -> &'static [&'static str] {
    STACKS
}

fn payload() -> BoxedStrategy<Value> {
    use proptest::collection::vec;
    vec(any::<u8>(), 0..=32)
        .prop_map(|v| Value::Bytes(bytes::Bytes::from(v)))
        .boxed()
}

/// Eth spec with the explicit `type` dropped: the derived-`type` stacks
/// (vlan chains since T7a, ipv6 chains since T7b) chain eth.type from
/// the next layer via autofill, so the differential chain follows the
/// spec exactly instead of diverging on a random ethertype (an explicit
/// 0x0800 would chain straight into ipv4, reading the vlan tag as an
/// ipv4 header; a random 0x0800 over an ipv6 stack would mis-parse the
/// v6 header as ipv4 — anomalies on our own layers either way).
fn eth_derived() -> BoxedStrategy<LayerSpec> {
    wrex_proto_eth::strategy::strategy()
        .prop_map(|mut eth| {
            eth.fields.remove("type");
            eth
        })
        .boxed()
}

/// Vlan spec with the explicit `type` dropped: the ipv6 vlan stacks
/// (tranche 7b) derive vlan.type from the next layer, so a random
/// ethertype cannot mis-parse the v6 chain (see `eth_derived`).
fn vlan_derived() -> BoxedStrategy<LayerSpec> {
    wrex_proto_vlan::strategy::strategy()
        .prop_map(|mut vlan| {
            vlan.fields.remove("type");
            vlan
        })
        .boxed()
}

/// Build a packet strategy for a named stack.
///
/// Stacks: `"eth"`, `"eth-arp"`, `"eth-vlan"`, `"eth-vlan-vlan"` (QinQ),
/// `"eth-vlan-ipv4-udp"`, `"eth-vlan-ipv4-tcp"`, `"eth-vlan-ipv4-icmp"`,
/// `"eth-ipv4-udp"`, `"eth-ipv4-tcp"`, `"eth-ipv4-icmp"`, `"ipv4"` (raw
/// L3 start).
pub fn packet_strategy(stack: &str) -> BoxedStrategy<PacketSpec> {
    match stack {
        "eth" => (wrex_proto_eth::strategy::strategy(), payload())
            .prop_map(|(eth, pay)| PacketSpec::new(vec![eth], Some(pay)))
            .boxed(),
        "eth-arp" => (
            wrex_proto_eth::strategy::strategy(),
            wrex_proto_arp::strategy::strategy(),
        )
            .prop_map(|(eth, arp)| PacketSpec::new(vec![eth, arp], None))
            .boxed(),
        "eth-vlan" => (
            eth_derived(),
            wrex_proto_vlan::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, vlan, pay)| PacketSpec::new(vec![eth, vlan], Some(pay)))
            .boxed(),
        // QinQ: 802.1ad double tag (eth -> outer vlan -> inner vlan).
        "eth-vlan-vlan" => (
            eth_derived(),
            wrex_proto_vlan::strategy::strategy(),
            wrex_proto_vlan::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, outer, inner, pay)| {
                PacketSpec::new(vec![eth, outer, inner], Some(pay))
            })
            .boxed(),
        "eth-vlan-ipv4-udp" => (
            eth_derived(),
            wrex_proto_vlan::strategy::strategy(),
            wrex_proto_ip::strategy::strategy(),
            wrex_proto_udp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, vlan, ip, udp, pay)| {
                PacketSpec::new(vec![eth, vlan, ip, udp], Some(pay))
            })
            .boxed(),
        "eth-vlan-ipv4-tcp" => (
            eth_derived(),
            wrex_proto_vlan::strategy::strategy(),
            wrex_proto_ip::strategy::strategy(),
            wrex_proto_tcp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, vlan, ip, tcp, pay)| {
                PacketSpec::new(vec![eth, vlan, ip, tcp], Some(pay))
            })
            .boxed(),
        "eth-vlan-ipv4-icmp" => (
            eth_derived(),
            wrex_proto_vlan::strategy::strategy(),
            wrex_proto_ip::strategy::strategy(),
            wrex_proto_icmp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, vlan, ip, icmp, pay)| {
                PacketSpec::new(vec![eth, vlan, ip, icmp], Some(pay))
            })
            .boxed(),
        "ipv4" => (wrex_proto_ip::strategy::strategy(), payload())
            .prop_map(|(ip, pay)| PacketSpec::new(vec![ip], Some(pay)))
            .boxed(),
        "eth-ipv4-udp" => (
            wrex_proto_eth::strategy::strategy(),
            wrex_proto_ip::strategy::strategy(),
            wrex_proto_udp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, udp, pay)| PacketSpec::new(vec![eth, ip, udp], Some(pay)))
            .boxed(),
        "eth-ipv4-tcp" => (
            wrex_proto_eth::strategy::strategy(),
            wrex_proto_ip::strategy::strategy(),
            wrex_proto_tcp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, tcp, pay)| PacketSpec::new(vec![eth, ip, tcp], Some(pay)))
            .boxed(),
        "eth-ipv4-icmp" => (
            wrex_proto_eth::strategy::strategy(),
            wrex_proto_ip::strategy::strategy(),
            wrex_proto_icmp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, icmp, pay)| PacketSpec::new(vec![eth, ip, icmp], Some(pay)))
            .boxed(),
        "eth-vlan-ipv6-udp" => (
            eth_derived(),
            vlan_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_udp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, vlan, ip, udp, pay)| {
                PacketSpec::new(vec![eth, vlan, ip, udp], Some(pay))
            })
            .boxed(),
        "eth-vlan-ipv6-tcp" => (
            eth_derived(),
            vlan_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_tcp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, vlan, ip, tcp, pay)| {
                PacketSpec::new(vec![eth, vlan, ip, tcp], Some(pay))
            })
            .boxed(),
        "eth-vlan-ipv6-icmpv6" => (
            eth_derived(),
            vlan_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_icmpv6::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, vlan, ip, icmp, pay)| {
                PacketSpec::new(vec![eth, vlan, ip, icmp], Some(pay))
            })
            .boxed(),
        "eth-ipv6-udp" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_udp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, udp, pay)| PacketSpec::new(vec![eth, ip, udp], Some(pay)))
            .boxed(),
        "eth-ipv6-tcp" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_tcp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, tcp, pay)| PacketSpec::new(vec![eth, ip, tcp], Some(pay)))
            .boxed(),
        "eth-ipv6-icmpv6" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_icmpv6::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, icmp, pay)| PacketSpec::new(vec![eth, ip, icmp], Some(pay)))
            .boxed(),
        "ipv6" => (wrex_proto_ip6::strategy::strategy(), payload())
            .prop_map(|(ip, pay)| PacketSpec::new(vec![ip], Some(pay)))
            .boxed(),
        other => panic!("unknown stack `{other}` (valid: {})", STACKS.join(", ")),
    }
}

/// Fixed-ish eth spec helper for corpus/harness glue.
pub fn layer(kind: &'static str, fields: &[(&'static str, Value)]) -> LayerSpec {
    let mut map = std::collections::BTreeMap::new();
    for (k, v) in fields {
        map.insert(k.to_string(), v.clone());
    }
    LayerSpec::with_fields(kind, map)
}
