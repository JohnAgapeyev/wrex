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
    "eth-vlan-ipv4-udp-dhcp",
    "eth-vlan-ipv6-udp",
    "eth-vlan-ipv6-tcp",
    "eth-vlan-ipv6-icmpv6",
    "eth-ipv4-udp",
    "eth-ipv4-tcp",
    "eth-ipv4-icmp",
    "eth-ipv4-udp-dhcp",
    "eth-ipv6-udp",
    "eth-ipv6-tcp",
    "eth-ipv6-icmpv6",
    "ipv4",
    "ipv6",
    // Tranche 17a: the v6 extension-header stacks (esp excluded —
    // etherparse stops at esp, the tshark/corpus arms carry it).
    "eth-ipv6-hopopts-tcp",
    "eth-ipv6-hopopts-udp",
    "eth-ipv6-hopopts-icmpv6",
    "eth-ipv6-dstopts-tcp",
    "eth-ipv6-dstopts-udp",
    "eth-ipv6-dstopts-icmpv6",
    "eth-ipv6-routing-tcp",
    "eth-ipv6-routing-udp",
    "eth-ipv6-routing-icmpv6",
    "eth-ipv6-frag-tcp",
    "eth-ipv6-frag-udp",
    "eth-ipv6-frag-icmpv6",
    "eth-ipv6-ah-tcp",
    "eth-ipv6-ah-udp",
    "eth-ipv6-ah-icmpv6",
    "eth-vlan-ipv6-hopopts-tcp",
    "eth-vlan-ipv6-hopopts-udp",
    "eth-vlan-ipv6-hopopts-icmpv6",
    // Tranche 17c: the DHCPv6 stacks (ports pinned 546→547 so the
    // udp dispatch chains into the codec).
    "eth-ipv6-udp-dhcp6",
    "eth-vlan-ipv6-udp-dhcp6",
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

/// Udp spec with client ports pinned (68→67): the dhcp stacks need the
/// port dispatch to chain into the codec (the first fixed-port stack —
/// dns has none; random ports would stay terminal).
fn udp_for_dhcp() -> BoxedStrategy<LayerSpec> {
    wrex_proto_udp::strategy::strategy()
        .prop_map(|mut udp| {
            udp.fields.insert("sport".to_string(), Value::Int(68));
            udp.fields.insert("dport".to_string(), Value::Int(67));
            udp
        })
        .boxed()
}

/// Udp spec with client ports pinned (546→547): the dhcp6 stacks need
/// the port dispatch to chain into the codec (the `udp_for_dhcp`
/// pattern).
fn udp_for_dhcp6() -> BoxedStrategy<LayerSpec> {
    wrex_proto_udp::strategy::strategy()
        .prop_map(|mut udp| {
            udp.fields.insert("sport".to_string(), Value::Int(546));
            udp.fields.insert("dport".to_string(), Value::Int(547));
            udp
        })
        .boxed()
}

/// Frag spec pinned to the unfragmented-carrying shape (offset 0, M 0):
/// the differential chain needs the full stack to dissect, and etherparse
/// treats M=1 as payload fragmentation (no transport slice to compare).
fn frag_unfragmented() -> BoxedStrategy<LayerSpec> {
    wrex_proto_ip6ext::strategy::frag()
        .prop_map(|mut frag| {
            frag.fields.insert("offset".to_string(), Value::Int(0));
            frag.fields.insert("m".to_string(), Value::Int(0));
            frag
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
/// `"eth-ipv4-udp-dhcp"`, `"eth-vlan-ipv4-udp-dhcp"` (ports pinned
/// 68→67 for the udp dispatch),
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
        // DHCP stacks (tranche 7c): the udp ports are pinned so the
        // port dispatch chains into the dhcp codec.
        "eth-ipv4-udp-dhcp" => (
            wrex_proto_eth::strategy::strategy(),
            wrex_proto_ip::strategy::strategy(),
            udp_for_dhcp(),
            wrex_proto_dhcp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, udp, dhcp, pay)| {
                PacketSpec::new(vec![eth, ip, udp, dhcp], Some(pay))
            })
            .boxed(),
        "eth-vlan-ipv4-udp-dhcp" => (
            eth_derived(),
            vlan_derived(),
            wrex_proto_ip::strategy::strategy(),
            udp_for_dhcp(),
            wrex_proto_dhcp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, vlan, ip, udp, dhcp, pay)| {
                PacketSpec::new(vec![eth, vlan, ip, udp, dhcp], Some(pay))
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
        "eth-ipv6-hopopts-tcp" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_ip6ext::strategy::hopopts(),
            wrex_proto_tcp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, ext, l4, pay)| PacketSpec::new(vec![eth, ip, ext, l4], Some(pay)))
            .boxed(),
        "eth-ipv6-hopopts-udp" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_ip6ext::strategy::hopopts(),
            wrex_proto_udp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, ext, l4, pay)| PacketSpec::new(vec![eth, ip, ext, l4], Some(pay)))
            .boxed(),
        "eth-ipv6-hopopts-icmpv6" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_ip6ext::strategy::hopopts(),
            wrex_proto_icmpv6::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, ext, l4, pay)| PacketSpec::new(vec![eth, ip, ext, l4], Some(pay)))
            .boxed(),
        "eth-ipv6-dstopts-tcp" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_ip6ext::strategy::dstopts(),
            wrex_proto_tcp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, ext, l4, pay)| PacketSpec::new(vec![eth, ip, ext, l4], Some(pay)))
            .boxed(),
        "eth-ipv6-dstopts-udp" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_ip6ext::strategy::dstopts(),
            wrex_proto_udp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, ext, l4, pay)| PacketSpec::new(vec![eth, ip, ext, l4], Some(pay)))
            .boxed(),
        "eth-ipv6-dstopts-icmpv6" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_ip6ext::strategy::dstopts(),
            wrex_proto_icmpv6::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, ext, l4, pay)| PacketSpec::new(vec![eth, ip, ext, l4], Some(pay)))
            .boxed(),
        "eth-ipv6-routing-tcp" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_ip6ext::strategy::routing(),
            wrex_proto_tcp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, ext, l4, pay)| PacketSpec::new(vec![eth, ip, ext, l4], Some(pay)))
            .boxed(),
        "eth-ipv6-routing-udp" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_ip6ext::strategy::routing(),
            wrex_proto_udp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, ext, l4, pay)| PacketSpec::new(vec![eth, ip, ext, l4], Some(pay)))
            .boxed(),
        "eth-ipv6-routing-icmpv6" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_ip6ext::strategy::routing(),
            wrex_proto_icmpv6::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, ext, l4, pay)| PacketSpec::new(vec![eth, ip, ext, l4], Some(pay)))
            .boxed(),
        "eth-ipv6-frag-tcp" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            frag_unfragmented(),
            wrex_proto_tcp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, ext, l4, pay)| PacketSpec::new(vec![eth, ip, ext, l4], Some(pay)))
            .boxed(),
        "eth-ipv6-frag-udp" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            frag_unfragmented(),
            wrex_proto_udp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, ext, l4, pay)| PacketSpec::new(vec![eth, ip, ext, l4], Some(pay)))
            .boxed(),
        "eth-ipv6-frag-icmpv6" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            frag_unfragmented(),
            wrex_proto_icmpv6::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, ext, l4, pay)| PacketSpec::new(vec![eth, ip, ext, l4], Some(pay)))
            .boxed(),
        "eth-ipv6-ah-tcp" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_ip6ext::strategy::ah(),
            wrex_proto_tcp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, ext, l4, pay)| PacketSpec::new(vec![eth, ip, ext, l4], Some(pay)))
            .boxed(),
        "eth-ipv6-ah-udp" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_ip6ext::strategy::ah(),
            wrex_proto_udp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, ext, l4, pay)| PacketSpec::new(vec![eth, ip, ext, l4], Some(pay)))
            .boxed(),
        "eth-ipv6-ah-icmpv6" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_ip6ext::strategy::ah(),
            wrex_proto_icmpv6::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, ip, ext, l4, pay)| PacketSpec::new(vec![eth, ip, ext, l4], Some(pay)))
            .boxed(),
        "eth-vlan-ipv6-hopopts-tcp" => (
            eth_derived(),
            vlan_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_ip6ext::strategy::hopopts(),
            wrex_proto_tcp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, vlan, ip, ext, l4, pay)| {
                PacketSpec::new(vec![eth, vlan, ip, ext, l4], Some(pay))
            })
            .boxed(),
        "eth-vlan-ipv6-hopopts-udp" => (
            eth_derived(),
            vlan_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_ip6ext::strategy::hopopts(),
            wrex_proto_udp::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, vlan, ip, ext, l4, pay)| {
                PacketSpec::new(vec![eth, vlan, ip, ext, l4], Some(pay))
            })
            .boxed(),
        "eth-vlan-ipv6-hopopts-icmpv6" => (
            eth_derived(),
            vlan_derived(),
            wrex_proto_ip6::strategy::strategy(),
            wrex_proto_ip6ext::strategy::hopopts(),
            wrex_proto_icmpv6::strategy::strategy(),
            payload(),
        )
            .prop_map(|(eth, vlan, ip, ext, l4, pay)| {
                PacketSpec::new(vec![eth, vlan, ip, ext, l4], Some(pay))
            })
            .boxed(),
        "ipv6" => (wrex_proto_ip6::strategy::strategy(), payload())
            .prop_map(|(ip, pay)| PacketSpec::new(vec![ip], Some(pay)))
            .boxed(),
        // DHCPv6 stacks (tranche 17c): the udp ports are pinned so the
        // port dispatch chains into the dhcp6 codec (the 7c pattern).
        // No payload: dhcp6 is the terminal layer and v6 has no end
        // marker (the v4 `end` precedent made a random tail payload
        // safe there) — a random tail would read as garbage TLVs and
        // anomaly on our own layer.
        "eth-ipv6-udp-dhcp6" => (
            eth_derived(),
            wrex_proto_ip6::strategy::strategy(),
            udp_for_dhcp6(),
            wrex_proto_dhcp6::strategy::strategy(),
        )
            .prop_map(|(eth, ip, udp, dhcp6)| PacketSpec::new(vec![eth, ip, udp, dhcp6], None))
            .boxed(),
        "eth-vlan-ipv6-udp-dhcp6" => (
            eth_derived(),
            vlan_derived(),
            wrex_proto_ip6::strategy::strategy(),
            udp_for_dhcp6(),
            wrex_proto_dhcp6::strategy::strategy(),
        )
            .prop_map(|(eth, vlan, ip, udp, dhcp6)| {
                PacketSpec::new(vec![eth, vlan, ip, udp, dhcp6], None)
            })
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
