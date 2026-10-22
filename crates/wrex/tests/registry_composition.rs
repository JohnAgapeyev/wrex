//! ADR 3 registry-composition invariants.
//!
//! The codec dep graph makes child-without-parent unbuildable and the
//! per-crate `register()` closures make it unconstructible through the
//! documented seam. These tests pin the guarantee at both levels.
//!
//! Note on feature unification: the `wrex-test` dev-dependency (the
//! corpus/oracle crate) depends on `wrex` with default features, so
//! *any* `cargo test -p wrex` build unifies all codec features on and
//! the per-feature cfg gates below always fire in-tree. The genuinely
//! lean selections are verified by the CI lean-build job (runtime
//! `wrex fields` smokes against the lean binaries) and by the
//! per-crate `register()` dispatch tests in the codec crates
//! themselves, which construct the closure directly.

use wrex::standard;

/// No registered kind dangles: every parent resolves in the same
/// registry. Feature-agnostic — it verifies the closure of whatever
/// feature set was selected.
#[test]
fn no_dangling_parents() {
    let r = standard();
    for kind in r.kinds() {
        let schema = r.schema(kind).expect("registered kind resolves");
        for parent in schema.parents {
            assert!(
                r.get(parent).is_some(),
                "kind `{kind}` is registered without its parent `{parent}` — \
                 the ADR 3 closure is broken"
            );
        }
    }
}

/// The all-codecs registration order is pinned: the enumeration
/// surfaces (`wrex fields`, the man pages, completions, the
/// "(registered: …)" usage errors) are registration-ordered, and the
/// self-first `register()` closures must keep them byte-identical.
#[cfg(all(
    feature = "proto-eth",
    feature = "proto-arp",
    feature = "proto-vlan",
    feature = "proto-ip",
    feature = "proto-ip6",
    feature = "proto-ip6ext",
    feature = "proto-icmp",
    feature = "proto-icmpv6",
    feature = "proto-udp",
    feature = "proto-tcp",
    feature = "proto-dns",
    feature = "proto-dhcp",
    feature = "proto-dhcp6"
))]
#[test]
fn standard_registration_order_pinned() {
    let r = standard();
    assert_eq!(
        r.kinds(),
        &[
            "eth", "arp", "vlan", "ipv4", "ipv6", "hopopts", "dstopts", "routing", "frag", "ah",
            "esp", "nonext", "icmp", "icmpv6", "udp", "tcp", "dns", "dhcp", "dhcp6",
        ]
    );
}

/// A single crate's `register()` closure is parent-complete (the
/// whole chain the codec dep graph guarantees) and idempotent (a
/// second call registers nothing — the dedup guard).
macro_rules! closure_test {
    ($name:ident, $feature:literal, $register:path, [$($kind:literal),+ $(,)?]) => {
        #[cfg(feature = $feature)]
        #[test]
        fn $name() {
            let mut r = wrex_core::Registry::empty();
            $register(&mut r);
            for kind in &[$($kind),+] {
                assert!(
                    r.get(kind).is_some(),
                    "the closure must pull `{kind}` along its parent chain"
                );
            }
            let after_first: Vec<&str> = r.kinds().to_vec();
            $register(&mut r);
            assert_eq!(
                r.kinds(),
                after_first,
                "re-registration must be a no-op (dedup guard)"
            );
        }
    };
}

closure_test!(eth_closure, "proto-eth", wrex_proto_eth::register, ["eth"]);
closure_test!(
    vlan_closure,
    "proto-vlan",
    wrex_proto_vlan::register,
    ["vlan", "eth"]
);
closure_test!(
    arp_closure,
    "proto-arp",
    wrex_proto_arp::register,
    ["arp", "eth", "vlan"]
);
closure_test!(
    ip_closure,
    "proto-ip",
    wrex_proto_ip::register,
    ["ipv4", "eth", "vlan"]
);
closure_test!(
    ip6_closure,
    "proto-ip6",
    wrex_proto_ip6::register,
    ["ipv6", "eth", "vlan"]
);
closure_test!(
    ip6ext_closure,
    "proto-ip6ext",
    wrex_proto_ip6ext::register,
    [
        "hopopts", "dstopts", "routing", "frag", "ah", "esp", "nonext", "ipv6", "eth", "vlan"
    ]
);
closure_test!(
    icmp_closure,
    "proto-icmp",
    wrex_proto_icmp::register,
    ["icmp", "ipv4", "eth", "vlan"]
);
closure_test!(
    icmpv6_closure,
    "proto-icmpv6",
    wrex_proto_icmpv6::register,
    [
        "icmpv6", "ipv6", "hopopts", "dstopts", "routing", "frag", "ah", "esp", "nonext", "eth",
        "vlan"
    ]
);
closure_test!(
    udp_closure,
    "proto-udp",
    wrex_proto_udp::register,
    [
        "udp", "ipv4", "ipv6", "hopopts", "dstopts", "routing", "frag", "ah", "esp", "nonext",
        "eth", "vlan"
    ]
);
closure_test!(
    tcp_closure,
    "proto-tcp",
    wrex_proto_tcp::register,
    [
        "tcp", "ipv4", "ipv6", "hopopts", "dstopts", "routing", "frag", "ah", "esp", "nonext",
        "eth", "vlan"
    ]
);
closure_test!(
    dns_closure,
    "proto-dns",
    wrex_proto_dns::register,
    [
        "dns", "udp", "ipv4", "ipv6", "hopopts", "dstopts", "routing", "frag", "ah", "esp",
        "nonext", "eth", "vlan"
    ]
);
closure_test!(
    dhcp_closure,
    "proto-dhcp",
    wrex_proto_dhcp::register,
    [
        "dhcp", "udp", "ipv4", "ipv6", "hopopts", "dstopts", "routing", "frag", "ah", "esp",
        "nonext", "eth", "vlan"
    ]
);

closure_test!(
    dhcp6_closure,
    "proto-dhcp6",
    wrex_proto_dhcp6::register,
    ["dhcp6", "udp", "ipv4", "ipv6", "eth", "vlan"]
);
