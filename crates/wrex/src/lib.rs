#![forbid(unsafe_code)]
//! wrex library facade + protocol registry composition.

pub mod cli;
pub mod edit;
pub mod spec;
pub mod verbs;

pub mod prelude {
    pub use wrex_core::{
        DissectedPacket, EncodeError, LayerSpec, PacketSpec, Registry, SpecError, Value,
    };
}

/// The standard registry: every feature-gated protocol codec.
///
/// ADR 3: each line pulls the crate's `register()` closure, so any
/// feature selection is parent-complete — a lone `--features
/// proto-dns` build registers dns + udp + ipv4/ipv6 + eth/vlan,
/// computed by cargo from the codec dep graph; with no codec
/// features the registry is honestly empty. The fixed line order
/// (self-first closures, dedup-guarded) keeps the registration
/// order — and with it `wrex fields`, man pages and completions —
/// byte-identical.
pub fn standard() -> wrex_core::Registry {
    let mut r = wrex_core::Registry::empty();
    #[cfg(feature = "proto-eth")]
    wrex_proto_eth::register(&mut r);
    #[cfg(feature = "proto-arp")]
    wrex_proto_arp::register(&mut r);
    #[cfg(feature = "proto-vlan")]
    wrex_proto_vlan::register(&mut r);
    #[cfg(feature = "proto-ip")]
    wrex_proto_ip::register(&mut r);
    #[cfg(feature = "proto-ip6")]
    wrex_proto_ip6::register(&mut r);
    #[cfg(feature = "proto-ip6ext")]
    wrex_proto_ip6ext::register(&mut r);
    #[cfg(feature = "proto-icmp")]
    wrex_proto_icmp::register(&mut r);
    #[cfg(feature = "proto-icmpv6")]
    wrex_proto_icmpv6::register(&mut r);
    #[cfg(feature = "proto-udp")]
    wrex_proto_udp::register(&mut r);
    #[cfg(feature = "proto-tcp")]
    wrex_proto_tcp::register(&mut r);
    #[cfg(feature = "proto-dns")]
    wrex_proto_dns::register(&mut r);
    #[cfg(feature = "proto-dhcp")]
    wrex_proto_dhcp::register(&mut r);
    r
}
