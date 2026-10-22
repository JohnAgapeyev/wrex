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
pub fn standard() -> wrex_core::Registry {
    let mut r = wrex_core::Registry::empty();
    #[cfg(feature = "proto-eth")]
    r.register(&wrex_proto_eth::CODEC);
    #[cfg(feature = "proto-arp")]
    r.register(&wrex_proto_arp::CODEC);
    #[cfg(feature = "proto-vlan")]
    r.register(&wrex_proto_vlan::CODEC);
    #[cfg(feature = "proto-ip")]
    r.register(&wrex_proto_ip::CODEC);
    #[cfg(feature = "proto-ip6")]
    r.register(&wrex_proto_ip6::CODEC);
    #[cfg(feature = "proto-icmp")]
    r.register(&wrex_proto_icmp::CODEC);
    #[cfg(feature = "proto-icmpv6")]
    r.register(&wrex_proto_icmpv6::CODEC);
    #[cfg(feature = "proto-udp")]
    r.register(&wrex_proto_udp::CODEC);
    #[cfg(feature = "proto-tcp")]
    r.register(&wrex_proto_tcp::CODEC);
    #[cfg(feature = "proto-dns")]
    r.register(&wrex_proto_dns::CODEC);
    #[cfg(feature = "proto-dhcp")]
    r.register(&wrex_proto_dhcp::CODEC);
    r
}
