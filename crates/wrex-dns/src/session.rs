//! Query configuration + the bare DNS message builder shared by the
//! kernel transports. Perf-pass 3b moved the default `wrex query`
//! transport onto a kernel UDP socket ([`crate::DnsUdpSession`], the
//! dig-style path — arbitrary L3/L4 crafting stays in the craft/send
//! verbs); the tranche-3 raw-IP session this module carried was
//! deleted with that move.

use std::collections::BTreeMap;
use std::net::IpAddr;

use bytes::Bytes;
use wrex_core::Registry;
use wrex_core::encode::{EncodeOpts, encode};
use wrex_core::spec::{LayerSpec, PacketSpec};
use wrex_core::value::Value;
use wrex_proto_dns::types::{parse_class, parse_type};

/// One validated question.
#[derive(Clone, Debug)]
pub struct QueryConfig {
    /// DNS server address (datagram destination; either family —
    /// tranche 10a: v6 targets query over v6 sockets).
    pub server: IpAddr,
    /// Server port (53 by convention; `--port`).
    pub port: u16,
    /// Question name, dotted presentation form.
    pub name: String,
    /// Question type (canonical grammar: `A`, `MX`, `TXT`, …).
    pub qtype: String,
    /// Question class (`IN` by default).
    pub qclass: String,
    /// Recursion-desired (`wrex query` default: true).
    pub rd: bool,
    /// Extra attempts beyond the first, same query id.
    pub retries: u32,
    /// Per-attempt reply timeout.
    pub timeout: std::time::Duration,
    /// RNG seed (query id + source port).
    pub seed: u64,
}

impl QueryConfig {
    /// Validate the type/class grammar up front (usage → exit 2).
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("query name is empty".to_string());
        }
        if parse_type(&self.qtype).is_none() {
            return Err(format!("unknown dns type `{}`", self.qtype));
        }
        if parse_class(&self.qclass).is_none() {
            return Err(format!("unknown dns class `{}`", self.qclass));
        }
        if self.timeout.is_zero() {
            return Err("query --timeout must be > 0".to_string());
        }
        Ok(())
    }
}

/// Network-layer registry kinds the query chain needs for `server`'s
/// family (tranche 10a: family-aware gating).
pub(crate) const fn kinds_for_family(server: &IpAddr) -> [&'static str; 3] {
    match server {
        IpAddr::V4(_) => ["ipv4", "udp", "dns"],
        IpAddr::V6(_) => ["ipv6", "udp", "dns"],
    }
}

/// Build a bare `[dns]` query message (no L3/L4): what DNS-over-TCP
/// carries inside the RFC 7766 length prefix and DNS-over-UDP sends
/// as the datagram body (perf-pass 3b: both kernel transports send
/// the same bytes; the kernel owns L3/L4). Same seeded identity as
/// the old raw path's dns layer — the query id is the seed's
/// observable.
pub fn build_tcp_query(
    registry: &Registry,
    cfg: &QueryConfig,
    sport: u16,
    id: u16,
) -> Result<Bytes, String> {
    let _ = sport;
    let mut dns_fields = BTreeMap::new();
    dns_fields.insert("id".into(), Value::Int(id as u128));
    if cfg.rd {
        dns_fields.insert("flags.rd".into(), Value::Bool(true));
    }
    dns_fields.insert("qd.0.name".into(), Value::Str(cfg.name.clone().into()));
    dns_fields.insert("qd.0.type".into(), Value::Str(cfg.qtype.clone().into()));
    dns_fields.insert("qd.0.class".into(), Value::Str(cfg.qclass.clone().into()));
    let spec = PacketSpec::new(vec![LayerSpec::with_fields("dns", dns_fields)], None);
    let encoded = encode(
        registry,
        &spec,
        &EncodeOpts {
            autofill: true,
            ..Default::default()
        },
    )
    .map_err(|e| e.to_string())?;
    Ok(encoded.bytes)
}

#[cfg(test)]
pub(crate) mod tests_support {
    //! Helpers shared by the transport session tests (registry
    //! fixture, cfg, t0).

    use super::*;
    use std::time::Duration;

    pub(crate) fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&wrex_proto_ip::CODEC);
        r.register(&wrex_proto_ip6::CODEC);
        r.register(&wrex_proto_udp::CODEC);
        r.register(&wrex_proto_icmp::CODEC);
        r.register(&wrex_proto_icmpv6::CODEC);
        r.register(&wrex_proto_tcp::CODEC);
        r.register(&wrex_proto_dns::CODEC);
        r
    }

    pub(crate) fn cfg() -> QueryConfig {
        QueryConfig {
            server: "127.0.0.1".parse().unwrap(),
            port: 53,
            name: "example.com".to_string(),
            qtype: "A".to_string(),
            qclass: "IN".to_string(),
            rd: true,
            retries: 1,
            timeout: Duration::from_secs(1),
            seed: 0xC0FFEE,
        }
    }

    /// A v6 cfg (tranche 10a): same grammar, `::1` server.
    pub(crate) fn cfg6() -> QueryConfig {
        QueryConfig {
            server: "::1".parse().unwrap(),
            ..cfg()
        }
    }

    pub(crate) fn t0() -> std::time::Instant {
        std::time::Instant::now()
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{cfg, cfg6, registry};
    use super::*;

    #[test]
    fn validate_rejects_bad_grammar() {
        let mut bad = cfg();
        bad.name = String::new();
        assert!(QueryConfig::validate(&bad).is_err());

        let mut bad = cfg();
        bad.qtype = "NOPE".to_string();
        assert!(QueryConfig::validate(&bad).is_err());

        let mut bad = cfg();
        bad.qclass = "NOPE".to_string();
        assert!(QueryConfig::validate(&bad).is_err());

        let mut bad = cfg();
        bad.timeout = std::time::Duration::ZERO;
        assert!(QueryConfig::validate(&bad).is_err());

        assert!(QueryConfig::validate(&cfg()).is_ok());
        assert!(QueryConfig::validate(&cfg6()).is_ok());
    }

    #[test]
    fn bare_query_bytes_match_the_seed() {
        // Same seed ⇒ same id ⇒ byte-identical message; the transport
        // (kernel udp or tcp) changes nothing about the bytes.
        let reg = registry();
        let a = build_tcp_query(&reg, &cfg(), 0, 0x1234).unwrap();
        let b = build_tcp_query(&reg, &cfg(), 0, 0x1234).unwrap();
        assert_eq!(a, b);
        let c = build_tcp_query(&reg, &cfg(), 0, 0x4321).unwrap();
        assert_ne!(a, c, "the id is the seed's observable");
        let d = build_tcp_query(&reg, &cfg6(), 0, 0x1234).unwrap();
        assert_eq!(a, d, "the family lives in the transport, not the bytes");

        // Dissects as dns with the seeded identity + question.
        let pkt = wrex_core::dissect::dissect(&reg, &a, "dns");
        let dns = pkt.layers.iter().find(|l| l.kind == "dns").unwrap();
        use wrex_core::value::Value;
        assert_eq!(
            dns.fields.get("id"),
            Some(&Value::Int(0x1234)),
            "the wire carries the seed-derived id"
        );
        assert_eq!(
            dns.fields.get("qd.0.name"),
            Some(&Value::Str("example.com".into()))
        );
        assert!(matches!(
            dns.fields.get("flags"),
            Some(Value::List(items)) if items.contains(&Value::Str("rd".into()))
        ));
    }
}
