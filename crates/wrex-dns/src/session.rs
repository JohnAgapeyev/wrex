//! [`DnsSession`]: send one query, match its reply, retransmit with the
//! same dns id while attempts remain.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use bytes::Bytes;
use wrex_core::Registry;
use wrex_core::dissect::{DissectedPacket, dissect};
use wrex_core::encode::{EncodeOpts, encode};
use wrex_core::spec::{LayerSpec, PacketSpec};
use wrex_core::value::Value;
use wrex_io::{Frame, Rng};
use wrex_proto_dns::types::{parse_class, parse_type};
use wrex_session::{Session, SessionAction};

/// One validated question.
#[derive(Clone, Debug)]
pub struct QueryConfig {
    /// DNS server address (datagram destination; either family —
    /// tranche 10a: v6 targets build `ipv6`-rooted queries).
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
    pub timeout: Duration,
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
pub(crate) fn kinds_for_family(server: &IpAddr) -> [&'static str; 3] {
    match server {
        IpAddr::V4(_) => ["ipv4", "udp", "dns"],
        IpAddr::V6(_) => ["ipv6", "udp", "dns"],
    }
}

/// The query outcome: the dissected reply (exit-0 data, whatever the
/// rcode says), or silence after every attempt.
#[derive(Clone, Debug)]
pub enum DnsReply {
    /// The matched reply, dissected from the IP header down.
    Reply(DissectedPacket),
    /// No reply within `retries + 1` attempts.
    NoReply { attempts: u32 },
}

/// The DNS ask state machine: send at `t0`, retransmit the SAME
/// bytes (DNS retransmission keeps the id) after each timeout while
/// attempts remain, classify on the first reply that matches the
/// query's id + 4-tuple.
pub struct DnsSession<'a> {
    registry: &'a Registry,
    cfg: QueryConfig,
    /// Our source address (the `-i` interface address; either family).
    src: IpAddr,
    now: Instant,
    /// Seeded query identity.
    sport: u16,
    id: u16,
    query: Bytes,
    attempt: u32,
    deadline: Instant,
    phase: Phase,
    outbox: Option<Bytes>,
    result: Option<DnsReply>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// First send not yet emitted.
    Pending,
    /// In flight, awaiting a reply or timeout.
    InFlight,
    /// Classified.
    Done,
}

impl<'a> DnsSession<'a> {
    /// Build the session and the query bytes. Fails if the registry
    /// lacks `ipv4`/`udp`/`dns` (registry gating, exit 2) or the
    /// question grammar is invalid.
    pub fn new(
        registry: &'a Registry,
        cfg: QueryConfig,
        src: IpAddr,
        t0: Instant,
    ) -> Result<Self, String> {
        for kind in kinds_for_family(&cfg.server) {
            if registry.get(kind).is_none() {
                return Err(format!(
                    "{kind} layer not registered (registered: {})",
                    registry.kinds().join(", ")
                ));
            }
        }
        cfg.validate()?;

        let mut rng = Rng::new(cfg.seed);
        // Query identity: ephemeral source port + 16-bit dns id.
        let sport = rng.range_u16(32768, 60999);
        let id = (rng.next_u64() & 0xffff) as u16;

        let query = build_query(registry, &cfg, src, sport, id)?;
        Ok(Self {
            registry,
            cfg,
            src,
            now: t0,
            sport,
            id,
            query,
            attempt: 0,
            deadline: t0,
            phase: Phase::Pending,
            outbox: None,
            result: None,
        })
    }

    /// The seeded query bytes (deterministic under a pinned seed).
    pub fn query_bytes(&self) -> &Bytes {
        &self.query
    }

    /// The seeded 16-bit dns id (shared with the TCP transport so the
    /// same seed identifies the same exchange on either wire).
    pub fn query_id(&self) -> u16 {
        self.id
    }

    /// Does a dissected frame match our 4-tuple? Family-aware (10a): the
    /// network layer is `ipv4`/`ipv6` per the source family and the
    /// destination field carries the matching `Value` kind.
    fn matches_udp(&self, pkt: &DissectedPacket) -> bool {
        let ip_kind = match self.src {
            IpAddr::V4(_) => "ipv4",
            IpAddr::V6(_) => "ipv6",
        };
        let Some(ip) = pkt.layers.iter().find(|l| l.kind == ip_kind) else {
            return false;
        };
        let dst_ok = match (&self.src, ip.fields.get("dst")) {
            (IpAddr::V4(src), Some(Value::Ipv4(dst))) => dst == src,
            (IpAddr::V6(src), Some(Value::Ipv6(dst))) => dst == src,
            _ => false,
        };
        if !dst_ok {
            return false;
        }
        let Some(udp) = pkt.layers.iter().find(|l| l.kind == "udp") else {
            return false;
        };
        let (sport, dport) = match (udp.fields.get("sport"), udp.fields.get("dport")) {
            (Some(Value::Int(s)), Some(Value::Int(d))) => (*s as u16, *d as u16),
            _ => return false,
        };
        sport == self.cfg.port && dport == self.sport
    }

    /// Does the dissected frame's dns layer echo our id?
    fn matches_dns(&self, pkt: &DissectedPacket) -> bool {
        let Some(dns) = pkt.layers.iter().find(|l| l.kind == "dns") else {
            return false;
        };
        match dns.fields.get("id") {
            Some(Value::Int(id)) => *id as u16 == self.id,
            _ => false,
        }
    }

    /// Ensure a dns layer exists: the udp port-53 dispatch produces it
    /// for standard ports; a non-53 server port (`--port`, test stubs)
    /// re-roots the udp payload at `dns` so the reply still dissects
    /// ipv4/udp/dns end-to-end.
    fn ensure_dns_layer(&self, pkt: &mut DissectedPacket) {
        if pkt.layers.iter().any(|l| l.kind == "dns") {
            return;
        }
        let dns = dissect(self.registry, &pkt.payload, "dns");
        pkt.layers.extend(dns.layers);
        pkt.anomalies.extend(dns.anomalies);
        pkt.payload = dns.payload;
    }
}

impl<'a> Session for DnsSession<'a> {
    type Output = DnsReply;

    fn on_frame(&mut self, frame: Frame, now: Instant) {
        self.now = now;
        if self.phase != Phase::InFlight {
            return; // late reply after resolution or exhaustion
        }
        let start = match self.src {
            IpAddr::V4(_) => "ipv4",
            IpAddr::V6(_) => "ipv6",
        };
        let mut pkt = dissect(self.registry, &frame.bytes, start);
        if !self.matches_udp(&pkt) {
            return; // cross-talk
        }
        self.ensure_dns_layer(&mut pkt);
        if !self.matches_dns(&pkt) {
            return; // cross-talk (different dns id)
        }
        self.phase = Phase::Done;
        self.result = Some(DnsReply::Reply(pkt));
    }

    fn on_timeout(&mut self, now: Instant) {
        self.now = now;
        if self.phase != Phase::InFlight {
            return;
        }
        if self.attempt <= self.cfg.retries {
            // Retransmit the SAME query (DNS keeps the id across tries).
            self.attempt += 1;
            self.deadline = now + self.cfg.timeout;
            self.outbox = Some(self.query.clone());
        } else {
            self.phase = Phase::Done;
            self.result = Some(DnsReply::NoReply {
                attempts: self.attempt,
            });
        }
    }

    fn poll_action(&mut self) -> Option<SessionAction> {
        if let Some(bytes) = self.outbox.take() {
            return Some(SessionAction::Send(bytes));
        }
        if self.phase == Phase::Pending {
            self.attempt = 1;
            self.phase = Phase::InFlight;
            self.deadline = self.now + self.cfg.timeout;
            return Some(SessionAction::Send(self.query.clone()));
        }
        None
    }

    fn next_timeout(&mut self) -> Option<Instant> {
        match self.phase {
            Phase::Pending | Phase::InFlight => Some(self.deadline),
            Phase::Done => None,
        }
    }

    fn poll_result(&mut self) -> Option<DnsReply> {
        self.result.take()
    }
}

/// Build a bare `[dns]` query message (no L3/L4): what DNS-over-TCP
/// carries inside the RFC 7766 length prefix. Same seeded identity as
/// the UDP query's dns layer.
pub fn build_tcp_query(
    registry: &Registry,
    cfg: &QueryConfig,
    sport: u16,
    id: u16,
) -> Result<Bytes, String> {
    let _ = sport;
    let mut dns_fields = BTreeMap::new();
    dns_fields.insert("id".to_string(), Value::Int(id as u128));
    if cfg.rd {
        dns_fields.insert("flags.rd".to_string(), Value::Bool(true));
    }
    dns_fields.insert("qd.0.name".to_string(), Value::Str(cfg.name.clone()));
    dns_fields.insert("qd.0.type".to_string(), Value::Str(cfg.qtype.clone()));
    dns_fields.insert("qd.0.class".to_string(), Value::Str(cfg.qclass.clone()));
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

/// Build the network-rooted query datagram through the encode engine
/// (autofilled lengths/checksums; the kernel routes it). Family-aware
/// (tranche 10a): `ipv4` (ttl 64) or `ipv6` (hop limit 64) — v4 wire
/// stays byte-identical to the tranche-3 shape.
fn build_query(
    registry: &Registry,
    cfg: &QueryConfig,
    src: IpAddr,
    sport: u16,
    id: u16,
) -> Result<Bytes, String> {
    let mut ip_fields = BTreeMap::new();
    match (&cfg.server, &src) {
        (IpAddr::V4(dst), IpAddr::V4(src)) => {
            ip_fields.insert("src".to_string(), Value::Ipv4(*src));
            ip_fields.insert("dst".to_string(), Value::Ipv4(*dst));
            ip_fields.insert("ttl".to_string(), Value::Int(64));
        }
        (IpAddr::V6(dst), IpAddr::V6(src)) => {
            ip_fields.insert("src".to_string(), Value::Ipv6(*src));
            ip_fields.insert("dst".to_string(), Value::Ipv6(*dst));
            ip_fields.insert("hop_limit".to_string(), Value::Int(64));
        }
        // One family per run: the caller picks `src` from the same
        // family as `server` (the CLI enforces it; mismatched configs
        // cannot build a coherent datagram).
        _ => return Err("query source/server address family mismatch".to_string()),
    }

    let mut udp_fields = BTreeMap::new();
    udp_fields.insert("sport".to_string(), Value::Int(sport as u128));
    udp_fields.insert("dport".to_string(), Value::Int(cfg.port as u128));

    let mut dns_fields = BTreeMap::new();
    dns_fields.insert("id".to_string(), Value::Int(id as u128));
    if cfg.rd {
        dns_fields.insert("flags.rd".to_string(), Value::Bool(true));
    }
    dns_fields.insert("qd.0.name".to_string(), Value::Str(cfg.name.clone()));
    dns_fields.insert("qd.0.type".to_string(), Value::Str(cfg.qtype.clone()));
    dns_fields.insert("qd.0.class".to_string(), Value::Str(cfg.qclass.clone()));

    let spec = PacketSpec::new(
        vec![
            LayerSpec::with_fields(
                match src {
                    IpAddr::V4(_) => "ipv4",
                    IpAddr::V6(_) => "ipv6",
                },
                ip_fields,
            ),
            LayerSpec::with_fields("udp", udp_fields),
            LayerSpec::with_fields("dns", dns_fields),
        ],
        None,
    );
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
    //! Helpers shared by the udp session tests and the tcp session
    //! tests (registry fixture, cfg, src, t0).

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

    pub(crate) fn src() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    /// A v6 source for the v6 cfg (same family).
    pub(crate) fn src6() -> IpAddr {
        "::1".parse().unwrap()
    }

    pub(crate) fn t0() -> Instant {
        Instant::now()
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{cfg, cfg6, registry, src, src6, t0};
    use super::*;

    fn frame(bytes: Vec<u8>) -> Frame {
        Frame {
            bytes: Bytes::from(bytes),
            iface: "lo".into(),
            ts: std::time::SystemTime::UNIX_EPOCH,
        }
    }

    /// Craft the reply a real resolver would send: our 4-tuple, our id,
    /// qr+rd+ra, one A answer. Family-aware (10a): the reply roots at
    /// ipv4 or ipv6 to mirror the session's source family.
    fn reply(reg: &Registry, s: &DnsSession<'_>, rcode: u8, answer: bool) -> Vec<u8> {
        let query = s.query_bytes().to_vec();
        // Echo the query's question verbatim, rewrite header + counts.
        let mut ip_fields = BTreeMap::new();
        match (s.cfg.server, s.src) {
            (std::net::IpAddr::V4(server), std::net::IpAddr::V4(src)) => {
                ip_fields.insert("src".to_string(), Value::Ipv4(server));
                ip_fields.insert("dst".to_string(), Value::Ipv4(src));
            }
            (std::net::IpAddr::V6(server), std::net::IpAddr::V6(src)) => {
                ip_fields.insert("src".to_string(), Value::Ipv6(server));
                ip_fields.insert("dst".to_string(), Value::Ipv6(src));
            }
            _ => panic!("family mismatch in test reply"),
        }
        let ip_kind = match s.src {
            std::net::IpAddr::V4(_) => "ipv4",
            std::net::IpAddr::V6(_) => "ipv6",
        };
        let mut udp_fields = BTreeMap::new();
        udp_fields.insert("sport".to_string(), Value::Int(53));
        udp_fields.insert("dport".to_string(), Value::Int(s.sport as u128));
        let mut dns_fields = BTreeMap::new();
        dns_fields.insert("id".to_string(), Value::Int(s.id as u128));
        dns_fields.insert("flags.qr".to_string(), Value::Bool(true));
        dns_fields.insert("flags.rd".to_string(), Value::Bool(true));
        dns_fields.insert("flags.ra".to_string(), Value::Bool(true));
        dns_fields.insert("rcode".to_string(), Value::Int(rcode as u128));
        dns_fields.insert("qdcount".to_string(), Value::Int(1));
        if answer {
            // Counts may be set explicitly (kept as written); the answer
            // RR itself rides the payload below (records are not
            // craftable at tranche 3).
            dns_fields.insert("ancount".to_string(), Value::Int(1));
        }
        dns_fields.insert("qd.0.name".to_string(), Value::Str("example.com".into()));
        dns_fields.insert("qd.0.type".to_string(), Value::Str("A".into()));
        dns_fields.insert("qd.0.class".to_string(), Value::Str("IN".into()));
        let _ = query;
        let dns = LayerSpec::with_fields("dns", dns_fields);
        let mut spec = PacketSpec::new(
            vec![
                LayerSpec::with_fields(ip_kind, ip_fields),
                LayerSpec::with_fields("udp", udp_fields),
                dns,
            ],
            None,
        );
        if answer {
            // craft cannot emit answer RRs (tranche-3 freeze): the dns
            // layer writes header+question; the answer RR rides the
            // terminal payload (name pointer -> question at offset 12).
            let mut rr = vec![0xC0, 0x0C]; // name -> question
            rr.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
            rr.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // ttl 60
            rr.extend_from_slice(&[0x00, 0x04, 93, 184, 216, 34]); // rdlen 4: 93.184.216.34
            spec.payload = Some(Value::Bytes(Bytes::from(rr)));
        }
        encode(
            reg,
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap()
        .bytes
        .to_vec()
    }

    #[test]
    fn query_shape() {
        let reg = registry();
        let s = DnsSession::new(&reg, cfg(), src(), t0()).unwrap();
        let bytes = s.query_bytes();
        let pkt = dissect(&reg, bytes, "ipv4");
        assert!(pkt.anomalies.is_empty(), "{:?}", pkt.anomalies);
        assert_eq!(
            pkt.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec!["ipv4", "udp", "dns"]
        );
        let dns = &pkt.layers[2];
        assert_eq!(dns.fields.get("id"), Some(&Value::Int(s.id as u128)));
        let udp = &pkt.layers[1];
        assert_eq!(udp.fields.get("dport"), Some(&Value::Int(53)));
        assert_eq!(
            dns.fields.get("qd.0.name"),
            Some(&Value::Str("example.com".into()))
        );
        assert!(matches!(
            dns.fields.get("flags"),
            Some(Value::List(items)) if items.contains(&Value::Str("rd".into()))
        ));
    }

    /// Tranche 10a: a v6 cfg builds an `ipv6 → udp → dns` query, and a
    /// v6-rooted reply with our 4-tuple + id resolves.
    #[test]
    fn query_shape_and_reply_v6() {
        let reg = registry();
        let s = DnsSession::new(&reg, cfg6(), src6(), t0()).unwrap();
        let bytes = s.query_bytes();
        let pkt = dissect(&reg, bytes, "ipv6");
        assert!(pkt.anomalies.is_empty(), "{:?}", pkt.anomalies);
        assert_eq!(
            pkt.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec!["ipv6", "udp", "dns"]
        );
        let ip = &pkt.layers[0];
        assert_eq!(
            ip.fields.get("dst"),
            Some(&Value::Ipv6("::1".parse::<std::net::Ipv6Addr>().unwrap()))
        );
        assert_eq!(ip.fields.get("hop_limit"), Some(&Value::Int(64)));

        // drive: send, then a v6-rooted reply resolves.
        let mut s = DnsSession::new(&reg, cfg6(), src6(), t0()).unwrap();
        while s.poll_action().is_some() {}
        let bytes = reply(&reg, &s, 0, true);
        s.on_frame(frame(bytes), t0() + Duration::from_millis(5));
        assert!(
            matches!(s.poll_result(), Some(DnsReply::Reply(_))),
            "v6 reply must resolve"
        );
        assert!(s.next_timeout().is_none(), "session must go idle");
    }

    /// A v4-rooted reply does not match a v6 session (family cross-talk).
    #[test]
    fn family_cross_talk_ignored() {
        let reg = registry();
        let mut s4 = DnsSession::new(&reg, cfg(), src(), t0()).unwrap();
        while s4.poll_action().is_some() {}
        let mut s6 = DnsSession::new(&reg, cfg6(), src6(), t0()).unwrap();
        while s6.poll_action().is_some() {}
        // The v4 session's reply carries the same id/port shapes but a
        // v4 network layer: the v6 session must not resolve on it.
        let bytes = reply(&reg, &s4, 0, false);
        s6.on_frame(frame(bytes), t0());
        assert!(s6.poll_result().is_none(), "family mismatch is cross-talk");
        // and the v6 session's own reply still resolves.
        let bytes = reply(&reg, &s6, 0, false);
        s6.on_frame(frame(bytes), t0());
        assert!(matches!(s6.poll_result(), Some(DnsReply::Reply(_))));
    }

    #[test]
    fn seed_determinism() {
        let reg = registry();
        let a = DnsSession::new(&reg, cfg(), src(), t0()).unwrap();
        let b = DnsSession::new(&reg, cfg(), src(), t0()).unwrap();
        assert_eq!(a.query_bytes(), b.query_bytes());
        let mut other = cfg();
        other.seed = 1;
        let c = DnsSession::new(&reg, other, src(), t0()).unwrap();
        assert_ne!(a.query_bytes(), c.query_bytes());
    }

    #[test]
    fn reply_resolves_with_typed_rdata() {
        let reg = registry();
        let mut s = DnsSession::new(&reg, cfg(), src(), t0()).unwrap();
        assert!(matches!(s.poll_action(), Some(SessionAction::Send(_))));
        let bytes = reply(&reg, &s, 0, true);
        s.on_frame(frame(bytes), t0() + Duration::from_millis(5));
        match s.poll_result().unwrap() {
            DnsReply::Reply(pkt) => {
                let dns = pkt.layers.iter().find(|l| l.kind == "dns").unwrap();
                assert_eq!(dns.fields.get("an.0.ttl"), Some(&Value::Int(60)));
                assert_eq!(
                    dns.fields.get("an.0.rdata"),
                    Some(&Value::Ipv4("93.184.216.34".parse().unwrap()))
                );
                assert_eq!(dns.fields.get("rcode"), Some(&Value::Int(0)));
            }
            other => panic!("expected a reply, got {other:?}"),
        }
        assert!(s.next_timeout().is_none(), "session must go idle");
    }

    #[test]
    fn nxdomain_is_still_a_reply() {
        // rcode 3 (NXDOMAIN): data, not an error — resolves Reply.
        let reg = registry();
        let mut s = DnsSession::new(&reg, cfg(), src(), t0()).unwrap();
        while s.poll_action().is_some() {}
        let bytes = reply(&reg, &s, 3, false);
        s.on_frame(frame(bytes), t0());
        assert!(matches!(s.poll_result().unwrap(), DnsReply::Reply(_)));
    }

    #[test]
    fn retransmit_same_id_then_noreply() {
        let reg = registry();
        let mut s = DnsSession::new(&reg, cfg(), src(), t0()).unwrap();
        let first = match s.poll_action() {
            Some(SessionAction::Send(b)) => b,
            other => panic!("{other:?}"),
        };
        // timeout → same bytes again
        s.on_timeout(t0() + Duration::from_secs(1));
        let second = match s.poll_action() {
            Some(SessionAction::Send(b)) => b,
            other => panic!("{other:?}"),
        };
        assert_eq!(first, second, "retransmission keeps the id and bytes");
        // exhaust
        s.on_timeout(t0() + Duration::from_secs(2));
        match s.poll_result().unwrap() {
            DnsReply::NoReply { attempts } => assert_eq!(attempts, 2),
            other => panic!("expected NoReply, got {other:?}"),
        }
        assert!(s.next_timeout().is_none());
    }

    #[test]
    fn cross_talk_and_late_replies_ignored() {
        let reg = registry();
        // a *different* session's reply (different seed → different
        // id/port): cross-talk.
        let mut other_cfg = cfg();
        other_cfg.seed = 0x0BAD;
        let other = DnsSession::new(&reg, other_cfg, src(), t0()).unwrap();
        let reg2 = registry();
        let mut s = DnsSession::new(&reg2, cfg(), src(), t0()).unwrap();
        while s.poll_action().is_some() {}
        let foreign = reply(&reg2, &other, 0, false);
        s.on_frame(frame(foreign), t0());
        assert!(s.poll_result().is_none(), "cross-talk must not resolve");
        assert_eq!(s.attempt, 1);
        // resolve by timeout (retransmit, then exhaust), then a late
        // reply does nothing
        s.on_timeout(t0() + Duration::from_secs(2));
        assert!(s.poll_action().is_some(), "retransmit");
        s.on_timeout(t0() + Duration::from_secs(3));
        assert!(matches!(s.poll_result().unwrap(), DnsReply::NoReply { .. }));
        let bytes = reply(&reg2, &s, 0, false);
        s.on_frame(frame(bytes), t0() + Duration::from_secs(4));
        assert!(s.poll_result().is_none());
    }

    #[test]
    fn registry_gating_and_grammar() {
        let mut reg = Registry::empty();
        reg.register(&wrex_proto_ip::CODEC);
        reg.register(&wrex_proto_udp::CODEC);
        let err = match DnsSession::new(&reg, cfg(), src(), t0()) {
            Ok(_) => panic!("query must require the dns codec"),
            Err(e) => e,
        };
        assert!(err.contains("dns layer not registered"), "{err}");
        // bad type grammar
        let mut bad = cfg();
        bad.qtype = "BOGUS".into();
        assert!(DnsSession::new(&registry(), bad, src(), t0()).is_err());
        // bad name
        let mut bad = cfg();
        bad.name = "a..b".into();
        assert!(DnsSession::new(&registry(), bad, src(), t0()).is_err());
    }
}
