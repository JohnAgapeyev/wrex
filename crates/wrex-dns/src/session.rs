//! [`DnsSession`]: send one query, match its reply, retransmit with the
//! same dns id while attempts remain.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
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
    /// DNS server address (datagram destination).
    pub server: Ipv4Addr,
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
    /// Our source IPv4 (the `-i` interface address).
    src: Ipv4Addr,
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
        src: Ipv4Addr,
        t0: Instant,
    ) -> Result<Self, String> {
        for kind in ["ipv4", "udp", "dns"] {
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

    /// Does a dissected frame match our 4-tuple?
    fn matches_udp(&self, pkt: &DissectedPacket) -> bool {
        let Some(ip) = pkt.layers.iter().find(|l| l.kind == "ipv4") else {
            return false;
        };
        match ip.fields.get("dst") {
            Some(Value::Ipv4(dst)) if *dst == self.src => {}
            _ => return false,
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
        let mut pkt = dissect(self.registry, &frame.bytes, "ipv4");
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

/// Build the `[ipv4, udp, dns]` query datagram through the encode
/// engine (autofilled lengths/checksums; the kernel routes it).
fn build_query(
    registry: &Registry,
    cfg: &QueryConfig,
    src: Ipv4Addr,
    sport: u16,
    id: u16,
) -> Result<Bytes, String> {
    let mut ip_fields = BTreeMap::new();
    ip_fields.insert("src".to_string(), Value::Ipv4(src));
    ip_fields.insert("dst".to_string(), Value::Ipv4(cfg.server));
    ip_fields.insert("ttl".to_string(), Value::Int(64));

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
            LayerSpec::with_fields("ipv4", ip_fields),
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
mod tests {
    use super::*;
    use std::time::Duration;

    fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&wrex_proto_ip::CODEC);
        r.register(&wrex_proto_udp::CODEC);
        r.register(&wrex_proto_icmp::CODEC);
        r.register(&wrex_proto_tcp::CODEC);
        r.register(&wrex_proto_dns::CODEC);
        r
    }

    fn cfg() -> QueryConfig {
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

    fn src() -> Ipv4Addr {
        "127.0.0.1".parse().unwrap()
    }

    fn t0() -> Instant {
        Instant::now()
    }

    fn frame(bytes: Vec<u8>) -> Frame {
        Frame {
            bytes: Bytes::from(bytes),
            iface: "lo".into(),
            ts: std::time::SystemTime::UNIX_EPOCH,
        }
    }

    /// Craft the reply a real resolver would send: our 4-tuple, our id,
    /// qr+rd+ra, one A answer.
    fn reply(reg: &Registry, s: &DnsSession<'_>, rcode: u8, answer: bool) -> Vec<u8> {
        let query = s.query_bytes().to_vec();
        // Echo the query's question verbatim, rewrite header + counts.
        let mut ip_fields = BTreeMap::new();
        ip_fields.insert("src".to_string(), Value::Ipv4("127.0.0.1".parse().unwrap()));
        ip_fields.insert("dst".to_string(), Value::Ipv4(src()));
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
                LayerSpec::with_fields("ipv4", ip_fields),
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
        // dissects as ipv4 → udp → dns with the seeded identity
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
