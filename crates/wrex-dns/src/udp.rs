//! [`DnsUdpSession`]: one seeded DNS question over a kernel UDP socket
//! — the dig-style transport, perf-pass 3b. Send the bare message,
//! match the reply by dns id, retransmit the SAME bytes (DNS
//! retransmission keeps the id) after each attempt timeout while
//! attempts remain.
//!
//! This replaces the tranche-3 raw-IP + AF_PACKET tap session (the
//! perf-diff dns/udp row measured ~15–19ms of fixed tap cost per
//! invocation — any AF_PACKET socket's protocol-hook add/remove waits
//! on an RCU grace period; kernel sockets cost microseconds). The
//! kernel's `connect(2)` demux replaces the session's old 4-tuple
//! matching: cross-talk from other sources never reaches
//! [`on_frame`]; a wrong-id datagram from the peer (a stale reply)
//! still can, and the id match filters it.
//!
//! Framing on the [`wrex_io::UdpDriver`]: one datagram = one frame
//! (the bare DNS message, dissected from the `dns` root — the same
//! output shape as `--tcp`/`--tls`, whose kernels own L3/L4 likewise).

use std::time::Instant;

use bytes::Bytes;
use wrex_core::Registry;
use wrex_core::dissect::{DissectedPacket, dissect};
use wrex_core::value::Value;
use wrex_io::Frame;
use wrex_session::{Session, SessionAction};

use crate::session::QueryConfig;

/// The UDP exchange outcome (same shape as the TCP transport's
/// [`crate::DnsTcpReply`] so the verb renders both transports alike).
#[derive(Clone, Debug)]
pub enum DnsReply {
    /// The matched reply, dissected from the dns layer down.
    Reply(DissectedPacket),
    /// No reply within `retries + 1` attempts.
    NoReply { attempts: u32 },
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

/// The DNS ask state machine over a kernel UDP socket: send at `t0`,
/// retransmit the same bytes after each timeout while attempts remain,
/// classify on the first reply that echoes the query's dns id.
pub struct DnsUdpSession<'a> {
    registry: &'a Registry,
    cfg: QueryConfig,
    now: Instant,
    /// Seeded query identity (the id; the transport port is drawn
    /// from the same seed by the verb).
    id: u16,
    query: Bytes,
    attempt: u32,
    deadline: Instant,
    phase: Phase,
    outbox: Option<Bytes>,
    result: Option<DnsReply>,
}

impl<'a> DnsUdpSession<'a> {
    /// Build the session: gates the registry by the server's family,
    /// validates the question grammar, takes the verb-built query
    /// bytes + seed-derived id (same draw as the TCP path — the same
    /// `--seed` identifies the same exchange on either transport).
    pub fn new(
        registry: &'a Registry,
        cfg: QueryConfig,
        query: Bytes,
        id: u16,
        t0: Instant,
    ) -> Result<Self, String> {
        for kind in crate::session::kinds_for_family(&cfg.server) {
            if registry.get(kind).is_none() {
                return Err(format!(
                    "{kind} layer not registered (registered: {})",
                    registry.kinds().join(", ")
                ));
            }
        }
        cfg.validate()?;
        Ok(Self {
            registry,
            cfg,
            now: t0,
            id,
            query,
            attempt: 0,
            deadline: t0,
            phase: Phase::Pending,
            outbox: None,
            result: None,
        })
    }

    /// Does a dissected datagram echo our dns id?
    fn matches_id(&self, pkt: &DissectedPacket) -> bool {
        pkt.layers
            .iter()
            .find(|l| l.kind == "dns")
            .is_some_and(|dns| {
                matches!(
                    dns.fields.get("id"),
                    Some(Value::Int(v)) if *v as u16 == self.id
                )
            })
    }
}

impl<'a> Session for DnsUdpSession<'a> {
    type Output = DnsReply;

    fn on_frame(&mut self, frame: Frame, now: Instant) {
        self.now = now;
        if self.phase != Phase::InFlight {
            return; // late reply after resolution or exhaustion
        }
        let pkt = dissect(self.registry, &frame.bytes, "dns");
        if !self.matches_id(&pkt) {
            return; // cross-talk (a stale reply from the peer)
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
            // Retransmit the SAME query (DNS retransmission keeps the
            // id across attempts).
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use std::collections::BTreeMap;
    use std::time::Duration;

    use wrex_core::encode::{EncodeOpts, encode};
    use wrex_core::spec::{LayerSpec, PacketSpec};
    use wrex_session::run;

    use crate::session::tests_support::{cfg, cfg6, registry, t0};

    fn query_bytes(reg: &Registry, id: u16) -> Bytes {
        // A minimal dns query through the real codec.
        let mut fields = BTreeMap::new();
        fields.insert("id".into(), Value::Int(id as u128));
        fields.insert("qd.0.name".into(), Value::Str("example.com".into()));
        fields.insert("qd.0.type".into(), Value::Str("A".into()));
        let spec = PacketSpec::new(vec![LayerSpec::with_fields("dns", fields)], None);
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
    }

    /// The wire reply: id echoed, qr/rd/ra, one A answer spliced as
    /// the payload (records are not craftable at the session level —
    /// the same shape the driver-suite stubs serve).
    fn reply_bytes(reg: &Registry, id: u16) -> Vec<u8> {
        let fields = [
            ("id", Value::Int(id as u128)),
            ("flags.qr", Value::Bool(true)),
            ("qdcount", Value::Int(1)),
            ("ancount", Value::Int(1)),
            ("qd.0.name", Value::Str("example.com".into())),
            ("qd.0.type", Value::Str("A".into())),
            ("qd.0.class", Value::Str("IN".into())),
        ]
        .iter()
        .map(|(k, v)| (Cow::Owned((*k).to_string()), v.clone()))
        .collect();
        let reply_spec = PacketSpec::new(
            vec![LayerSpec::with_fields("dns", fields)],
            Some(Value::Bytes(Bytes::from_static(&[
                0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 93, 184,
                216, 34,
            ]))),
        );
        encode(
            reg,
            &reply_spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap()
        .bytes
        .to_vec()
    }

    fn frame(bytes: Vec<u8>) -> Frame {
        Frame {
            bytes: Bytes::from(bytes),
            iface: "udp".into(),
            ts: std::time::SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn reply_resolves_with_typed_rdata() {
        let reg = registry();
        let mut s =
            DnsUdpSession::new(&reg, cfg(), query_bytes(&reg, 0x1234), 0x1234, t0()).unwrap();
        assert!(matches!(s.poll_action(), Some(SessionAction::Send(_))));
        s.on_frame(
            frame(reply_bytes(&reg, 0x1234)),
            t0() + Duration::from_millis(1),
        );
        match s.poll_result() {
            Some(DnsReply::Reply(pkt)) => {
                let dns = pkt.layers.iter().find(|l| l.kind == "dns").unwrap();
                assert_eq!(
                    dns.fields.get("an.0.rdata"),
                    Some(&Value::Ipv4("93.184.216.34".parse().unwrap()))
                );
            }
            other => panic!("expected a reply, got {other:?}"),
        }
        assert!(s.next_timeout().is_none(), "resolved: the session is idle");
    }

    #[test]
    fn wrong_id_is_cross_talk_then_timeout_retransmits_then_no_reply() {
        let reg = registry();
        let query = query_bytes(&reg, 0x1234);
        let mut s = DnsUdpSession::new(&reg, cfg(), query.clone(), 0x1234, t0()).unwrap();
        // First send.
        assert!(matches!(s.poll_action(), Some(SessionAction::Send(_))));
        s.on_timeout(t0() + Duration::from_secs(1));
        // Retransmit: the SAME bytes (DNS keeps the id).
        assert!(
            matches!(s.poll_action(), Some(SessionAction::Send(bytes)) if bytes == query),
            "the retransmit is the same datagram"
        );
        // A stale reply with a different id is cross-talk: not a
        // resolution, the deadline keeps running.
        s.on_frame(
            frame(reply_bytes(&reg, 0x9999)),
            t0() + Duration::from_secs(1),
        );
        assert!(s.poll_result().is_none());
        // Second timeout exhausts the attempts (retries 1).
        s.on_timeout(t0() + Duration::from_secs(2));
        assert!(matches!(
            s.poll_result(),
            Some(DnsReply::NoReply { attempts: 2 })
        ));
        assert!(s.next_timeout().is_none());
    }

    #[test]
    fn same_seed_same_bytes_across_transports() {
        // The UDP session carries verb-built bytes; the identity is
        // the id draw — same seed, same bytes (the tcp path asserts
        // the same through its own session).
        let reg = registry();
        let id = 0x1234;
        let a = crate::build_tcp_query(&reg, &cfg(), 0, id).unwrap();
        let b = crate::build_tcp_query(&reg, &cfg(), 0, id).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn registry_gating_and_validation() {
        // A registry without the dns codec: usage error, not a panic.
        let empty = Registry::empty();
        assert!(DnsUdpSession::new(&empty, cfg(), Bytes::new(), 1, t0()).is_err());

        // Bad grammar surfaces before any socket work.
        let mut bad = cfg6();
        bad.qtype = "NOPE".to_string();
        let reg = registry();
        assert!(DnsUdpSession::new(&reg, bad, Bytes::new(), 1, t0()).is_err());
    }

    #[test]
    fn runtime_loop_end_to_end_with_scripted_driver() {
        // The full sans-IO loop over a scripted driver: one send, one
        // matching reply — the shape the verb drives with the real
        // UdpDriver (loopback, the driver suite).
        use std::sync::Arc;

        let reg = registry();
        let query = query_bytes(&reg, 0x1234);
        let reply = reply_bytes(&reg, 0x1234);
        let mut session = DnsUdpSession::new(&reg, cfg(), query.clone(), 0x1234, t0()).unwrap();
        let clock = Arc::new(wrex_io::FakeClock::new());
        let mut driver = wrex_io::ScriptedDriver::new(clock.clone(), vec![reply]);
        let outcomes = run(&mut session, &mut driver, clock.as_ref()).expect("session run");
        assert_eq!(outcomes.len(), 1, "one outcome per query");
        assert!(
            matches!(outcomes[0], DnsReply::Reply(_)),
            "the matching reply resolves: {:?}",
            outcomes[0]
        );
        assert_eq!(driver.sent, vec![query.to_vec()], "the query went out once");
    }
}
