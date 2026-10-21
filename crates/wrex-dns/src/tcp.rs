//! [`DnsTcpSession`]: DNS over TCP (RFC 7766) — the two-byte length
//! prefix framing on a stream — over the frozen Session contract.
//!
//! The exchange rides one [`wrex_io::TcpDriver`] connection (kernel
//! TCP, driver-side connect); retries are verb-level (a fresh
//! connection per attempt, per RFC 7766 §6.2.1's guidance for failed
//! TCP exchanges). Stream conventions: chunks in via `on_frame`,
//! **orderly EOF as an empty frame**.

use std::time::Instant;

use bytes::{Bytes, BytesMut};

use wrex_core::Registry;
use wrex_core::dissect::{DissectedPacket, dissect};
use wrex_io::Frame;
use wrex_session::{Session, SessionAction};

use crate::session::QueryConfig;

/// The DNS-over-TCP exchange outcome (same shape as the UDP session's
/// [`crate::DnsReply`] so the verb renders both transports alike).
#[derive(Clone, Debug)]
pub enum DnsTcpReply {
    /// The matched reply, dissected from the dns layer down.
    Reply(DissectedPacket),
    /// Orderly close (or reset) before a complete message arrived.
    Truncated { got: usize, want: u16 },
    /// No reply within the attempt timeout.
    NoReply,
}

// (`got` is `usize`: the truncated-message byte count, unclamped.)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Length prefix (2 bytes) not complete yet.
    ReadingLen,
    /// Message body: `remaining` bytes to go.
    ReadingMsg {
        remaining: u16,
    },
    Done,
}

/// Length-prefixed DNS over one TCP stream.
pub struct DnsTcpSession<'a> {
    registry: &'a Registry,
    _cfg: QueryConfig,
    id: u16,
    query: Bytes,
    now: Instant,
    deadline: Instant,
    sent: bool,
    phase: Phase,
    buf: BytesMut,
    result: Option<DnsTcpReply>,
}

impl<'a> DnsTcpSession<'a> {
    /// Build the session: reuses the UDP path's seeded query bytes
    /// (same id, same question) so `--tcp` changes only the transport.
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
        let deadline = t0 + cfg.timeout;
        Ok(Self {
            registry,
            _cfg: cfg,
            id,
            query,
            now: t0,
            deadline,
            sent: false,
            phase: Phase::ReadingLen,
            buf: BytesMut::new(),
            result: None,
        })
    }

    fn finish(&mut self, outcome: DnsTcpReply) {
        self.phase = Phase::Done;
        self.result = Some(outcome);
    }
}

impl<'a> Session for DnsTcpSession<'a> {
    type Output = DnsTcpReply;

    fn on_frame(&mut self, frame: Frame, now: Instant) {
        self.now = now;
        if self.phase == Phase::Done {
            return; // late bytes
        }
        if frame.bytes.is_empty() {
            // Orderly EOF mid-exchange: report how much was seen.
            let want = match self.phase {
                Phase::ReadingMsg { remaining } => remaining,
                Phase::ReadingLen => 0,
                Phase::Done => 0,
            };
            self.finish(DnsTcpReply::Truncated {
                got: self.buf.len().min(u16::MAX as usize),
                want,
            });
            return;
        }
        self.buf.extend_from_slice(&frame.bytes);
        loop {
            match self.phase {
                Phase::ReadingLen => {
                    if self.buf.len() < 2 {
                        return;
                    }
                    let len = u16::from_be_bytes([self.buf[0], self.buf[1]]);
                    let _ = self.buf.split_to(2);
                    self.phase = Phase::ReadingMsg { remaining: len };
                }
                Phase::ReadingMsg { remaining } => {
                    if self.buf.len() < remaining as usize {
                        return;
                    }
                    let msg = self.buf.split_to(remaining as usize).freeze();
                    let pkt = dissect(self.registry, &msg, "dns");
                    let matched = pkt
                        .layers
                        .iter()
                        .find(|l| l.kind == "dns")
                        .is_some_and(|dns| {
                            matches!(
                                dns.fields.get("id"),
                                Some(wrex_core::value::Value::Int(v)) if *v as u16 == self.id
                            )
                        });
                    if matched {
                        self.finish(DnsTcpReply::Reply(pkt));
                    } else {
                        // Wrong id: cross-talk on the wire; keep reading
                        // for our message until the deadline.
                        self.phase = Phase::ReadingLen;
                    }
                }
                Phase::Done => return,
            }
        }
    }

    fn on_timeout(&mut self, now: Instant) {
        self.now = now;
        if self.phase == Phase::Done {
            return;
        }
        self.finish(DnsTcpReply::NoReply);
    }

    fn poll_action(&mut self) -> Option<SessionAction> {
        if self.sent {
            return None;
        }
        self.sent = true;
        // RFC 7766: two-byte length prefix, then the message.
        let mut wire = BytesMut::with_capacity(self.query.len() + 2);
        wire.extend_from_slice(&(self.query.len() as u16).to_be_bytes());
        wire.extend_from_slice(&self.query);
        Some(SessionAction::Send(wire.freeze()))
    }

    fn next_timeout(&mut self) -> Option<Instant> {
        match self.phase {
            Phase::Done => None,
            _ => Some(self.deadline),
        }
    }

    fn poll_result(&mut self) -> Option<DnsTcpReply> {
        self.result.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use wrex_core::encode::{EncodeOpts, encode};
    use wrex_core::spec::{LayerSpec, PacketSpec};
    use wrex_core::value::Value;

    use std::time::Duration;

    use crate::session::tests_support::{cfg as query_cfg, registry as dns_registry, t0};

    fn query_bytes() -> Bytes {
        // A minimal dns query through the real codec (id 0x1234).
        let mut fields = BTreeMap::new();
        fields.insert("id".to_string(), Value::Int(0x1234));
        fields.insert("qd.0.name".to_string(), Value::Str("example.com".into()));
        fields.insert("qd.0.type".to_string(), Value::Str("A".into()));
        let spec = PacketSpec::new(vec![LayerSpec::with_fields("dns", fields)], None);
        encode(
            &dns_registry(),
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap()
        .bytes
    }

    fn frame(bytes: Vec<u8>) -> Frame {
        Frame {
            bytes: Bytes::from(bytes),
            iface: "tcp".into(),
            ts: std::time::SystemTime::UNIX_EPOCH,
        }
    }

    /// Prefix a dns message with its RFC 7766 length.
    fn prefixed(msg: &[u8]) -> Vec<u8> {
        let mut out = (msg.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(msg);
        out
    }

    #[test]
    fn roundtrip_reply() {
        let reg = dns_registry();
        let mut s = DnsTcpSession::new(&reg, query_cfg(), query_bytes(), 0x1234, t0()).unwrap();
        assert!(s.poll_action().is_some());
        // reply: same id, qr set, one A answer spliced as the payload
        // (records are not craftable at tranche 3)
        let fields = [
            ("id", Value::Int(0x1234)),
            ("flags.qr", Value::Bool(true)),
            ("qdcount", Value::Int(1)),
            ("ancount", Value::Int(1)),
            ("qd.0.name", Value::Str("example.com".into())),
            ("qd.0.type", Value::Str("A".into())),
            ("qd.0.class", Value::Str("IN".into())),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect();
        let reply_spec = PacketSpec::new(
            vec![LayerSpec::with_fields("dns", fields)],
            Some(Value::Bytes(Bytes::from_static(&[
                0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 93, 184,
                216, 34,
            ]))),
        );
        let reply = encode(
            &reg,
            &reply_spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        let wire = prefixed(&reply.bytes);
        // deliver in two chunks + EOF; the reply must match
        s.on_frame(frame(wire[..10].to_vec()), t0() + Duration::from_millis(1));
        s.on_frame(frame(wire[10..].to_vec()), t0() + Duration::from_millis(2));
        s.on_frame(frame(vec![]), t0() + Duration::from_millis(3));
        match s.poll_result() {
            Some(DnsTcpReply::Reply(pkt)) => {
                let dns = pkt.layers.iter().find(|l| l.kind == "dns").unwrap();
                assert_eq!(
                    dns.fields.get("an.0.rdata"),
                    Some(&Value::Ipv4("93.184.216.34".parse().unwrap()))
                );
            }
            other => panic!("expected a reply, got {other:?}"),
        }
        assert!(s.next_timeout().is_none());
    }

    #[test]
    fn eof_and_wrong_id_and_timeout() {
        let reg = dns_registry();
        // EOF mid-prefix
        let mut s = DnsTcpSession::new(&reg, query_cfg(), query_bytes(), 0x1234, t0()).unwrap();
        s.on_frame(frame(vec![0x00]), t0());
        s.on_frame(frame(vec![]), t0());
        assert!(matches!(
            s.poll_result(),
            Some(DnsTcpReply::Truncated { .. })
        ));

        // wrong-id message then EOF: cross-talk never resolves; the
        // deadline fires NoReply.
        let mut s = DnsTcpSession::new(&reg, query_cfg(), query_bytes(), 0x1234, t0()).unwrap();
        let mut wrong = query_bytes().to_vec();
        wrong[0] = 0x99;
        s.on_frame(frame(prefixed(&wrong)), t0());
        assert!(s.poll_result().is_none(), "wrong id must not resolve");
        s.on_frame(frame(vec![]), t0());
        // EOF with nothing of ours → truncated
        assert!(matches!(
            s.poll_result(),
            Some(DnsTcpReply::Truncated { .. })
        ));

        // silence → NoReply at the deadline
        let mut s = DnsTcpSession::new(&reg, query_cfg(), query_bytes(), 0x1234, t0()).unwrap();
        while s.poll_action().is_some() {}
        s.on_timeout(t0() + Duration::from_secs(3));
        assert!(matches!(s.poll_result(), Some(DnsTcpReply::NoReply)));
        assert!(s.next_timeout().is_none());
    }
}
