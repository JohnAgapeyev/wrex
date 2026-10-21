//! [`ProberSession`]: the tranche-6b recording prober over the frozen
//! [`wrex_session::Session`] contract.
//!
//! State per probe (pending → in-flight → resolved) mirrors the scan
//! session: **send** at the scheduled instant (pacing + seeded
//! jitter, `--concurrent` cap), **match** replies against the
//! in-flight table by 4-tuple (tcp/udp) or echo id (icmp) — the key
//! is derived from the *post-mutation* dissection so a mutation that
//! moved the identity still matches its own replies — **retransmit**
//! the same bytes on timeout while attempts remain, and **record**
//! one [`Finding`] per probe: the matched reply (with reply bytes),
//! an ICMP-unreachable attribution, or silence.

use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use bytes::Bytes;
use wrex_core::Registry;
use wrex_core::dissect::{LayerView, dissect};
use wrex_core::value::Value;
use wrex_io::{Frame, Rng};
use wrex_mut::Mutator;
use wrex_session::{Session, SessionAction};

use wrex_scan::target::{Family, ScanAddr};

use crate::config::{FuzzConfig, ProbeMode};
use crate::report::{Finding, Outcome};

/// Minimum spacing between probe sends after jitter clamping
/// (mirrors the scan session).
const MIN_STEP: Duration = Duration::from_millis(1);

/// Our source-port range for tcp/udp probes (Linux ephemeral range
/// convention, mirroring the scan session).
const SPORT_LO: u16 = 32768;
const SPORT_HI: u16 = 60999;

/// In-flight probe lookup key (same shape as the scan session's).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ProbeKey {
    /// tcp/udp: a reply (src, sport, dport) == (probe dst, probe dport, probe sport).
    L4 {
        src: ScanAddr,
        dport: u16,
        sport: u16,
    },
    /// icmp/icmpv6 echo: a reply (src, echo id) == (probe dst, probe id).
    Echo { src: ScanAddr, id: u16 },
}

impl ProbeKey {
    /// The pre-mutation identity (the fallback when a mutation broke
    /// dissection).
    fn base(mode: ProbeMode, target: ScanAddr, port: u16, sport: u16, id: u16) -> ProbeKey {
        match mode {
            ProbeMode::Tcp | ProbeMode::Udp => ProbeKey::L4 {
                src: target,
                dport: port,
                sport,
            },
            ProbeMode::Icmp => ProbeKey::Echo { src: target, id },
            // App modes never build raw probe keys (AppSession path).
            ProbeMode::Http | ProbeMode::Dns => {
                unreachable!("app modes do not use ProberSession")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Pending,
    InFlight,
    Resolved,
}

#[derive(Clone, Debug)]
struct Probe {
    key: ProbeKey,
    target: ScanAddr,
    port: Option<u16>,
    round: Option<u32>,
    strategy: &'static str,
    /// Final probe wire bytes (the mutation is baked in; a
    /// retransmission repeats them exactly).
    bytes: Bytes,
    due: Instant,
    deadline: Instant,
    last_sent: Instant,
    attempt: u32,
    phase: Phase,
}

/// The prober state machine. Construct with [`ProberSession::new`];
/// drive with [`wrex_session::run`] or by hand (tests).
pub struct ProberSession<'a> {
    registry: &'a Registry,
    cfg: FuzzConfig,
    now: Instant,
    probes: Vec<Probe>,
    pending: BinaryHeap<std::cmp::Reverse<(Instant, usize)>>,
    inflight: HashMap<ProbeKey, usize>,
    outbox: VecDeque<Bytes>,
    findings: VecDeque<Finding>,
}

impl<'a> ProberSession<'a> {
    /// Build the session: validates the mode's codec kinds, seeds
    /// probe identities and mutation streams, schedules every probe
    /// (pacing + jitter from the seed).
    pub fn new(
        registry: &'a Registry,
        cfg: FuzzConfig,
        src: ScanAddr,
        t0: Instant,
    ) -> Result<Self, String> {
        let family = cfg.family();
        for kind in cfg.mode.needs_for(family) {
            if registry.get(kind).is_none() {
                return Err(format!(
                    "{kind} layer not registered (registered: {})",
                    registry.kinds().join(", ")
                ));
            }
        }
        let mut rng = Rng::new(cfg.seed);
        let mut probes: Vec<Probe> = Vec::new();
        let mut pending = BinaryHeap::new();
        let mut due = t0;

        for &target in &cfg.targets {
            // icmp: one echo slot per target; tcp/udp: one per port.
            let slots: Vec<u16> = match cfg.mode {
                ProbeMode::Icmp => vec![0],
                _ => cfg.ports.clone(),
            };
            for port in slots {
                // Baseline first (when asked), then the mutated rounds.
                let mut rounds: Vec<Option<u32>> = Vec::new();
                if cfg.baseline {
                    rounds.push(None);
                }
                rounds.extend((1..=cfg.rounds).map(Some));
                for round in rounds {
                    // Probe identities draw from the shared stream
                    // (same shape as the scan session).
                    let sport = rng.range_u16(SPORT_LO, SPORT_HI);
                    let seq = (rng.next_u64() >> 32) as u32;
                    let id = (rng.next_u64() & 0xffff) as u16;
                    let base = match cfg.mode {
                        ProbeMode::Tcp => wrex_scan::packet::tcp(
                            registry,
                            src,
                            target,
                            sport,
                            port,
                            seq,
                            None,
                            wrex_scan::packet::FLAG_SYN,
                        ),
                        ProbeMode::Udp => {
                            wrex_scan::packet::udp(registry, src, target, sport, port)
                        }
                        ProbeMode::Icmp => {
                            // Echo protocol follows the family (8 over v4,
                            // 128 over v6).
                            let typ = match target {
                                ScanAddr::V4(_) => 8,
                                ScanAddr::V6(_) => wrex_scan::packet::ICMPV6_ECHO_REQ,
                            };
                            wrex_scan::packet::icmp_echo(registry, src, target, typ, id, 1)
                        }
                        // App modes never reach ProberSession (the verb
                        // routes them to `AppSession`).
                        ProbeMode::Http | ProbeMode::Dns => {
                            unreachable!("app modes do not use ProberSession")
                        }
                    }
                    .map_err(|e| format!("fuzz: probe build: {e}"))?;

                    let (bytes, strategy) = match round {
                        // Baseline: the unmutated base packet.
                        None => (base, "baseline"),
                        Some(r) => {
                            // A per-probe deterministic mutation stream:
                            // the shared rng pins the seed, the round
                            // varies it.
                            let mut_seed = rng.next_u64() ^ (u64::from(r) << 32);
                            let mut mutator = Mutator::new(
                                registry,
                                vec![base.to_vec()],
                                cfg.strategy,
                                mut_seed,
                            )?;
                            (Bytes::from(mutator.next_mutant()), cfg.strategy.as_str())
                        }
                    };

                    // The reply key comes from the *post-mutation*
                    // dissection: a mutation that moved the identity
                    // still matches its own replies. A mutation that
                    // broke dissection falls back to the base identity.
                    let key = probe_key(
                        registry,
                        &bytes,
                        cfg.mode,
                        family,
                        ProbeKey::base(cfg.mode, target, port, sport, id),
                    );
                    let probe = Probe {
                        key,
                        target,
                        port: match cfg.mode {
                            ProbeMode::Icmp => None,
                            _ => Some(port),
                        },
                        round,
                        strategy,
                        bytes,
                        due,
                        deadline: t0,
                        last_sent: t0,
                        attempt: 0,
                        phase: Phase::Pending,
                    };
                    pending.push(std::cmp::Reverse((probe.due, probes.len())));
                    probes.push(probe);
                    due = next_due(&mut rng, due, cfg.interval, cfg.jitter);
                }
            }
        }

        Ok(Self {
            registry,
            cfg,
            now: t0,
            probes,
            pending,
            inflight: HashMap::new(),
            outbox: VecDeque::new(),
            findings: VecDeque::new(),
        })
    }

    /// Resolve probe `idx` with `outcome` (reply bytes / rtt recorded).
    fn resolve(
        &mut self,
        idx: usize,
        outcome: Outcome,
        reply: Option<&[u8]>,
        rtt: Option<Duration>,
    ) {
        let (key, target, port, round, strategy, probe_hex, attempts) = {
            let p = &self.probes[idx];
            (
                p.key,
                p.target,
                p.port,
                p.round,
                p.strategy,
                hex::encode(&p.bytes),
                p.attempt,
            )
        };
        self.probes[idx].phase = Phase::Resolved;
        self.inflight.remove(&key);
        // tcp/udp are family-invariant; the icmp mode speaks icmpv6
        // over v6 targets.
        let proto = match self.cfg.mode {
            ProbeMode::Icmp => self.cfg.family().echo_kind(),
            ProbeMode::Tcp => "tcp",
            ProbeMode::Udp => "udp",
            // Unreachable: the verb routes app modes to `AppSession`.
            ProbeMode::Http | ProbeMode::Dns => {
                unreachable!("app modes do not use ProberSession")
            }
        };
        self.findings.push_back(Finding {
            target,
            port,
            proto,
            round,
            strategy,
            outcome,
            attempts,
            rtt_ms: rtt.map(|d| d.as_millis() as u64),
            probe_hex,
            reply_hex: reply.map(hex::encode),
        });
    }

    /// Handle one dissected incoming frame: a direct reply match
    /// first, then ICMP/ICMPv6-unreachable quote attribution (udp/tcp).
    fn on_reply(&mut self, pkt: &wrex_core::dissect::DissectedPacket, now: Instant, reply: &[u8]) {
        let family = self.cfg.family();
        if let Some(key) = reply_key(self.cfg.mode, pkt, family)
            && let Some(&idx) = self.inflight.get(&key)
        {
            let rtt = now - self.probes[idx].last_sent;
            self.resolve(idx, Outcome::Reply, Some(reply), Some(rtt));
            return;
        }
        // Unreachable attribution (udp/tcp modes, family-aware): the
        // quote rides as the icmp/icmpv6 payload (original IP header +
        // >= 8 bytes of the original L4 header).
        if self.cfg.mode == ProbeMode::Icmp {
            return;
        }
        let Some((unreach, code)) = unreachable_of(pkt, family) else {
            return;
        };
        let Some((q_dst, q_sport, q_dport)) = parse_icmp_quote(family, &pkt.payload) else {
            return;
        };
        let _ = unreach;
        let key = ProbeKey::L4 {
            src: q_dst,
            dport: q_dport,
            sport: q_sport,
        };
        if let Some(&idx) = self.inflight.get(&key) {
            let rtt = now - self.probes[idx].last_sent;
            self.resolve(idx, Outcome::Unreachable(code), None, Some(rtt));
        }
    }
}

impl<'a> Session for ProberSession<'a> {
    type Output = Finding;

    fn on_frame(&mut self, frame: Frame, now: Instant) {
        self.now = now;
        // Drivers yield network-layer-start datagrams; the start kind
        // follows the (grammar-pinned) target family (RawIpDriver for
        // v4, RawIpv6Driver for v6; scripted paths use the same start).
        let start = self.cfg.family().ip_kind();
        let pkt = dissect(self.registry, &frame.bytes, start);
        if !pkt.layers.iter().any(|l| l.kind == start) {
            return; // cross-talk
        }
        let reply = frame.bytes.to_vec();
        self.on_reply(&pkt, now, &reply);
    }

    fn on_timeout(&mut self, now: Instant) {
        self.now = now;
        // Deterministic order: lowest probe index first.
        let mut due: Vec<usize> = self
            .inflight
            .values()
            .copied()
            .filter(|&idx| self.probes[idx].deadline <= now)
            .collect();
        due.sort_unstable();
        for idx in due {
            if self.probes[idx].attempt <= self.cfg.retries {
                // Retransmit the same bytes (the mutation is baked in).
                let bytes = self.probes[idx].bytes.clone();
                let timeout = self.cfg.timeout;
                let p = &mut self.probes[idx];
                p.attempt += 1;
                p.last_sent = now;
                p.deadline = now + timeout;
                self.outbox.push_back(bytes);
            } else {
                self.resolve(idx, Outcome::Silence, None, None);
            }
        }
    }

    fn poll_action(&mut self) -> Option<SessionAction> {
        // Immediate follow-ups first (retransmissions).
        if let Some(bytes) = self.outbox.pop_front() {
            return Some(SessionAction::Send(bytes));
        }
        // Due scheduled probes, while concurrency capacity remains.
        if self.inflight.len() < self.cfg.concurrent
            && let Some(std::cmp::Reverse((due, idx))) = self.pending.peek().copied()
            && due <= self.now
        {
            let bytes = self.probes[idx].bytes.clone();
            self.pending.pop();
            let timeout = self.cfg.timeout;
            let now = self.now;
            let p = &mut self.probes[idx];
            p.phase = Phase::InFlight;
            p.attempt += 1;
            p.last_sent = now;
            p.deadline = now + timeout;
            let key = p.key;
            self.inflight.insert(key, idx);
            return Some(SessionAction::Send(bytes));
        }
        None
    }

    fn next_timeout(&mut self) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        for p in self.probes.iter().filter(|p| p.phase == Phase::InFlight) {
            earliest = Some(earliest.map_or(p.deadline, |e: Instant| e.min(p.deadline)));
        }
        // Scheduled sends matter only while there is capacity for them.
        if self.inflight.len() < self.cfg.concurrent
            && let Some(std::cmp::Reverse((due, _))) = self.pending.peek().copied()
        {
            earliest = Some(earliest.map_or(due, |e: Instant| e.min(due)));
        }
        earliest
    }

    fn poll_result(&mut self) -> Option<Finding> {
        self.findings.pop_front()
    }
}

/// Next scheduled send instant after `prev`: pacing + seeded jitter,
/// clamped so a jittered step never collapses below [`MIN_STEP`]
/// (mirrors the scan session's `next_due`).
fn next_due(rng: &mut Rng, prev: Instant, interval: Duration, jitter: Duration) -> Instant {
    if jitter.is_zero() {
        return prev + interval;
    }
    let off = rng.jitter_secs(jitter);
    let mut step = interval;
    if off > 0.0 {
        step += Duration::from_secs_f64(off);
    } else {
        step = step.saturating_sub(Duration::from_secs_f64(-off));
    }
    if step < MIN_STEP {
        step = MIN_STEP;
    }
    prev + step
}

/// The reply key a probe matches on, derived from the *sent* bytes
/// (post-mutation) with a base fallback. The dissection start follows
/// the configured family (a mutation that broke dissection — or moved
/// the packet to the other family — falls back to the base identity).
fn probe_key(
    registry: &Registry,
    bytes: &[u8],
    mode: ProbeMode,
    family: Family,
    base: ProbeKey,
) -> ProbeKey {
    let pkt = dissect(registry, bytes, family.ip_kind());
    match mode {
        ProbeMode::Tcp | ProbeMode::Udp => {
            let kind = if mode == ProbeMode::Tcp { "tcp" } else { "udp" };
            let Some(l4) = pkt.layers.iter().find(|l| l.kind == kind) else {
                return base;
            };
            let Some(dst) = f_addr(&pkt, family, "dst") else {
                return base;
            };
            let (Some(sport), Some(dport)) = (f_int(l4, "sport"), f_int(l4, "dport")) else {
                return base;
            };
            ProbeKey::L4 {
                src: dst,
                dport: dport as u16,
                sport: sport as u16,
            }
        }
        ProbeMode::Icmp => {
            let echo = family.echo_kind();
            let Some(icmp) = pkt.layers.iter().find(|l| l.kind == echo) else {
                return base;
            };
            let (Some(dst), Some(id)) = (f_addr(&pkt, family, "dst"), f_int(icmp, "echo.id"))
            else {
                return base;
            };
            ProbeKey::Echo {
                src: dst,
                id: id as u16,
            }
        }
        // App modes never derive raw probe keys (AppSession path).
        ProbeMode::Http | ProbeMode::Dns => unreachable!("app modes do not use ProberSession"),
    }
}

/// The reply-side key of a dissected incoming frame, when it is a
/// plausible reply shape for the mode (family-aware).
fn reply_key(
    mode: ProbeMode,
    pkt: &wrex_core::dissect::DissectedPacket,
    family: Family,
) -> Option<ProbeKey> {
    match mode {
        ProbeMode::Tcp | ProbeMode::Udp => {
            let kind = if mode == ProbeMode::Tcp { "tcp" } else { "udp" };
            let l4 = pkt.layers.iter().find(|l| l.kind == kind)?;
            let src = f_addr(pkt, family, "src")?;
            let (Some(sport), Some(dport)) = (f_int(l4, "sport"), f_int(l4, "dport")) else {
                return None;
            };
            Some(ProbeKey::L4 {
                src,
                dport: sport as u16,
                sport: dport as u16,
            })
        }
        ProbeMode::Icmp => {
            // Echo replies: icmp type 0 over v4, icmpv6 type 129 over v6.
            let (echo, reply_type) = match family {
                Family::V4 => ("icmp", 0u128),
                Family::V6 => ("icmpv6", 129),
            };
            let icmp = pkt.layers.iter().find(|l| l.kind == echo)?;
            if f_int(icmp, "type")? != reply_type {
                return None; // echo replies only
            }
            let src = f_addr(pkt, family, "src")?;
            let id = f_int(icmp, "echo.id")?;
            Some(ProbeKey::Echo { src, id: id as u16 })
        }
        // App modes never derive raw reply keys (AppSession path).
        ProbeMode::Http | ProbeMode::Dns => unreachable!("app modes do not use ProberSession"),
    }
}

/// The `(layer kind, code)` of an ICMP/ICMPv6 destination-unreachable
/// error in `pkt`, when one is present (family-aware).
fn unreachable_of(
    pkt: &wrex_core::dissect::DissectedPacket,
    family: Family,
) -> Option<(&'static str, u8)> {
    let (kind, unreach_type) = match family {
        Family::V4 => ("icmp", 3u128),
        // RFC 4443 §3.1: type 1 = destination unreachable.
        Family::V6 => ("icmpv6", 1),
    };
    let icmp = pkt.layers.iter().find(|l| l.kind == kind)?;
    if f_int(icmp, "type")? != unreach_type {
        return None;
    }
    Some((kind, f_int(icmp, "code").unwrap_or(255) as u8))
}

/// Source/destination address of a dissected network-layer header,
/// family-checked (a v4 reply never matches a v6 probe).
fn f_addr(
    pkt: &wrex_core::dissect::DissectedPacket,
    family: Family,
    name: &str,
) -> Option<ScanAddr> {
    let ip = pkt.layers.iter().find(|l| l.kind == family.ip_kind())?;
    match (family, ip.fields.get(name)) {
        (Family::V4, Some(Value::Ipv4(a))) => Some(ScanAddr::V4(*a)),
        (Family::V6, Some(Value::Ipv6(a))) => Some(ScanAddr::V6(*a)),
        _ => None,
    }
}

// --- dissected-field helpers (mirroring the scan session) -------------------

fn f_int(layer: &LayerView, name: &str) -> Option<u128> {
    match layer.fields.get(name) {
        Some(Value::Int(v)) => Some(*v),
        _ => None,
    }
}

/// ICMP/ICMPv6 unreachable quote: `(quoted dst, quoted sport, quoted
/// dport)` from the embedded original datagram (mirrors the scan
/// session's private helpers; v6 quotes carry a fixed 40-byte header).
fn parse_icmp_quote(family: Family, payload: &[u8]) -> Option<(ScanAddr, u16, u16)> {
    match family {
        Family::V4 => {
            if payload.len() < 28 {
                return None; // 20-byte IPv4 header + 8-byte L4 header
            }
            let ihl = (payload[0] & 0x0f) as usize;
            if ihl < 5 {
                return None;
            }
            let hlen = ihl * 4;
            if payload.len() < hlen + 8 {
                return None;
            }
            let dst = ScanAddr::V4(std::net::Ipv4Addr::new(
                payload[16],
                payload[17],
                payload[18],
                payload[19],
            ));
            let sport = u16::from_be_bytes([payload[hlen], payload[hlen + 1]]);
            let dport = u16::from_be_bytes([payload[hlen + 2], payload[hlen + 3]]);
            Some((dst, sport, dport))
        }
        Family::V6 => {
            // RFC 4443 §3.1: as much of the original datagram as fits,
            // never less than the fixed 40-byte IPv6 header.
            if payload.len() < 40 + 8 || payload[0] >> 4 != 6 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&payload[24..40]);
            let dst = ScanAddr::V6(std::net::Ipv6Addr::from(o));
            let sport = u16::from_be_bytes([payload[40], payload[41]]);
            let dport = u16::from_be_bytes([payload[42], payload[43]]);
            Some((dst, sport, dport))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FuzzConfig;
    use std::sync::Arc;
    use wrex_io::{Clock as _, FakeClock, ScriptedDriver};
    use wrex_mut::Strategy;
    use wrex_session::run;

    const MS: Duration = Duration::from_millis(1);
    const SEC: Duration = Duration::from_secs(1);

    fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&wrex_proto_ip::CODEC);
        r.register(&wrex_proto_udp::CODEC);
        r.register(&wrex_proto_tcp::CODEC);
        r.register(&wrex_proto_icmp::CODEC);
        r
    }

    fn src() -> ScanAddr {
        ScanAddr::V4("127.0.0.1".parse().unwrap())
    }

    fn t0() -> Instant {
        Instant::now()
    }

    fn cfg_of(mode: ProbeMode, ports: Option<&str>, rounds: u32, baseline: bool) -> FuzzConfig {
        FuzzConfig::build(
            mode,
            &["127.0.0.1".to_string()],
            ports,
            rounds,
            baseline,
            Strategy::All,
            Duration::ZERO, // burst
            Duration::ZERO,
            0xC0FFEE,
            0, // no retransmissions: timeout == silence
            SEC,
            256,
        )
        .unwrap()
    }

    fn frame(bytes: Vec<u8>) -> Frame {
        Frame {
            bytes: Bytes::from(bytes),
            iface: "lo".into(),
            ts: std::time::SystemTime::UNIX_EPOCH,
        }
    }

    fn drain_sends(s: &mut ProberSession<'_>) -> Vec<Vec<u8>> {
        let mut sent = Vec::new();
        while let Some(SessionAction::Send(bytes)) = s.poll_action() {
            sent.push(bytes.to_vec());
        }
        sent
    }

    fn drain_findings(s: &mut ProberSession<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        while let Some(f) = s.poll_result() {
            out.push(f);
        }
        out
    }

    /// A UDP datagram replying probe `idx`'s *post-mutation* 4-tuple
    /// (built from the probe key, which carries that identity).
    fn udp_reply(reg: &Registry, s: &ProberSession<'_>, idx: usize) -> Vec<u8> {
        let p = &s.probes[idx];
        let (peer, dport, sport) = match p.key {
            ProbeKey::L4 { src, dport, sport } => (src, dport, sport),
            ProbeKey::Echo { src, id } => (src, 0, id),
        };
        wrex_scan::packet::udp(reg, peer, src(), dport, sport)
            .unwrap()
            .to_vec()
    }

    fn sport_of(p: &Probe) -> u16 {
        match p.key {
            ProbeKey::L4 { sport, .. } => sport,
            ProbeKey::Echo { id, .. } => id,
        }
    }

    #[test]
    fn probe_count_and_baseline_order() {
        let reg = registry();
        // baseline + 2 rounds, one port.
        let mut s = ProberSession::new(
            &reg,
            cfg_of(ProbeMode::Udp, Some("53"), 2, true),
            src(),
            t0(),
        )
        .unwrap();
        let sent = drain_sends(&mut s);
        assert_eq!(sent.len(), 3, "baseline + 2 mutated rounds");
        // The baseline probe is the unmutated base packet: a valid,
        // anomaly-free UDP datagram.
        let pkt = dissect(&reg, &sent[0], "ipv4");
        assert!(pkt.anomalies.is_empty(), "{:?}", pkt.anomalies);
        // Rounds carry labels.
        assert_eq!(s.probes[0].strategy, "baseline");
        assert_eq!(s.probes[1].round, Some(1));
        assert_eq!(s.probes[2].round, Some(2));
    }

    #[test]
    fn reply_recorded_with_bytes() {
        let reg = registry();
        let mut s = ProberSession::new(
            &reg,
            cfg_of(ProbeMode::Udp, Some("53"), 1, true),
            src(),
            t0(),
        )
        .unwrap();
        drain_sends(&mut s);
        let reply = udp_reply(&reg, &s, 0);
        s.on_frame(frame(reply.clone()), t0() + 5 * MS);
        let out = drain_findings(&mut s);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].outcome, Outcome::Reply);
        assert_eq!(out[0].reply_hex, Some(hex::encode(&reply)));
        assert_eq!(out[0].strategy, "baseline");
        assert_eq!(out[0].attempts, 1);
        assert!(out[0].rtt_ms.unwrap() >= 5, "{:?}", out[0].rtt_ms);
        assert_eq!(out[0].proto, "udp");
        // Remaining probes resolve on timeout.
        s.on_timeout(t0() + SEC);
        let rest = drain_findings(&mut s);
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].outcome, Outcome::Silence);
        assert!(s.next_timeout().is_none(), "session must go idle");
    }

    #[test]
    fn mutated_probe_matches_its_own_identity() {
        let reg = registry();
        // No baseline: every probe is mutated.
        let mut s = ProberSession::new(
            &reg,
            cfg_of(ProbeMode::Udp, Some("53"), 4, false),
            src(),
            t0(),
        )
        .unwrap();
        let sent = drain_sends(&mut s);
        assert_eq!(sent.len(), 4);
        // Answer every probe on its own post-mutation 4-tuple.
        for idx in 0..sent.len() {
            let reply = udp_reply(&reg, &s, idx);
            s.on_frame(frame(reply), t0() + MS * (idx as u32 + 1));
        }
        let out = drain_findings(&mut s);
        assert_eq!(out.len(), 4, "every mutated probe must resolve");
        assert!(out.iter().all(|f| f.outcome == Outcome::Reply));
        s.on_timeout(t0() + 10 * SEC);
        assert!(s.poll_result().is_none(), "no stragglers");
        assert!(s.next_timeout().is_none());
    }

    #[test]
    fn cross_talk_resolves_nothing() {
        let reg = registry();
        let mut s = ProberSession::new(
            &reg,
            cfg_of(ProbeMode::Udp, Some("53"), 0, true),
            src(),
            t0(),
        )
        .unwrap();
        drain_sends(&mut s);
        let key = {
            let p = &s.probes[0];
            match p.key {
                ProbeKey::L4 { src, dport, .. } => ProbeKey::L4 {
                    src,
                    dport,
                    sport: 65534 - 1,
                },
                ProbeKey::Echo { src, .. } => ProbeKey::Echo { src, id: 65534 },
            }
        };
        let reply = match key {
            ProbeKey::L4 {
                src: their,
                dport,
                sport,
            } => wrex_scan::packet::udp(&reg, their, src(), dport, sport)
                .unwrap()
                .to_vec(),
            ProbeKey::Echo { src: their, id } => {
                wrex_scan::packet::icmp_echo(&reg, their, src(), 0, id, 1)
                    .unwrap()
                    .to_vec()
            }
        };
        s.on_frame(frame(reply), t0());
        assert!(s.poll_result().is_none(), "cross-talk must not resolve");
        s.on_timeout(t0() + 10 * SEC);
        let out = drain_findings(&mut s);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].outcome, Outcome::Silence);
    }

    #[test]
    fn retransmission_repeats_the_same_bytes() {
        let reg = registry();
        let mut cfg = cfg_of(ProbeMode::Tcp, Some("80"), 1, true);
        cfg.retries = 2;
        let mut s = ProberSession::new(&reg, cfg, src(), t0()).unwrap();
        let sent = drain_sends(&mut s);
        assert_eq!(sent.len(), 2);
        for i in 0..2 {
            s.on_timeout(t0() + SEC * (1 + i as u32));
            let resent = drain_sends(&mut s);
            assert_eq!(resent.len(), 2, "both probes retransmit");
            for (r, b) in resent.iter().enumerate() {
                assert_eq!(&sent[r], b, "retransmission is byte-identical");
            }
        }
        // Budget exhausted → silence for both.
        s.on_timeout(t0() + 5 * SEC);
        let out = drain_findings(&mut s);
        assert_eq!(out.len(), 2);
        assert!(
            out.iter()
                .all(|f| f.outcome == Outcome::Silence && f.attempts == 3)
        );
        assert!(s.next_timeout().is_none());
    }

    #[test]
    fn tcp_syn_and_icmp_shapes() {
        let reg = registry();
        // TCP: a SYN+ACK on the probe 4-tuple is a recorded reply.
        let mut s = ProberSession::new(
            &reg,
            cfg_of(ProbeMode::Tcp, Some("443"), 0, true),
            src(),
            t0(),
        )
        .unwrap();
        drain_sends(&mut s);
        let probe = s.probes[0].clone();
        let synack = wrex_scan::packet::tcp(
            &reg,
            probe.target,
            src(),
            probe.port.unwrap(),
            sport_of(&probe),
            0x9955,
            None,
            wrex_scan::packet::FLAG_SYN | wrex_scan::packet::FLAG_ACK,
        )
        .unwrap()
        .to_vec();
        s.on_frame(frame(synack), t0() + 3 * MS);
        let out = drain_findings(&mut s);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].outcome, Outcome::Reply);
        assert_eq!(out[0].proto, "tcp");
        drop(s);

        // ICMP: an echo reply with the probe id is recorded.
        let mut s =
            ProberSession::new(&reg, cfg_of(ProbeMode::Icmp, None, 0, true), src(), t0()).unwrap();
        drain_sends(&mut s);
        let probe = s.probes[0].clone();
        let reply = wrex_scan::packet::icmp_echo(&reg, probe.target, src(), 0, sport_of(&probe), 1)
            .unwrap()
            .to_vec();
        s.on_frame(frame(reply), t0() + 2 * MS);
        let out = drain_findings(&mut s);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].outcome, Outcome::Reply);
        assert_eq!(out[0].proto, "icmp");
        assert_eq!(out[0].port, None);
    }

    #[test]
    fn icmp_unreachable_attribution() {
        let reg = registry();
        let mut s = ProberSession::new(
            &reg,
            cfg_of(ProbeMode::Udp, Some("5353"), 0, true),
            src(),
            t0(),
        )
        .unwrap();
        drain_sends(&mut s);
        let probe = s.probes[0].clone();
        // Quote probe 0's datagram inside an ICMP 3/3 (the wire shape:
        // ipv4 + icmp, quote as the icmp payload).
        let quoted =
            wrex_scan::packet::udp(&reg, src(), probe.target, sport_of(&probe), 5353).unwrap();
        let mk = |pairs: &[(&str, Value)]| -> std::collections::BTreeMap<String, Value> {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect()
        };
        let as4 = |a: ScanAddr| match a {
            ScanAddr::V4(v) => v,
            ScanAddr::V6(_) => unreachable!("v4 test helper"),
        };
        let spec = wrex_core::spec::PacketSpec::new(
            vec![
                wrex_core::spec::LayerSpec::with_fields(
                    "ipv4",
                    mk(&[
                        ("src", Value::Ipv4(as4(probe.target))),
                        ("dst", Value::Ipv4(as4(src()))),
                    ]),
                ),
                wrex_core::spec::LayerSpec::with_fields(
                    "icmp",
                    mk(&[("type", Value::Int(3)), ("code", Value::Int(3))]),
                ),
            ],
            Some(Value::Bytes(quoted)),
        );
        let unreach = wrex_core::encode::encode(
            &reg,
            &spec,
            &wrex_core::encode::EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap()
        .bytes
        .to_vec();
        s.on_frame(frame(unreach), t0() + 4 * MS);
        let out = drain_findings(&mut s);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].outcome, Outcome::Unreachable(3));
        assert_eq!(out[0].reply_hex, None);
    }

    #[test]
    fn same_seed_same_probe_bytes() {
        let reg = registry();
        let cfg = cfg_of(ProbeMode::Udp, Some("53,80"), 4, true);
        let t = t0();
        let a = ProberSession::new(&reg, cfg.clone(), src(), t).unwrap();
        let b = ProberSession::new(&reg, cfg.clone(), src(), t).unwrap();
        let ea: Vec<String> = a.probes.iter().map(|p| hex::encode(&p.bytes)).collect();
        let eb: Vec<String> = b.probes.iter().map(|p| hex::encode(&p.bytes)).collect();
        assert_eq!(ea, eb, "same seed → byte-identical probe stream");
        // Different seed → different stream (over the first few probes).
        let mut cfg2 = cfg;
        cfg2.seed = 0xFACE;
        let c = ProberSession::new(&reg, cfg2, src(), t).unwrap();
        let ec: Vec<String> = c.probes.iter().map(|p| hex::encode(&p.bytes)).collect();
        assert_ne!(ea, ec);
    }

    #[test]
    fn run_loop_end_to_end_with_scripted_driver() {
        // Same seed → identical probe identities: craft replies against
        // a manually-driven twin, then run the real runtime loop.
        let reg = registry();
        let clock = Arc::new(FakeClock::new());
        let t = clock.now();
        let cfg = cfg_of(ProbeMode::Udp, Some("53"), 1, true);

        let twin = ProberSession::new(&reg, cfg.clone(), src(), t).unwrap();
        let mut twin = twin;
        let _sent = {
            let mut sent = Vec::new();
            while let Some(SessionAction::Send(b)) = twin.poll_action() {
                sent.push(b.to_vec());
            }
            sent
        };
        let reply = udp_reply(&reg, &twin, 0);
        // Probe 1 (the mutated round) times out: no reply scripted.
        let mut session = ProberSession::new(&reg, cfg.clone(), src(), t).unwrap();
        let mut driver = ScriptedDriver::new(clock.clone(), vec![reply]);
        let out = run(&mut session, &mut driver, clock.as_ref()).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].outcome, Outcome::Reply);
        assert_eq!(out[0].strategy, "baseline");
        assert_eq!(out[1].outcome, Outcome::Silence);
        assert_eq!(out[1].round, Some(1));
    }
}
