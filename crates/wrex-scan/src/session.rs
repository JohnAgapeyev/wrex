//! [`ScanSession`]: the scan state machine over the frozen
//! [`wrex_session::Session`] contract.
//!
//! State per probe (pending → in-flight → resolved):
//!
//! - **send** at its scheduled instant (pacing + seeded jitter), at most
//!   `--concurrent` in flight;
//! - **match** replies against the in-flight table by 4-tuple
//!   (tcp/udp) or echo id (icmp) — cross-talk frames never resolve a
//!   probe;
//! - **retransmit** on timeout while attempts remain (same identity:
//!   sport/seq/id);
//! - **classify** per the tranche-2 semantics table:
//!
//!   | mode  | reply | state |
//!   |---|---|---|
//!   | syn | SYN+ACK on our 4-tuple (ack = seq+1) | `open` (+RST action) |
//!   | syn | RST | `closed` |
//!   | syn | exhausted | `filtered` |
//!   | connect | SYN+ACK | ACK action, RST action, `open` |
//!   | connect | RST | `closed` |
//!   | connect | exhausted | `filtered` |
//!   | udp | UDP reply on 4-tuple | `open` |
//!   | udp | ICMP 3/3 (quoted datagram matches) | `closed` |
//!   | udp | ICMP 3/{1,2,9,10,13} | `filtered` |
//!   | udp | exhausted | `open\|filtered` |
//!   | udp (v6) | ICMPv6 1/4 (RFC 4443 §3.1 port unreachable) | `closed` |
//!   | udp (v6) | ICMPv6 1/{0,1,2,3,5,6,7} | `filtered` |
//!   | icmp | echo reply (id match) | `alive` |
//!   | icmp | exhausted | `dead` |

use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::time::{Duration, Instant};

use bytes::Bytes;
use wrex_core::Registry;
use wrex_core::dissect::{DissectedPacket, LayerView, dissect};
use wrex_core::value::Value;
use wrex_io::Frame;
use wrex_session::{Session, SessionAction};

use wrex_io::Rng;

use crate::config::{ScanConfig, ScanMode};
use crate::packet;
use crate::report::ScanResult;
use crate::target::ScanAddr;

/// Minimum spacing between probe sends after jitter clamping.
const MIN_STEP: Duration = Duration::from_millis(1);

/// Our source-port range for tcp/udp probes (Linux ephemeral range
/// convention).
const SPORT_LO: u16 = 32768;
const SPORT_HI: u16 = 60999;

/// In-flight probe lookup key. Probe identities are unique per
/// (target, port) — reply matching is unambiguous under concurrency.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ProbeKey {
    /// tcp/udp: reply (src, sport, dport) == (target, probe dport, probe sport).
    L4 {
        src: ScanAddr,
        dport: u16,
        sport: u16,
    },
    /// icmp/icmpv6 echo: reply (src, echo id) == (target, probe id).
    Echo { src: ScanAddr, id: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Scheduled, not yet sent (`due` applies).
    Pending,
    /// Sent, awaiting a reply or timeout (`deadline` applies).
    InFlight,
    /// Classified; result emitted.
    Resolved,
}

#[derive(Clone, Debug)]
struct Probe {
    /// Reply-matching key (mode-appropriate).
    key: ProbeKey,
    target: ScanAddr,
    /// Probed port (tcp/udp).
    port: u16,
    /// Our source port (tcp/udp); echo id for icmp.
    sport: u16,
    /// tcp seq / icmp echo.seq.
    seq: u32,
    /// Scheduled send instant (pending only).
    due: Instant,
    /// Reply deadline (in-flight only).
    deadline: Instant,
    /// Instant of the most recent send (rtt basis).
    last_sent: Instant,
    /// Sends performed (first + retransmissions).
    attempt: u32,
    phase: Phase,
}

/// The scan state machine. Construct with [`ScanSession::new`] (which
/// validates that the mode's codec kinds are registered); drive with
/// [`wrex_session::run`] or by hand (tests).
pub struct ScanSession<'a> {
    registry: &'a Registry,
    cfg: ScanConfig,
    /// Our source address (the `-i` interface address; family matches
    /// the targets).
    src: ScanAddr,
    /// Latest observed instant (events carry time; `poll_action` stays
    /// clock-less per the frozen trait shape).
    now: Instant,
    probes: Vec<Probe>,
    /// Unscheduled sends, earliest first.
    pending: BinaryHeap<std::cmp::Reverse<(Instant, usize)>>,
    /// In-flight probes by reply key.
    inflight: HashMap<ProbeKey, usize>,
    /// Immediate follow-up sends (retransmissions, RST/ACK actions).
    outbox: VecDeque<Bytes>,
    results: VecDeque<ScanResult>,
}

impl<'a> ScanSession<'a> {
    /// Build the session: validates the registry has the mode's codec
    /// kinds, seeds probe identities and schedules every probe's first
    /// send (pacing + jitter from the seed).
    pub fn new(
        registry: &'a Registry,
        cfg: ScanConfig,
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
        if src.family() != family {
            return Err(format!(
                "source address {src} does not match the target family ({})",
                family.ip_kind()
            ));
        }
        let mut rng = Rng::new(cfg.seed);

        let mut probes: Vec<Probe> = Vec::with_capacity(cfg.probe_count());
        let mut pending = BinaryHeap::new();
        let mut due = t0;

        match cfg.mode {
            ScanMode::Icmp => {
                // One echo per target: id per scan, seq per host.
                let id = (rng.next_u64() & 0xffff) as u16;
                for (i, &target) in cfg.targets.iter().enumerate() {
                    let key = ProbeKey::Echo { src: target, id };
                    let probe = Probe {
                        key,
                        target,
                        port: 0,
                        sport: id,
                        seq: (i as u32) & 0xffff,
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
            ScanMode::Syn | ScanMode::Connect | ScanMode::Udp => {
                for &target in &cfg.targets {
                    for &port in &cfg.ports {
                        let sport = rng.range_u16(SPORT_LO, SPORT_HI);
                        let seq = (rng.next_u64() >> 32) as u32;
                        let key = ProbeKey::L4 {
                            src: target,
                            dport: port,
                            sport,
                        };
                        let probe = Probe {
                            key,
                            target,
                            port,
                            sport,
                            seq,
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
        }

        Ok(Self {
            registry,
            cfg,
            src,
            now: t0,
            probes,
            pending,
            inflight: HashMap::new(),
            outbox: VecDeque::new(),
            results: VecDeque::new(),
        })
    }

    /// Classification on timeout per mode.
    const fn timeout_state(&self) -> &'static str {
        match self.cfg.mode {
            ScanMode::Syn | ScanMode::Connect => "filtered",
            ScanMode::Udp => "open|filtered",
            ScanMode::Icmp => "dead",
        }
    }

    /// Probe packet bytes for probe `idx` (first send or retransmission;
    /// the identity is stable).
    fn build_probe(&self, idx: usize) -> Result<Bytes, wrex_core::EncodeError> {
        let p = &self.probes[idx];
        match self.cfg.mode {
            ScanMode::Syn | ScanMode::Connect => packet::tcp(
                self.registry,
                self.src,
                p.target,
                p.sport,
                p.port,
                p.seq,
                None,
                packet::FLAG_SYN,
            ),
            ScanMode::Udp => packet::udp(self.registry, self.src, p.target, p.sport, p.port),
            ScanMode::Icmp => {
                // The echo protocol follows the family (8/0 over v4,
                // 128/129 over v6).
                let typ = match self.cfg.family() {
                    crate::target::Family::V4 => 8,
                    crate::target::Family::V6 => packet::ICMPV6_ECHO_REQ,
                };
                packet::icmp_echo(
                    self.registry,
                    self.src,
                    p.target,
                    typ,
                    p.sport,
                    p.seq as u16,
                )
            }
        }
    }

    /// Mark probe sent (first or retransmission).
    fn mark_sent(&mut self, idx: usize) {
        let now = self.now;
        let timeout = self.cfg.timeout;
        let p = &mut self.probes[idx];
        p.phase = Phase::InFlight;
        p.attempt += 1;
        p.last_sent = now;
        p.deadline = now + timeout;
    }

    /// Resolve probe `idx` with `state`; `rtt` from the reply instant.
    fn resolve(&mut self, idx: usize, state: &'static str, rtt: Option<Duration>) {
        let probe = &mut self.probes[idx];
        probe.phase = Phase::Resolved;
        let attempts = probe.attempt;
        let port = match self.cfg.mode {
            ScanMode::Icmp => None,
            _ => Some(probe.port),
        };
        let target = probe.target;
        let key = probe.key;
        let proto = self.cfg.mode.proto_for(self.cfg.family());
        self.inflight.remove(&key);
        self.results.push_back(ScanResult {
            target,
            port,
            proto,
            state,
            attempts,
            rtt_ms: rtt.map(ScanResult::rtt_from),
        });
    }

    /// RST (syn) or ACK+RST (connect) follow-up for a SYN+ACK reply.
    fn queue_handshake_close(&mut self, idx: usize, their_seq: u32, ack: bool) {
        let p = &self.probes[idx];
        let our_ack = their_seq.wrapping_add(1);
        let seq = p.seq.wrapping_add(1);
        let actions: &[u128] = if ack {
            &[packet::FLAG_ACK, packet::FLAG_RST | packet::FLAG_ACK]
        } else {
            &[packet::FLAG_RST | packet::FLAG_ACK]
        };
        for &flags in actions {
            if let Ok(bytes) = packet::tcp(
                self.registry,
                self.src,
                p.target,
                p.sport,
                p.port,
                seq,
                Some(our_ack),
                flags,
            ) {
                self.outbox.push_back(bytes);
            }
        }
    }

    /// Handle a dissected TCP reply (syn/connect modes).
    fn on_tcp_reply(&mut self, pkt: &DissectedPacket, _ip: &LayerView, now: Instant) {
        let Some(tcp) = pkt.layers.iter().find(|l| l.kind == "tcp") else {
            return;
        };
        let Some(src) = f_addr(pkt, self.cfg.family(), "src") else {
            return;
        };
        let (Some(sport), Some(dport), Some(ack)) =
            (f_int(tcp, "sport"), f_int(tcp, "dport"), f_int(tcp, "ack"))
        else {
            return;
        };
        // Reply 4-tuple → probe key: their sport is our dport.
        let key = ProbeKey::L4 {
            src,
            dport: sport as u16,
            sport: dport as u16,
        };
        let Some(&idx) = self.inflight.get(&key) else {
            return; // cross-talk or late reply
        };
        let names = flag_names(tcp.fields.get("flags"));
        let probe_seq = self.probes[idx].seq;
        if names.contains(&"syn") && names.contains(&"ack") {
            // SYN+ACK must acknowledge our seq (else cross-talk).
            if (ack as u32) != probe_seq.wrapping_add(1) {
                return;
            }
            let their_seq = f_int(tcp, "seq").unwrap_or(0) as u32;
            match self.cfg.mode {
                ScanMode::Syn => self.queue_handshake_close(idx, their_seq, false),
                ScanMode::Connect => self.queue_handshake_close(idx, their_seq, true),
                ScanMode::Udp | ScanMode::Icmp => return,
            }
            let rtt = now - self.probes[idx].last_sent;
            self.resolve(idx, "open", Some(rtt));
        } else if names.contains(&"rst") {
            let rtt = now - self.probes[idx].last_sent;
            self.resolve(idx, "closed", Some(rtt));
        }
        // Other flag combinations are not scan replies.
    }

    /// Handle a dissected UDP-mode reply (UDP reply or ICMP/ICMPv6 error).
    fn on_udp_reply(&mut self, pkt: &DissectedPacket, now: Instant) {
        if let Some(udp) = pkt.layers.iter().find(|l| l.kind == "udp") {
            let Some(src) = f_addr(pkt, self.cfg.family(), "src") else {
                return;
            };
            let (Some(sport), Some(dport)) = (f_int(udp, "sport"), f_int(udp, "dport")) else {
                return;
            };
            let key = ProbeKey::L4 {
                src,
                dport: sport as u16,
                sport: dport as u16,
            };
            if let Some(&idx) = self.inflight.get(&key) {
                // Any UDP datagram on our 4-tuple counts as open.
                let rtt = now - self.probes[idx].last_sent;
                self.resolve(idx, "open", Some(rtt));
            }
            return;
        }
        // ICMP-unreachable attribution (family-aware): the unreachable
        // quotes the original datagram; parse the quote and match by
        // (quoted dst, quoted sport→our dport, quoted dport→our sport).
        let family = self.cfg.family();
        let (layer_kind, quote) = match family {
            crate::target::Family::V4 => {
                let Some(icmp) = pkt.layers.iter().find(|l| l.kind == "icmp") else {
                    return;
                };
                let Some(icmp_type) = f_int(icmp, "type") else {
                    return;
                };
                if icmp_type != 3 {
                    return; // only unreachables carry scan information
                }
                let state = match f_int(icmp, "code").unwrap_or(255) {
                    3 => "closed", // port unreachable
                    1 | 2 | 9 | 10 | 13 => "filtered",
                    _ => return, // other codes carry no scan semantics
                };
                let Some(q) = parse_icmp_quote_v4(&pkt.payload) else {
                    return;
                };
                ("icmp", (state, q))
            }
            crate::target::Family::V6 => {
                let Some(icmp6) = pkt.layers.iter().find(|l| l.kind == "icmpv6") else {
                    return;
                };
                let Some(icmp_type) = f_int(icmp6, "type") else {
                    return;
                };
                // RFC 4443 §3.1: type 1 = destination unreachable.
                if icmp_type != 1 {
                    return;
                }
                // RFC 4443 §3.1 codes (not the v4 type-3 numbering):
                // 4 = port unreachable; the rest are route/policy
                // failures → filtered.
                let state = match f_int(icmp6, "code").unwrap_or(255) {
                    4 => "closed", // port unreachable
                    0 | 1 | 2 | 3 | 5 | 6 | 7 => "filtered",
                    _ => return, // other codes carry no scan semantics
                };
                let Some(q) = parse_icmp_quote_v6(&pkt.payload) else {
                    return;
                };
                ("icmpv6", (state, q))
            }
        };
        let _ = layer_kind;
        let (state, (q_dst, q_sport, q_dport)) = quote;
        let key = ProbeKey::L4 {
            src: q_dst,
            dport: q_dport,
            sport: q_sport,
        };
        let Some(&idx) = self.inflight.get(&key) else {
            return;
        };
        let rtt = now - self.probes[idx].last_sent;
        self.resolve(idx, state, Some(rtt));
    }

    /// Handle a dissected ICMP/ICMPv6-mode reply (echo reply → alive).
    fn on_icmp_reply(&mut self, pkt: &DissectedPacket, now: Instant) {
        let family = self.cfg.family();
        let (layer_kind, echo_reply_type) = match family {
            crate::target::Family::V4 => ("icmp", 0u128),
            crate::target::Family::V6 => ("icmpv6", 129u128),
        };
        let Some(icmp) = pkt.layers.iter().find(|l| l.kind == layer_kind) else {
            return;
        };
        let (Some(src), Some(icmp_type), Some(id)) = (
            f_addr(pkt, family, "src"),
            f_int(icmp, "type"),
            f_int(icmp, "echo.id"),
        ) else {
            return;
        };
        if icmp_type != echo_reply_type {
            return; // echo replies only
        }
        let key = ProbeKey::Echo { src, id: id as u16 };
        if let Some(&idx) = self.inflight.get(&key) {
            let rtt = now - self.probes[idx].last_sent;
            self.resolve(idx, "alive", Some(rtt));
        }
    }
}

impl<'a> Session for ScanSession<'a> {
    type Output = ScanResult;

    fn on_frame(&mut self, frame: Frame, now: Instant) {
        self.now = now;
        // Drivers yield datagrams starting at the network layer; the
        // start kind follows the (grammar-pinned) target family.
        let start = self.cfg.family().ip_kind();
        let pkt = dissect(self.registry, &frame.bytes, start);
        let Some(_ip) = pkt.layers.iter().find(|l| l.kind == start) else {
            return; // cross-talk
        };
        match self.cfg.mode {
            ScanMode::Syn | ScanMode::Connect => self.on_tcp_reply(&pkt, _ip, now),
            ScanMode::Udp => self.on_udp_reply(&pkt, now),
            ScanMode::Icmp => self.on_icmp_reply(&pkt, now),
        }
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
                // Retransmit with the same identity, new deadline.
                let Ok(bytes) = self.build_probe(idx) else {
                    continue;
                };
                self.mark_sent(idx);
                self.outbox.push_back(bytes);
            } else {
                self.resolve(idx, self.timeout_state(), None);
            }
        }
    }

    fn poll_action(&mut self) -> Option<SessionAction> {
        // Immediate follow-ups first (retransmissions, RST/ACK actions).
        if let Some(bytes) = self.outbox.pop_front() {
            return Some(SessionAction::Send(bytes));
        }
        // Due scheduled probes, while concurrency capacity remains.
        if self.inflight.len() < self.cfg.concurrent
            && let Some(std::cmp::Reverse((due, idx))) = self.pending.peek().copied()
            && due <= self.now
        {
            let bytes = self.build_probe(idx).ok()?;
            self.pending.pop();
            self.mark_sent(idx);
            self.inflight.insert(self.probes[idx].key, idx);
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

    fn poll_result(&mut self) -> Option<ScanResult> {
        self.results.pop_front()
    }
}

/// Next scheduled send instant after `prev`: pacing + seeded jitter,
/// clamped so a jittered step never collapses below 1ms (a pure pacing
/// schedule — including burst (`interval == 0`, `jitter == 0`) — is
/// passed through untouched).
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

/// ICMP unreachable quote (v4): `(quoted dst, quoted sport, quoted
/// dport)` from the embedded original IPv4 header + UDP header.
fn parse_icmp_quote_v4(payload: &[u8]) -> Option<(ScanAddr, u16, u16)> {
    if payload.len() < 28 {
        return None; // 20-byte IPv4 header + 8-byte UDP header
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

/// ICMPv6 unreachable quote (RFC 4443 §3.1): `(quoted dst, quoted
/// sport, quoted dport)` from the original IPv6 datagram — a fixed
/// 40-byte header (no options) + 8 bytes of the original UDP header.
fn parse_icmp_quote_v6(payload: &[u8]) -> Option<(ScanAddr, u16, u16)> {
    if payload.len() < 40 + 8 {
        return None;
    }
    if payload[0] >> 4 != 6 {
        return None; // not an IPv6 datagram
    }
    let mut o = [0u8; 16];
    o.copy_from_slice(&payload[24..40]);
    let dst = ScanAddr::V6(std::net::Ipv6Addr::from(o));
    let sport = u16::from_be_bytes([payload[40], payload[41]]);
    let dport = u16::from_be_bytes([payload[42], payload[43]]);
    Some((dst, sport, dport))
}

// --- dissected-field helpers -------------------------------------------------

fn f_int(layer: &LayerView, name: &str) -> Option<u128> {
    match layer.fields.get(name) {
        Some(Value::Int(v)) => Some(*v),
        _ => None,
    }
}

/// Source/destination address of the dissected network-layer header,
/// family-checked (a v4 reply never matches a v6 probe).
fn f_addr(pkt: &DissectedPacket, family: crate::target::Family, name: &str) -> Option<ScanAddr> {
    let ip_kind = family.ip_kind();
    let ip = pkt.layers.iter().find(|l| l.kind == ip_kind)?;
    match (family, ip.fields.get(name)) {
        (crate::target::Family::V4, Some(Value::Ipv4(a))) => Some(ScanAddr::V4(*a)),
        (crate::target::Family::V6, Some(Value::Ipv6(a))) => Some(ScanAddr::V6(*a)),
        _ => None,
    }
}

/// Flag names out of a dissected flags aggregate (`syn,ack` list or raw
/// int mask → MSB-first bit names).
fn flag_names(value: Option<&Value>) -> Vec<&'static str> {
    const NAMES: [&str; 8] = ["cwr", "ece", "urg", "ack", "psh", "rst", "syn", "fin"];
    match value {
        Some(Value::List(items)) => items
            .iter()
            .filter_map(|v| match v {
                Value::Str(s) => NAMES.iter().copied().find(|&n| n == &**s),
                _ => None,
            })
            .collect(),
        Some(Value::Int(mask)) => NAMES
            .iter()
            .enumerate()
            .filter(|&(i, _)| mask & (1 << (7 - i)) != 0)
            .map(|(_, n)| *n)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use wrex_core::encode::EncodeOpts;
    use wrex_core::spec::{LayerSpec, PacketSpec};
    use wrex_io::{Clock as _, FakeClock, ScriptedDriver};
    use wrex_session::run;

    const MS: Duration = Duration::from_millis(1);
    const SEC: Duration = Duration::from_secs(1);

    fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&wrex_proto_ip::CODEC);
        r.register(&wrex_proto_ip6::CODEC);
        r.register(&wrex_proto_icmp::CODEC);
        r.register(&wrex_proto_icmpv6::CODEC);
        r.register(&wrex_proto_udp::CODEC);
        r.register(&wrex_proto_tcp::CODEC);
        r
    }

    fn src() -> ScanAddr {
        ScanAddr::V4("127.0.0.1".parse().unwrap())
    }

    fn src6() -> ScanAddr {
        ScanAddr::V6("::1".parse().unwrap())
    }

    fn t0() -> Instant {
        Instant::now()
    }

    fn cfg_of(mode: ScanMode, ports: &[u16], retries: u32) -> ScanConfig {
        let spec = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        ScanConfig::build(
            mode,
            &["127.0.0.1".to_string()],
            if spec.is_empty() { None } else { Some(&spec) },
            Duration::ZERO, // burst
            Duration::ZERO,
            0xC0FFEE,
            retries,
            SEC,
            256,
        )
        .unwrap()
    }

    fn cfg6_of(mode: ScanMode, ports: &[u16], retries: u32) -> ScanConfig {
        let spec = ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        ScanConfig::build(
            mode,
            &["::1".to_string()],
            if spec.is_empty() { None } else { Some(&spec) },
            Duration::ZERO, // burst
            Duration::ZERO,
            0xC0FFEE,
            retries,
            SEC,
            256,
        )
        .unwrap()
    }

    fn icmp_cfg(retries: u32) -> ScanConfig {
        ScanConfig::build(
            ScanMode::Icmp,
            &["127.0.0.1".to_string()],
            None,
            Duration::ZERO,
            Duration::ZERO,
            0xC0FFEE,
            retries,
            SEC,
            256,
        )
        .unwrap()
    }

    fn icmp6_cfg(retries: u32) -> ScanConfig {
        ScanConfig::build(
            ScanMode::Icmp,
            &["::1".to_string()],
            None,
            Duration::ZERO,
            Duration::ZERO,
            0xC0FFEE,
            retries,
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

    /// TCP reply to probe `idx` (flags/ack chosen by the caller).
    fn tcp_reply(s: &ScanSession<'_>, idx: usize, flags: u128, ack: Option<u32>) -> Vec<u8> {
        let reg = registry();
        let p = &s.probes[idx];
        packet::tcp(&reg, p.target, s.src, p.port, p.sport, 0x9955, ack, flags)
            .unwrap()
            .to_vec()
    }

    fn synack(s: &ScanSession<'_>, idx: usize) -> Vec<u8> {
        let seq = s.probes[idx].seq;
        tcp_reply(
            s,
            idx,
            packet::FLAG_SYN | packet::FLAG_ACK,
            Some(seq.wrapping_add(1)),
        )
    }

    fn rst(s: &ScanSession<'_>, idx: usize) -> Vec<u8> {
        tcp_reply(s, idx, packet::FLAG_RST | packet::FLAG_ACK, None)
    }

    /// Send every due probe (burst) and collect the sent byte payloads.
    fn drain_sends(s: &mut ScanSession<'_>) -> Vec<Vec<u8>> {
        let mut sent = Vec::new();
        while let Some(SessionAction::Send(bytes)) = s.poll_action() {
            sent.push(bytes.to_vec());
        }
        sent
    }

    /// Collect all pending results.
    fn drain_results(s: &mut ScanSession<'_>) -> Vec<ScanResult> {
        let mut out = Vec::new();
        while let Some(r) = s.poll_result() {
            out.push(r);
        }
        out
    }

    #[test]
    fn syn_probe_shape() {
        let reg = registry();
        let mut s = ScanSession::new(&reg, cfg_of(ScanMode::Syn, &[443], 0), src(), t0()).unwrap();
        let sent = drain_sends(&mut s);
        assert_eq!(sent.len(), 1);
        let p = dissect(&reg, &sent[0], "ipv4");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[0].fields.get("proto"), Some(&Value::Int(6)));
        assert!(matches!(
            p.layers[1].fields.get("flags"),
            Some(Value::List(items)) if items == &vec![Value::Str("syn".into())]
        ));
    }

    #[test]
    fn syn_open_closed_filtered() {
        let reg = registry();
        // port 1: SYN+ACK → open; port 2: RST → closed; port 3: silence.
        let mut s =
            ScanSession::new(&reg, cfg_of(ScanMode::Syn, &[1, 2, 3], 0), src(), t0()).unwrap();
        drain_sends(&mut s);
        s.on_frame(frame(synack(&s, 0)), t0() + 5 * MS);
        s.on_frame(frame(rst(&s, 1)), t0() + 6 * MS);
        s.on_timeout(t0() + SEC);
        let out = drain_results(&mut s);
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].port, Some(1));
        assert_eq!(out[0].state, "open");
        assert_eq!(out[0].attempts, 1);
        // rtt basis is wall-clock (Miri runs slow): bound, don't pin.
        assert!(out[0].rtt_ms.unwrap() >= 5, "{:?}", out[0].rtt_ms);
        assert_eq!(out[1].port, Some(2));
        assert_eq!(out[1].state, "closed");
        assert_eq!(out[2].port, Some(3));
        assert_eq!(out[2].state, "filtered");
        assert_eq!(out[2].rtt_ms, None);
        assert!(s.next_timeout().is_none(), "scan must go idle");
    }

    #[test]
    fn syn_queues_rst_after_open() {
        let reg = registry();
        let mut s = ScanSession::new(&reg, cfg_of(ScanMode::Syn, &[443], 0), src(), t0()).unwrap();
        drain_sends(&mut s);
        s.on_frame(frame(synack(&s, 0)), t0() + 3 * MS);
        assert_eq!(drain_results(&mut s)[0].state, "open");
        // exactly one follow-up: RST (+ack), matching 4-tuple
        let sent = drain_sends(&mut s);
        assert_eq!(sent.len(), 1);
        let d = dissect(&reg, &sent[0], "ipv4");
        assert!(matches!(
            d.layers[1].fields.get("flags"),
            Some(Value::List(items)) if items.contains(&Value::Str("rst".into()))
        ));
    }

    #[test]
    fn connect_queues_ack_then_rst() {
        let reg = registry();
        let mut s =
            ScanSession::new(&reg, cfg_of(ScanMode::Connect, &[80], 0), src(), t0()).unwrap();
        drain_sends(&mut s);
        s.on_frame(frame(synack(&s, 0)), t0() + 7 * MS);
        assert_eq!(drain_results(&mut s)[0].state, "open");
        let sent = drain_sends(&mut s);
        assert_eq!(sent.len(), 2, "ACK then RST");
        let ack = dissect(&reg, &sent[0], "ipv4");
        assert!(matches!(
            ack.layers[1].fields.get("flags"),
            Some(Value::List(items)) if items == &vec![Value::Str("ack".into())]
        ));
        let rst = dissect(&reg, &sent[1], "ipv4");
        assert!(matches!(
            rst.layers[1].fields.get("flags"),
            Some(Value::List(items)) if items.contains(&Value::Str("rst".into()))
        ));
    }

    #[test]
    fn retransmission_keeps_identity() {
        let reg = registry();
        let mut s = ScanSession::new(&reg, cfg_of(ScanMode::Syn, &[22], 1), src(), t0()).unwrap();
        let sent = drain_sends(&mut s);
        assert_eq!(sent.len(), 1);
        // deadline passes → one retransmission, byte-identical
        s.on_timeout(t0() + SEC);
        let resent = drain_sends(&mut s);
        assert_eq!(resent.len(), 1);
        assert_eq!(resent[0], sent[0], "retransmission keeps the identity");
        assert_eq!(s.probes[0].attempt, 2);
        // exhausted → filtered
        s.on_timeout(t0() + 2 * SEC);
        let out = drain_results(&mut s);
        assert_eq!(out[0].state, "filtered");
        assert_eq!(out[0].attempts, 2);
        assert!(s.next_timeout().is_none());
    }

    #[test]
    fn late_and_cross_talk_replies_ignored() {
        let reg = registry();
        let mut s = ScanSession::new(&reg, cfg_of(ScanMode::Syn, &[81], 0), src(), t0()).unwrap();
        drain_sends(&mut s);
        s.on_timeout(t0() + SEC);
        // late SYN+ACK after resolution: no double result
        s.on_frame(frame(synack(&s, 0)), t0() + 2 * SEC);
        let out = drain_results(&mut s);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].state, "filtered");
        assert!(s.poll_result().is_none());

        // cross-talk: wrong sport / wrong ack
        let mut s2 = ScanSession::new(&reg, cfg_of(ScanMode::Syn, &[82], 0), src(), t0()).unwrap();
        drain_sends(&mut s2);
        let p = s2.probes[0].clone();
        let reg2 = registry();
        let wrong_port = packet::tcp(
            &reg2,
            p.target,
            src(),
            p.port,
            p.sport.wrapping_add(1),
            7,
            Some(p.seq.wrapping_add(1)),
            packet::FLAG_SYN | packet::FLAG_ACK,
        )
        .unwrap();
        let wrong_ack = packet::tcp(
            &reg2,
            p.target,
            src(),
            p.port,
            p.sport,
            7,
            Some(p.seq.wrapping_add(2)),
            packet::FLAG_SYN | packet::FLAG_ACK,
        )
        .unwrap();
        s2.on_frame(frame(wrong_port.to_vec()), t0());
        s2.on_frame(frame(wrong_ack.to_vec()), t0());
        assert!(s2.poll_result().is_none(), "cross-talk must not resolve");
        assert_eq!(s2.probes[0].phase, Phase::InFlight);
    }

    /// Build an ICMP 3/`code` unreachable quoting probe `idx`'s datagram.
    /// The quote rides as the icmp payload (the wire format: 8-byte
    /// header + the original datagram).
    fn icmp_unreach(s: &ScanSession<'_>, idx: usize, code: u8) -> Vec<u8> {
        let reg = registry();
        let p = &s.probes[idx];
        let quoted = packet::udp(&reg, s.src, p.target, p.sport, p.port).unwrap();
        let mut ip_fields = std::collections::BTreeMap::new();
        ip_fields.insert(
            "src".to_string(),
            Value::Ipv4(match p.target {
                ScanAddr::V4(a) => a,
                ScanAddr::V6(_) => unreachable!("v4 test helper"),
            }),
        );
        ip_fields.insert(
            "dst".to_string(),
            Value::Ipv4(match s.src {
                ScanAddr::V4(a) => a,
                ScanAddr::V6(_) => unreachable!("v4 test helper"),
            }),
        );
        ip_fields.insert("ttl".to_string(), Value::Int(64));
        let mut icmp_fields = std::collections::BTreeMap::new();
        icmp_fields.insert("type".to_string(), Value::Int(3));
        icmp_fields.insert("code".to_string(), Value::Int(code as u128));
        let spec = PacketSpec::new(
            vec![
                LayerSpec::with_fields("ipv4", ip_fields),
                LayerSpec::with_fields("icmp", icmp_fields),
            ],
            Some(Value::Bytes(quoted)),
        );
        wrex_core::encode::encode(
            &reg,
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

    /// UDP reply on probe `idx`'s 4-tuple (optionally a wrong port).
    fn udp_reply(s: &ScanSession<'_>, idx: usize, wrong_port: bool) -> Vec<u8> {
        let reg = registry();
        let p = &s.probes[idx];
        let from_port = if wrong_port {
            p.port.wrapping_add(1)
        } else {
            p.port
        };
        packet::udp(&reg, p.target, s.src, from_port, p.sport)
            .unwrap()
            .to_vec()
    }

    #[test]
    fn udp_open_closed_filtered_openfiltered() {
        let reg = registry();
        let mut s = ScanSession::new(
            &reg,
            cfg_of(ScanMode::Udp, &[5353, 5354, 5355, 5356], 0),
            src(),
            t0(),
        )
        .unwrap();
        drain_sends(&mut s);
        s.on_frame(frame(udp_reply(&s, 0, false)), t0() + 4 * MS);
        s.on_frame(frame(icmp_unreach(&s, 1, 3)), t0() + 5 * MS);
        s.on_frame(frame(icmp_unreach(&s, 2, 1)), t0() + 6 * MS);
        s.on_timeout(t0() + 10 * SEC);
        let out = drain_results(&mut s);
        assert_eq!(out.len(), 4);
        assert_eq!(out[0].port, Some(5353));
        assert_eq!(out[0].state, "open");
        assert_eq!(out[1].port, Some(5354));
        assert_eq!(out[1].state, "closed");
        assert_eq!(out[2].port, Some(5355));
        assert_eq!(out[2].state, "filtered");
        assert_eq!(out[3].port, Some(5356));
        assert_eq!(out[3].state, "open|filtered");

        // cross-talk: ICMP 3/3 quoting a probe of a DIFFERENT target
        // (the quote is our own outbound datagram: src=us, dst=other).
        let mut s2 =
            ScanSession::new(&reg, cfg_of(ScanMode::Udp, &[5357], 0), src(), t0()).unwrap();
        drain_sends(&mut s2);
        let p = s2.probes[0].clone();
        let reg2 = registry();
        let other: ScanAddr = ScanAddr::V4("127.0.0.99".parse().unwrap());
        let quoted = packet::udp(&reg2, s2.src, other, p.sport, p.port).unwrap();
        let mut ip_fields = std::collections::BTreeMap::new();
        ip_fields.insert(
            "src".to_string(),
            Value::Ipv4(match other {
                ScanAddr::V4(a) => a,
                _ => unreachable!(),
            }),
        );
        ip_fields.insert(
            "dst".to_string(),
            Value::Ipv4(match s2.src {
                ScanAddr::V4(a) => a,
                _ => unreachable!(),
            }),
        );
        let mut icmp_fields = std::collections::BTreeMap::new();
        icmp_fields.insert("type".to_string(), Value::Int(3));
        icmp_fields.insert("code".to_string(), Value::Int(3));
        let spec = PacketSpec::new(
            vec![
                LayerSpec::with_fields("ipv4", ip_fields),
                LayerSpec::with_fields("icmp", icmp_fields),
            ],
            Some(Value::Bytes(quoted)),
        );
        let unreach = wrex_core::encode::encode(
            &reg2,
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap()
        .bytes
        .to_vec();
        s2.on_frame(frame(unreach), t0());
        assert!(
            s2.poll_result().is_none(),
            "cross-talk quote must not resolve"
        );
    }

    /// Build an ICMPv6 type/`code` unreachable quoting probe `idx`'s v6
    /// datagram (RFC 4443 §3.1: the original datagram rides as the
    /// icmpv6 payload, any error message ≥ 128 bytes convention aside —
    /// our parser needs 40 + 8).
    fn icmp6_unreach(s: &ScanSession<'_>, idx: usize, code: u8) -> Vec<u8> {
        let reg = registry();
        let p = &s.probes[idx];
        let quoted = packet::udp(&reg, s.src, p.target, p.sport, p.port).unwrap();
        let mut ip_fields = std::collections::BTreeMap::new();
        ip_fields.insert(
            "src".to_string(),
            Value::Ipv6(match p.target {
                ScanAddr::V6(a) => a,
                ScanAddr::V4(_) => unreachable!("v6 test helper"),
            }),
        );
        ip_fields.insert(
            "dst".to_string(),
            Value::Ipv6(match s.src {
                ScanAddr::V6(a) => a,
                ScanAddr::V4(_) => unreachable!("v6 test helper"),
            }),
        );
        ip_fields.insert("hop_limit".to_string(), Value::Int(64));
        let mut icmp_fields = std::collections::BTreeMap::new();
        icmp_fields.insert("type".to_string(), Value::Int(1));
        icmp_fields.insert("code".to_string(), Value::Int(code as u128));
        let spec = PacketSpec::new(
            vec![
                LayerSpec::with_fields("ipv6", ip_fields),
                LayerSpec::with_fields("icmpv6", icmp_fields),
            ],
            Some(Value::Bytes(quoted)),
        );
        wrex_core::encode::encode(
            &reg,
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
    fn v6_icmp_alive_dead() {
        let reg = registry();
        let mut s = ScanSession::new(&reg, icmp6_cfg(0), src6(), t0()).unwrap();
        drain_sends(&mut s);
        // probe dissects as icmpv6 echo request 128
        let sent = drain_sends_identities(&s);
        let _ = sent;
        let p = s.probes[0].clone();
        let reply = packet::icmp_echo(&reg, p.target, s.src, 129, p.sport, p.seq as u16)
            .unwrap()
            .to_vec();
        s.on_frame(frame(reply), t0() + 3 * MS);
        let out = drain_results(&mut s);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].state, "alive");
        assert_eq!(out[0].proto, "icmpv6");
        assert_eq!(out[0].target.to_string(), "::1");
        // wrong type (128 request) → cross-talk; timeout → dead
        let mut s2 = ScanSession::new(&reg, icmp6_cfg(0), src6(), t0()).unwrap();
        drain_sends(&mut s2);
        let p2 = s2.probes[0].clone();
        let req_again = packet::icmp_echo(&reg, p2.target, s2.src, 128, p2.sport, p2.seq as u16)
            .unwrap()
            .to_vec();
        s2.on_frame(frame(req_again), t0());
        assert!(s2.poll_result().is_none());
        s2.on_timeout(t0() + SEC);
        assert_eq!(drain_results(&mut s2)[0].state, "dead");
    }

    #[test]
    fn v6_udp_unreachable_attribution() {
        let reg = registry();
        let mut s =
            ScanSession::new(&reg, cfg6_of(ScanMode::Udp, &[5353, 5354], 0), src6(), t0()).unwrap();
        let sent = drain_sends(&mut s);
        assert_eq!(sent.len(), 2);
        // UDP reply → open
        let reply = packet::udp(
            &reg,
            s.probes[0].target,
            s.src,
            s.probes[0].port,
            s.probes[0].sport,
        )
        .unwrap()
        .to_vec();
        s.on_frame(frame(reply), t0() + MS);
        // ICMPv6 1/4 (RFC 4443 §3.1 port unreachable) quoting probe 1
        // → closed
        s.on_frame(frame(icmp6_unreach(&s, 1, 4)), t0() + 2 * MS);
        let out = drain_results(&mut s);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].port, Some(5353));
        assert_eq!(out[0].state, "open");
        assert_eq!(out[1].port, Some(5354));
        assert_eq!(out[1].state, "closed");

        // ICMPv6 1/0 (no route) → filtered; 1/3 (address unreachable)
        // is also filtered in v6 — the port-unreachable code is 4, not
        // the v4 type-3 numbering
        for code in [0u8, 3] {
            let mut s2 =
                ScanSession::new(&reg, cfg6_of(ScanMode::Udp, &[5355], 0), src6(), t0()).unwrap();
            drain_sends(&mut s2);
            s2.on_frame(frame(icmp6_unreach(&s2, 0, code)), t0() + MS);
            let out2 = drain_results(&mut s2);
            assert_eq!(out2.len(), 1);
            assert_eq!(out2[0].state, "filtered", "code {code}");
        }

        // cross-talk: a quote naming a different target must not resolve
        let mut s3 =
            ScanSession::new(&reg, cfg6_of(ScanMode::Udp, &[5356], 0), src6(), t0()).unwrap();
        drain_sends(&mut s3);
        let other = ScanAddr::V6("::99".parse().unwrap());
        let reg3 = registry();
        let quoted =
            packet::udp(&reg3, s3.src, other, s3.probes[0].sport, s3.probes[0].port).unwrap();
        let mut ip_fields = std::collections::BTreeMap::new();
        ip_fields.insert(
            "src".to_string(),
            Value::Ipv6(match other {
                ScanAddr::V6(a) => a,
                ScanAddr::V4(_) => unreachable!(),
            }),
        );
        ip_fields.insert(
            "dst".to_string(),
            Value::Ipv6(match s3.src {
                ScanAddr::V6(a) => a,
                ScanAddr::V4(_) => unreachable!(),
            }),
        );
        let mut icmp_fields = std::collections::BTreeMap::new();
        icmp_fields.insert("type".to_string(), Value::Int(1));
        icmp_fields.insert("code".to_string(), Value::Int(3));
        let spec = PacketSpec::new(
            vec![
                LayerSpec::with_fields("ipv6", ip_fields),
                LayerSpec::with_fields("icmpv6", icmp_fields),
            ],
            Some(Value::Bytes(quoted)),
        );
        let unreach = wrex_core::encode::encode(
            &reg3,
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap()
        .bytes
        .to_vec();
        s3.on_frame(frame(unreach), t0());
        assert!(
            s3.poll_result().is_none(),
            "cross-talk quote must not resolve"
        );
    }

    #[test]
    fn v6_syn_scan_shapes() {
        let reg = registry();
        let mut s =
            ScanSession::new(&reg, cfg6_of(ScanMode::Syn, &[443], 0), src6(), t0()).unwrap();
        let sent = drain_sends(&mut s);
        assert_eq!(sent.len(), 1);
        let p = wrex_core::dissect::dissect(&reg, &sent[0], "ipv6");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[0].kind, "ipv6");
        assert_eq!(p.layers[1].kind, "tcp");
        // SYN+ACK → open (+RST follow-up on our 4-tuple)
        let probe = s.probes[0].clone();
        let synack = packet::tcp(
            &reg,
            probe.target,
            s.src,
            probe.port,
            probe.sport,
            0x9955,
            Some(probe.seq.wrapping_add(1)),
            packet::FLAG_SYN | packet::FLAG_ACK,
        )
        .unwrap()
        .to_vec();
        s.on_frame(frame(synack), t0() + 3 * MS);
        let out = drain_results(&mut s);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].state, "open");
        assert_eq!(out[0].proto, "tcp");
        let followups = drain_sends(&mut s);
        assert_eq!(followups.len(), 1, "RST follow-up after open");
        let d = wrex_core::dissect::dissect(&reg, &followups[0], "ipv6");
        assert!(matches!(
            d.layers[1].fields.get("flags"),
            Some(Value::List(items)) if items.contains(&Value::Str("rst".into()))
        ));
    }

    /// Identities of every probe (for assertions).
    fn drain_sends_identities(s: &ScanSession<'_>) -> Vec<(ScanAddr, u16, u16, u32)> {
        s.probes
            .iter()
            .map(|p| (p.target, p.port, p.sport, p.seq))
            .collect()
    }

    #[test]
    fn icmp_alive_dead() {
        let reg = registry();
        let mut s = ScanSession::new(&reg, icmp_cfg(0), src(), t0()).unwrap();
        drain_sends(&mut s);
        let p = s.probes[0].clone();
        let reply = packet::icmp_echo(&reg, p.target, s.src, 0, p.sport, p.seq as u16)
            .unwrap()
            .to_vec();
        s.on_frame(frame(reply), t0() + 3 * MS);
        let out = drain_results(&mut s);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].state, "alive");
        assert_eq!(out[0].port, None);
        assert_eq!(out[0].proto, "icmp");
        // rtt basis is wall-clock (Miri runs slow): bound, don't pin.
        assert!(out[0].rtt_ms.unwrap() >= 3, "{:?}", out[0].rtt_ms);

        // wrong id → cross-talk; then timeout → dead
        let mut s2 = ScanSession::new(&reg, icmp_cfg(0), src(), t0()).unwrap();
        drain_sends(&mut s2);
        let wrong = packet::icmp_echo(&reg, src(), s2.src, 0, 0xffff, 1)
            .unwrap()
            .to_vec();
        s2.on_frame(frame(wrong), t0());
        assert!(s2.poll_result().is_none());
        s2.on_timeout(t0() + SEC);
        assert_eq!(drain_results(&mut s2)[0].state, "dead");
    }

    #[test]
    fn pacing_schedule_and_jitter_bounds() {
        let reg = registry();
        let mut cfg = cfg_of(ScanMode::Syn, &[1, 2, 3], 0);
        cfg.interval = Duration::from_millis(100);
        cfg.jitter = Duration::from_millis(40);
        cfg.seed = 12345;
        let t = t0();
        let s = ScanSession::new(&reg, cfg.clone(), src(), t).unwrap();
        let dues: Vec<Instant> = s.probes.iter().map(|p| p.due).collect();
        // monotonic strictly increasing under pacing
        for w in dues.windows(2) {
            assert!(w[1] > w[0]);
        }
        // |step - interval| <= jitter
        for w in dues.windows(2) {
            let step = w[1] - w[0];
            assert!(
                step >= Duration::from_millis(60),
                "step below jitter bound: {step:?}"
            );
            assert!(
                step <= Duration::from_millis(140),
                "step above jitter bound: {step:?}"
            );
        }
        // same seed → identical schedule and identities
        let s2 = ScanSession::new(&reg, cfg.clone(), src(), t).unwrap();
        assert_eq!(
            s2.probes
                .iter()
                .map(|p| (p.due, p.sport, p.seq))
                .collect::<Vec<_>>(),
            s.probes
                .iter()
                .map(|p| (p.due, p.sport, p.seq))
                .collect::<Vec<_>>(),
        );
        // different seed → different identities
        let mut cfg3 = cfg;
        cfg3.seed = 54321;
        let s3 = ScanSession::new(&reg, cfg3, src(), t).unwrap();
        let sports_a: Vec<u16> = s2.probes.iter().map(|p| p.sport).collect();
        let sports_b: Vec<u16> = s3.probes.iter().map(|p| p.sport).collect();
        assert_ne!(sports_a, sports_b);
    }

    #[test]
    fn burst_all_due_at_once() {
        let reg = registry();
        let s = ScanSession::new(&reg, cfg_of(ScanMode::Syn, &[1, 2, 3], 0), src(), t0()).unwrap();
        for p in &s.probes {
            assert_eq!(p.due, s.probes[0].due, "burst: every probe due at t0");
        }
    }

    #[test]
    fn concurrency_cap_holds_sends() {
        let reg = registry();
        let mut cfg = cfg_of(ScanMode::Syn, &[1, 2, 3, 4], 0);
        cfg.concurrent = 2;
        let mut s = ScanSession::new(&reg, cfg, src(), t0()).unwrap();
        let sent = drain_sends(&mut s);
        assert_eq!(sent.len(), 2, "only `concurrent` sends are due");
        // resolve one probe → a slot frees → next send
        s.on_frame(frame(synack(&s, 0)), t0());
        assert!(s.poll_action().is_some(), "freed slot must send");
    }

    #[test]
    fn registry_gating() {
        let mut reg = Registry::empty();
        reg.register(&wrex_proto_ip::CODEC);
        let err = match ScanSession::new(&reg, cfg_of(ScanMode::Syn, &[1], 0), src(), t0()) {
            Ok(_) => panic!("syn scan must require the tcp codec"),
            Err(e) => e,
        };
        assert!(err.contains("tcp layer not registered"), "{err}");
        assert!(ScanSession::new(&reg, icmp_cfg(0), src(), t0()).is_err());
    }

    #[test]
    fn run_loop_end_to_end_with_scripted_driver() {
        // Same seed → identical probe identities: craft replies against
        // a manually-driven twin, then run the real runtime loop.
        let reg = registry();
        let clock = Arc::new(FakeClock::new());
        let t = clock.now();

        let twin = ScanSession::new(&reg, cfg_of(ScanMode::Syn, &[1, 2], 0), src(), t).unwrap();
        let mut twin = twin;
        drain_sends(&mut twin);
        let script = vec![
            synack(&twin, 0),
            // port 2 times out (no reply scripted)
        ];

        let mut session =
            ScanSession::new(&reg, cfg_of(ScanMode::Syn, &[1, 2], 0), src(), t).unwrap();
        let mut driver = ScriptedDriver::new(clock.clone(), script);
        let out = run(&mut session, &mut driver, clock.as_ref()).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].state, "open");
        assert_eq!(out[1].state, "filtered");
    }

    // --- reference-model differential (proptest) ------------------------------

    use proptest::prelude::{ProptestConfig, any, prop_assert, prop_assert_eq, proptest};
    use proptest::test_runner::FileFailurePersistence;

    proptest! {
        #![proptest_config(ProptestConfig {
            failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
                "proptest-regressions",
            ))),
            cases: 64,
            ..ProptestConfig::default()
        })]

        /// Reference-model differential: random target/port sets, seeds,
        /// retries and per-probe outcomes (synack / rst / none) shuffled
        /// across arrival order, plus random cross-talk frames. Final
        /// classifications must match the naive per-probe expectation
        /// exactly, never panic, and bound the send count.
        #[test]
        fn syn_reference_model(
            n_targets in 1usize..4,
            n_ports in 1usize..4,
            seed in any::<u64>(),
            retries in 0u32..3,
            outcome_seed in any::<u64>(),
            shuffle_seed in any::<u64>(),
            cross_talk in proptest::bool::ANY,
        ) {
            let reg = registry();
            let targets: Vec<String> = (0..n_targets)
                .map(|i| format!("127.0.0.{}", 1 + i))
                .collect();
            let ports: Vec<u16> = (0..n_ports as u16).map(|i| 1000 + i).collect();
            let ports_spec = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
            let cfg = ScanConfig::build(
                ScanMode::Syn,
                &targets,
                Some(&ports_spec),
                Duration::ZERO,
                Duration::ZERO,
                seed,
                retries,
                SEC,
                256,
            ).unwrap();
            let probe_count = cfg.probe_count();

            // Twin session (same seed) learns the probe identities.
            let twin = ScanSession::new(&reg, cfg.clone(), src(), t0()).unwrap();
            let identities: Vec<(ScanAddr, u16, u16, u32)> = twin.probes.iter()
                .map(|p| (p.target, p.port, p.sport, p.seq))
                .collect();

            // Per-probe outcomes and reply frames (shuffled arrival).
            let mut orng = Rng::new(outcome_seed);
            let mut outcomes = Vec::with_capacity(probe_count);
            let mut replies: Vec<Vec<u8>> = Vec::new();
            for &(target, port, sport, seq) in &identities {
                let outcome = orng.next_u64() % 3;
                outcomes.push(outcome);
                if outcome == 2 { continue; } // silence
                let flags = if outcome == 0 {
                    packet::FLAG_SYN | packet::FLAG_ACK
                } else {
                    packet::FLAG_RST | packet::FLAG_ACK
                };
                let ack = if outcome == 0 { Some(seq.wrapping_add(1)) } else { None };
                replies.push(
                    packet::tcp(&reg, target, src(), port, sport, 0x1234, ack, flags)
                        .unwrap()
                        .to_vec(),
                );
            }
            let mut srng = Rng::new(shuffle_seed);
            for i in (1..replies.len()).rev() {
                let j = (srng.next_u64() as usize) % (i + 1);
                replies.swap(i, j);
            }

            // Session under test.
            let mut s = ScanSession::new(&reg, cfg, src(), t0()).unwrap();
            let t = t0();
            let mut sends = drain_sends(&mut s).len();
            prop_assert_eq!(sends, probe_count, "burst sends every probe once");

            // Cross-talk frame first (must resolve nothing).
            if cross_talk && probe_count > 0 {
                let (target, port, sport, seq) = identities[0];
                let wrong = packet::tcp(
                    &reg, target, src(), port, sport.wrapping_add(1), 9,
                    Some(seq.wrapping_add(1)), packet::FLAG_SYN | packet::FLAG_ACK,
                ).unwrap();
                s.on_frame(frame(wrong.to_vec()), t + MS);
                prop_assert!(s.poll_result().is_none(), "cross-talk resolved a probe");
            }

            // Deliver the shuffled replies.
            for (i, bytes) in replies.iter().enumerate() {
                s.on_frame(frame(bytes.clone()), t + Duration::from_millis(2 + i as u64));
                sends += drain_sends(&mut s).len();
                prop_assert!(
                    sends <= probe_count * (retries as usize + 2),
                    "follow-up send bound exceeded"
                );
            }
            // Fire deadlines until idle (retransmissions included).
            for i in 0..(retries + 3) {
                s.on_timeout(t + Duration::from_secs(10 + u64::from(i)));
                sends += drain_sends(&mut s).len();
                prop_assert!(
                    sends <= probe_count * (retries as usize + 2),
                    "retransmit send bound exceeded"
                );
            }

            let mut got: Vec<(ScanAddr, u16, &'static str)> = drain_results(&mut s)
                .into_iter()
                .map(|r| (r.target, r.port.unwrap_or(0), r.state))
                .collect();
            prop_assert_eq!(got.len(), probe_count, "every probe resolves exactly once");
            let expected: Vec<(ScanAddr, u16, &'static str)> = identities.iter().zip(&outcomes)
                .map(|(&(target, port, _, _), &o)| {
                    (target, port, match o { 0 => "open", 1 => "closed", _ => "filtered" })
                })
                .collect();
            // Result order is resolution order; compare per (target, port).
            got.sort_by_key(|&(t, p, _)| (t, p));
            let mut expected_sorted = expected;
            expected_sorted.sort_by_key(|&(t, p, _)| (t, p));
            prop_assert_eq!(got, expected_sorted, "classifications must match the reference model");
            prop_assert!(s.next_timeout().is_none(), "session must go idle");
        }
    }
}
