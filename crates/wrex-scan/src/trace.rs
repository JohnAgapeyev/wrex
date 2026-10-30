//! [`TraceSession`]: the traceroute state machine (T21b) over the
//! frozen [`wrex_session::Session`] contract — the T2 scan pattern
//! transposed to a TTL walk.
//!
//! One probe in flight at a time, TTL 1..=`max_hops`, per hop:
//!
//! | mode | reply | state |
//! |---|---|---|
//! | icmp | time-exceeded quoting our echo | `hop` (the quoting router) |
//! | icmp | echo reply (id match) | `reached` — walk ends |
//! | udp | time-exceeded quoting our datagram | `hop` |
//! | udp | port-unreachable quoting our datagram | `reached` — walk ends |
//! | udp | UDP reply on our 4-tuple | `reached` — walk ends |
//! | tcp | time-exceeded quoting our segment | `hop` |
//! | tcp | SYN+ACK / RST on our 4-tuple | `reached` — walk ends |
//! | any | exhausted | `silent` (`*`) — walk continues |
//!
//! The quote attribution is the scan mode's unreachable-quote machinery
//! transposed: an ICMP/ICMPv6 time-exceeded carries the original
//! datagram; the quote's inner 4-tuple (or echo id) must name OUR probe
//! — anything else is cross-talk and never resolves a hop. `--backoff`
//! paces retransmissions exponentially (`wait × backoff^(attempt-1)`).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use bytes::Bytes;

use wrex_core::Registry;
use wrex_core::dissect::{DissectedPacket, LayerView, dissect};
use wrex_core::value::Value;
use wrex_io::{Frame, Rng};
use wrex_session::{Session, SessionAction};

use crate::packet;
use crate::target::{Family, ScanAddr};

/// Traceroute probe mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceMode {
    /// ICMP echo probes (the default): echo reply ends the walk.
    Icmp,
    /// UDP datagrams to `--port` (classic traceroute): a UDP reply or
    /// ICMP port-unreachable ends the walk.
    Udp,
    /// TCP SYN to `--port`: SYN+ACK or RST ends the walk.
    Tcp,
}

impl TraceMode {
    pub const DEFAULT: Self = Self::Icmp;

    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw {
            None => Ok(Self::DEFAULT),
            Some("icmp") => Ok(Self::Icmp),
            Some("udp") => Ok(Self::Udp),
            Some("tcp") => Ok(Self::Tcp),
            Some(other) => Err(format!("unknown trace mode `{other}` (icmp|udp|tcp)")),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Icmp => "icmp",
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }

    /// Registry kinds this mode needs registered over `family`.
    pub const fn needs_for(self, family: Family) -> &'static [&'static str] {
        match self {
            Self::Icmp => match family {
                Family::V4 => &["ipv4", "icmp"],
                Family::V6 => &["ipv6", "icmpv6"],
            },
            Self::Udp => match family {
                Family::V4 => &["ipv4", "udp"],
                Family::V6 => &["ipv6", "udp"],
            },
            Self::Tcp => match family {
                Family::V4 => &["ipv4", "tcp"],
                Family::V6 => &["ipv6", "tcp"],
            },
        }
    }
}

/// Default destination port for `udp` probes (traceroute's convention).
pub const DEFAULT_UDP_PORT: u16 = 33434;
/// Default destination port for `tcp` probes.
pub const DEFAULT_TCP_PORT: u16 = 80;
/// Default walk length.
pub const DEFAULT_MAX_HOPS: u8 = 30;
/// Default per-attempt reply wait.
pub const DEFAULT_WAIT: Duration = Duration::from_secs(1);
/// Default extra attempts per hop beyond the first.
pub const DEFAULT_RETRIES: u32 = 1;
/// Default retransmission backoff base (`wait × backoff^(attempt-1)`).
pub const DEFAULT_BACKOFF: u32 = 1;

/// A validated traceroute configuration.
#[derive(Clone, Debug)]
pub struct TraceConfig {
    pub mode: TraceMode,
    /// Single target (one walk).
    pub target: ScanAddr,
    /// Probed port (udp/tcp modes).
    pub port: u16,
    pub max_hops: u8,
    /// Per-attempt reply wait.
    pub wait: Duration,
    /// Extra attempts per hop.
    pub retries: u32,
    /// Retransmission backoff base (≥ 1; 1 = none).
    pub backoff: u32,
    /// RNG seed (probe identities).
    pub seed: u64,
}

impl TraceConfig {
    /// Validate and build. `target_raw` follows the scan target grammar
    /// but must resolve to exactly one address (one walk per run).
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        mode: TraceMode,
        target_raw: &str,
        port: Option<u16>,
        max_hops: Option<u8>,
        wait: Duration,
        retries: u32,
        backoff: u32,
        seed: u64,
    ) -> Result<Self, String> {
        let targets = crate::target::parse_targets(&[target_raw.to_string()])?;
        if targets.is_empty() {
            return Err("no trace target given".to_string());
        }
        let target = targets[0];
        if targets.len() > 1 {
            return Err(format!(
                "trace takes one target ({} resolved); use one run per target",
                targets.len()
            ));
        }
        let port = match (mode, port) {
            (TraceMode::Icmp, Some(_)) => {
                return Err("icmp mode takes no --port (the echo id is the probe identity)".into());
            }
            (TraceMode::Icmp, None) => 0,
            (TraceMode::Udp, Some(p)) => p,
            (TraceMode::Udp, None) => DEFAULT_UDP_PORT,
            (TraceMode::Tcp, Some(p)) => p,
            (TraceMode::Tcp, None) => DEFAULT_TCP_PORT,
        };
        let max_hops = max_hops.unwrap_or(DEFAULT_MAX_HOPS);
        if max_hops == 0 {
            return Err("trace --max-hops must be >= 1".to_string());
        }
        if wait.is_zero() {
            return Err("trace --wait must be > 0".to_string());
        }
        if backoff == 0 {
            return Err("trace --backoff must be >= 1 (1 = no backoff)".to_string());
        }
        Ok(Self {
            mode,
            target,
            port,
            max_hops,
            wait,
            retries,
            backoff,
            seed,
        })
    }

    pub const fn family(&self) -> Family {
        self.target.family()
    }
}

/// One per-hop record, streamed in walk order.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct TraceHop {
    /// TTL of the probe that produced this record (the hop ordinal).
    pub hop: u8,
    /// The walk's destination (json/jsonl context).
    pub target: ScanAddr,
    /// The replying address (`None` for silent hops — `*`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hop_addr: Option<ScanAddr>,
    /// `hop` (time-exceeded) / `reached` (destination) / `silent`.
    pub state: &'static str,
    /// Reply round-trip in milliseconds (`None` for silent hops).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u64>,
    /// Attempts spent on this hop (first + retransmissions).
    pub attempts: u32,
}

impl TraceHop {
    /// Text rendering: `1  10.0.0.1  hop  (1ms)` / `2  *  silent`.
    pub fn text_line(&self) -> String {
        let addr = self
            .hop_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "*".to_string());
        let rtt = self
            .rtt_ms
            .map(|ms| format!("  ({ms}ms)"))
            .unwrap_or_default();
        format!("{}  {}  {}{}", self.hop, addr, self.state, rtt)
    }
}

/// Probe identity (mode-appropriate reply matching fields).
#[derive(Clone, Copy, Debug)]
struct Identity {
    sport: u16,
    seq: u32,
    id: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Next hop not yet sent (`next_send` may pace a retransmission).
    Idle,
    /// Probe in flight, awaiting a reply or `deadline`.
    Waiting { deadline: Instant, sent_at: Instant },
    /// Walk complete.
    Done,
}

/// The traceroute state machine. Construct with [`TraceSession::new`];
/// drive with [`wrex_session::run`] or by hand (tests).
pub struct TraceSession<'a> {
    registry: &'a Registry,
    cfg: TraceConfig,
    src: ScanAddr,
    now: Instant,
    /// Current hop's TTL (the next probe when `Idle`).
    ttl: u8,
    attempt: u32,
    phase: Phase,
    /// Pace gate for the next send (backoff, immediate when `None`).
    next_send: Option<Instant>,
    results: VecDeque<TraceHop>,
    identity: Identity,
}

impl<'a> TraceSession<'a> {
    /// Build the session: validates the registry carries the mode's
    /// codecs, seeds the probe identity, and schedules the first
    /// probe (TTL 1) immediately.
    pub fn new(
        registry: &'a Registry,
        cfg: TraceConfig,
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
        let identity = Identity {
            sport: rng.range_u16(32768, 60999),
            seq: (rng.next_u64() >> 32) as u32,
            id: (rng.next_u64() & 0xffff) as u16,
        };
        Ok(Self {
            registry,
            cfg,
            src,
            now: t0,
            ttl: 1,
            attempt: 0,
            phase: Phase::Idle,
            next_send: None,
            results: VecDeque::new(),
            identity,
        })
    }

    /// The current probe's packet bytes (identity stable across
    /// retransmissions of the same hop).
    fn build_probe(&self) -> Result<Bytes, wrex_core::EncodeError> {
        let cfg = &self.cfg;
        match cfg.mode {
            TraceMode::Icmp => {
                let typ = match cfg.family() {
                    Family::V4 => 8,
                    Family::V6 => packet::ICMPV6_ECHO_REQ,
                };
                packet::icmp_echo_ttl(
                    self.registry,
                    self.src,
                    cfg.target,
                    typ,
                    self.identity.id,
                    self.identity.seq as u16,
                    self.ttl,
                )
            }
            TraceMode::Udp => packet::udp_ttl(
                self.registry,
                self.src,
                cfg.target,
                self.identity.sport,
                cfg.port,
                self.ttl,
            ),
            TraceMode::Tcp => packet::tcp_ttl(
                self.registry,
                self.src,
                cfg.target,
                self.identity.sport,
                cfg.port,
                self.identity.seq,
                None,
                packet::FLAG_SYN,
                self.ttl,
            ),
        }
    }

    /// Send the current hop's probe (first attempt or retransmission).
    fn send_current(&mut self) -> Option<SessionAction> {
        let bytes = self.build_probe().ok()?;
        self.attempt += 1;
        self.phase = Phase::Waiting {
            deadline: self.now + self.cfg.wait,
            sent_at: self.now,
        };
        self.next_send = None;
        Some(SessionAction::Send(bytes))
    }

    /// Record one hop outcome and move on (`advance`: schedule the next
    /// TTL) or finish (`reached` / walk exhausted).
    fn record(&mut self, state: &'static str, hop_addr: Option<ScanAddr>, rtt: Option<Duration>) {
        let hop = self.ttl;
        let target = self.cfg.target;
        let attempts = self.attempt;
        self.results.push_back(TraceHop {
            hop,
            target,
            hop_addr,
            state,
            rtt_ms: rtt.map(TraceHop::rtt_from),
            attempts,
        });
        // reached ends the walk; a time-exceeded hop advances the TTL;
        // walk exhaustion ends it too.
        if state == "reached" || self.ttl >= self.cfg.max_hops {
            self.phase = Phase::Done;
        } else {
            self.ttl += 1;
            self.attempt = 0;
            self.phase = Phase::Idle;
            self.next_send = Some(self.now);
        }
    }

    /// Wait extra before the next attempt (backoff pacing).
    fn backoff_wait(&self) -> Duration {
        let k = self.attempt.saturating_sub(1);
        let factor = self.cfg.backoff.saturating_pow(k);
        self.cfg.wait.saturating_mul(factor)
    }

    /// Handle a time-exceeded reply quoting our probe: `hop_addr` is
    /// the quoting router. Returns `false` on cross-talk.
    fn on_time_exceeded(&mut self, pkt: &DissectedPacket, now: Instant, quote: Quote<'_>) -> bool {
        let family = self.cfg.family();
        if !quote.matches(family, self.cfg.mode, self.cfg.target, self.identity) {
            return false; // cross-talk quote
        }
        let hop_addr = f_addr(pkt, self.cfg.family(), "src");
        let sent_at = match self.phase {
            Phase::Waiting { sent_at, .. } => sent_at,
            _ => return false,
        };
        let rtt = now.saturating_duration_since(sent_at);
        self.record("hop", hop_addr, Some(rtt));
        true
    }

    /// Destination reached: record and end the walk.
    fn on_reached(&mut self, pkt: &DissectedPacket, now: Instant) {
        let hop_addr = f_addr(pkt, self.cfg.family(), "src");
        let sent_at = match self.phase {
            Phase::Waiting { sent_at, .. } => sent_at,
            _ => return,
        };
        let rtt = now.saturating_duration_since(sent_at);
        self.record("reached", hop_addr, Some(rtt));
    }

    /// Classify one dissected reply frame against the in-flight probe.
    fn on_reply(&mut self, pkt: &DissectedPacket, now: Instant) {
        if !matches!(self.phase, Phase::Waiting { .. }) {
            return; // late reply
        }
        let family = self.cfg.family();
        let (icmp_kind, time_exceeded, echo_reply, unreach_type) = match family {
            Family::V4 => ("icmp", 11u128, 0u128, 3u128),
            Family::V6 => ("icmpv6", 3, 129, 1),
        };
        // ICMP/ICMPv6 error replies (quotes) first — every mode reads
        // time-exceeded; udp additionally reads port-unreachable.
        if let Some(icmp) = pkt.layers.iter().find(|l| l.kind == icmp_kind) {
            let Some(t) = f_int(icmp, "type") else { return };
            let code = f_int(icmp, "code").unwrap_or(255);
            if t == time_exceeded && code == 0 {
                if let Some(q) = parse_quote(family, &pkt.payload) {
                    self.on_time_exceeded(pkt, now, q);
                }
                return;
            }
            // Destination-unreachable quoting our probe = the walk's end
            // in udp mode (port unreachable: ICMP type 3 code 3 over v4,
            // RFC 4443 §3.1 type 1 code 4 over v6).
            if self.cfg.mode == TraceMode::Udp
                && t == unreach_type
                && (matches!((family, code), (Family::V4, 3) | (Family::V6, 4)))
                && let Some(q) = parse_quote(family, &pkt.payload)
                && q.matches(family, self.cfg.mode, self.cfg.target, self.identity)
            {
                self.on_reached(pkt, now);
                return;
            }
            // icmp mode: an echo reply carrying our id ends the walk.
            if self.cfg.mode == TraceMode::Icmp
                && t == echo_reply
                && f_int(icmp, "echo.id") == Some(self.identity.id as u128)
            {
                self.on_reached(pkt, now);
            }
            return; // other ICMP types carry no traceroute semantics
        }
        match self.cfg.mode {
            TraceMode::Icmp => {
                // echo reply with our id → reached (the icmp arm above
                // returned already: this is a non-icmp frame, so
                // nothing to do).
            }
            TraceMode::Udp => {
                // any UDP datagram back on our 4-tuple → reached
                let Some(udp) = pkt.layers.iter().find(|l| l.kind == "udp") else {
                    return;
                };
                let from_target = f_int(udp, "sport") == Some(self.cfg.port as u128)
                    && f_int(udp, "dport") == Some(self.identity.sport as u128);
                if from_target {
                    self.on_reached(pkt, now);
                }
            }
            TraceMode::Tcp => {
                // SYN+ACK (acking our seq) or RST → reached
                let Some(tcp) = pkt.layers.iter().find(|l| l.kind == "tcp") else {
                    return;
                };
                let Some(sport) = f_int(tcp, "sport") else {
                    return;
                };
                let Some(dport) = f_int(tcp, "dport") else {
                    return;
                };
                if sport != self.cfg.port as u128 || dport != self.identity.sport as u128 {
                    return; // cross-talk
                }
                let names = flag_names(tcp.fields.get("flags"));
                let syn = names.contains(&"syn");
                let ack_ok = f_int(tcp, "ack") == Some(self.identity.seq.wrapping_add(1) as u128);
                if (syn && names.contains(&"ack") && ack_ok) || names.contains(&("rst")) {
                    self.on_reached(pkt, now);
                }
            }
        }
    }
}

impl TraceHop {
    /// Round-trip from a duration, millisecond precision.
    fn rtt_from(d: Duration) -> u64 {
        d.as_millis().min(u64::MAX as u128) as u64
    }
}

/// An ICMP/ICMPv6 quote of the original datagram (the first 8 L4
/// bytes): the fields the probe identity lives in.
#[derive(Clone, Copy)]
struct Quote<'a> {
    /// Inner (quoted) destination address.
    dst: Option<ScanAddr>,
    /// Inner L4 protocol number (v6: next_header at the fixed header).
    proto: Option<u8>,
    /// Inner L4 bytes (≥ 8 or a short tail; parse defensively).
    l4: &'a [u8],
}

impl Quote<'_> {
    /// Does the quote name OUR probe? (target address + mode identity).
    fn matches(&self, family: Family, mode: TraceMode, target: ScanAddr, id: Identity) -> bool {
        if self.dst != Some(target) {
            return false;
        }
        // Inner L4 protocol: icmpv6 rides next_header 58 (RFC 8200);
        // over v4 ICMP is proto 1.
        let want_proto = match (mode, family) {
            (TraceMode::Icmp, Family::V4) => 1,
            (TraceMode::Icmp, Family::V6) => 58,
            (TraceMode::Udp, _) => 17,
            (TraceMode::Tcp, _) => 6,
        };
        match (self.proto, mode) {
            (Some(p), _) if p != want_proto => false,
            (_, TraceMode::Icmp) => {
                // inner echo id at [4..6] (+ seq at [6..8])
                self.l4.len() >= 8 && u16::from_be_bytes([self.l4[4], self.l4[5]]) == id.id
            }
            (_, TraceMode::Udp) => {
                self.l4.len() >= 8 && u16::from_be_bytes([self.l4[0], self.l4[1]]) == id.sport
            }
            (_, TraceMode::Tcp) => {
                self.l4.len() >= 8 && u16::from_be_bytes([self.l4[0], self.l4[1]]) == id.sport
            }
        }
    }
}

/// Parse the quoted original datagram out of a time-exceeded /
/// unreachable payload (family-aware).
fn parse_quote<'a>(family: Family, payload: &'a [u8]) -> Option<Quote<'a>> {
    match family {
        Family::V4 => {
            if payload.len() < 28 {
                return None; // 20-byte inner IPv4 header + 8 bytes L4
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
            Some(Quote {
                dst: Some(dst),
                proto: Some(payload[9]),
                l4: &payload[hlen..],
            })
        }
        Family::V6 => {
            if payload.len() < 40 + 8 {
                return None; // fixed 40-byte inner header + 8 bytes L4
            }
            if payload[0] >> 4 != 6 {
                return None;
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&payload[24..40]);
            Some(Quote {
                dst: Some(ScanAddr::V6(std::net::Ipv6Addr::from(o))),
                proto: Some(payload[6]),
                l4: &payload[40..],
            })
        }
    }
}

// --- dissected-field helpers (the session module's shapes) ------------------

fn f_int(layer: &LayerView, name: &str) -> Option<u128> {
    match layer.fields.get(name) {
        Some(Value::Int(v)) => Some(*v),
        _ => None,
    }
}

fn f_addr(pkt: &DissectedPacket, family: Family, name: &str) -> Option<ScanAddr> {
    let ip_kind = family.ip_kind();
    let ip = pkt.layers.iter().find(|l| l.kind == ip_kind)?;
    match (family, ip.fields.get(name)) {
        (Family::V4, Some(Value::Ipv4(a))) => Some(ScanAddr::V4(*a)),
        (Family::V6, Some(Value::Ipv6(a))) => Some(ScanAddr::V6(*a)),
        _ => None,
    }
}

/// Flag names out of a dissected flags aggregate (the session shape).
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

impl<'a> Session for TraceSession<'a> {
    type Output = TraceHop;

    fn on_frame(&mut self, frame: Frame, now: Instant) {
        self.now = now;
        let start = self.cfg.family().ip_kind();
        let pkt = dissect(self.registry, &frame.bytes, start);
        self.on_reply(&pkt, now);
    }

    fn on_timeout(&mut self, now: Instant) {
        self.now = now;
        if let Phase::Waiting { deadline, .. } = self.phase {
            if deadline > now {
                return;
            }
            if self.attempt <= self.cfg.retries {
                // Retransmit this hop after the backoff pace.
                self.phase = Phase::Idle;
                self.next_send = Some(now + self.backoff_wait());
            } else {
                // Exhausted: a silent hop (`*`), walk continues.
                self.record("silent", None, None);
            }
            return;
        }
        // A paced (backoff-gated) retransmission whose gate arrived: open
        // the gate so the next `poll_action` sends (the runtime wakes us
        // at the gate, `next_timeout` reported it).
        if self.phase == Phase::Idle
            && let Some(due) = self.next_send
            && due <= now
        {
            self.next_send = None;
        }
    }

    fn poll_action(&mut self) -> Option<SessionAction> {
        match self.phase {
            Phase::Done => None,
            Phase::Waiting { .. } => None,
            Phase::Idle => {
                let due = self.next_send.unwrap_or(self.now);
                if due <= self.now {
                    self.send_current()
                } else {
                    None
                }
            }
        }
    }

    fn next_timeout(&mut self) -> Option<Instant> {
        match self.phase {
            Phase::Done => None,
            Phase::Waiting { deadline, .. } => Some(deadline),
            Phase::Idle => Some(self.next_send.unwrap_or(self.now)),
        }
    }

    fn poll_result(&mut self) -> Option<TraceHop> {
        self.results.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use wrex_io::{Clock as _, FakeClock, ScriptedDriver};
    use wrex_session::run;

    use crate::packet::{FLAG_ACK, FLAG_SYN};

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

    fn t0() -> Instant {
        Instant::now()
    }

    fn cfg(mode: TraceMode, target: &str) -> TraceConfig {
        TraceConfig::build(mode, target, None, None, SEC, 1, 1, 0xC0FFEE).unwrap()
    }

    fn drain_results(s: &mut TraceSession<'_>) -> Vec<TraceHop> {
        let mut out = Vec::new();
        while let Some(r) = s.poll_result() {
            out.push(r);
        }
        out
    }

    /// Send the current probe and return its bytes (dissected by tests).
    fn send_probe(s: &mut TraceSession<'_>) -> Vec<u8> {
        match s.poll_action() {
            Some(SessionAction::Send(b)) => b.to_vec(),
            other => panic!("probe expected, got {other:?}"),
        }
    }

    #[test]
    fn config_parse_and_guards() {
        assert_eq!(TraceMode::parse(None).unwrap(), TraceMode::Icmp);
        assert_eq!(TraceMode::parse(Some("udp")).unwrap(), TraceMode::Udp);
        assert_eq!(TraceMode::parse(Some("tcp")).unwrap(), TraceMode::Tcp);
        assert!(TraceMode::parse(Some("zzz")).is_err());
        let c = cfg(TraceMode::Udp, "127.0.0.1");
        assert_eq!(c.port, DEFAULT_UDP_PORT);
        assert_eq!(cfg(TraceMode::Tcp, "127.0.0.1").port, DEFAULT_TCP_PORT);
        // icmp takes no port
        assert!(
            TraceConfig::build(TraceMode::Icmp, "127.0.0.1", Some(80), None, SEC, 1, 1, 1).is_err()
        );
        // one target only
        assert!(
            TraceConfig::build(
                TraceMode::Icmp,
                "127.0.0.0-127.0.0.2",
                None,
                None,
                SEC,
                1,
                1,
                1
            )
            .is_err()
        );
        // wait + max_hops + backoff guards
        for bad in [
            TraceConfig::build(TraceMode::Icmp, "127.0.0.1", None, Some(0), SEC, 1, 1, 1),
            TraceConfig::build(
                TraceMode::Icmp,
                "127.0.0.1",
                None,
                None,
                Duration::ZERO,
                1,
                1,
                1,
            ),
            TraceConfig::build(TraceMode::Icmp, "127.0.0.1", None, None, SEC, 1, 0, 1),
        ] {
            assert!(bad.is_err());
        }
        assert_eq!(
            TraceConfig::build(TraceMode::Udp, "::1", Some(53), None, SEC, 1, 1, 1)
                .unwrap()
                .port,
            53
        );
    }

    /// Time-exceeded from `router` quoting our probe `bytes`.
    fn time_exceeded_v4(_s: &TraceSession<'_>, router: &str, probe: &[u8]) -> Vec<u8> {
        use wrex_core::encode::{EncodeOpts, encode};
        use wrex_core::spec::{LayerSpec, PacketSpec};
        let reg = registry();
        let mut ip_fields = std::collections::BTreeMap::new();
        ip_fields.insert("src".into(), Value::Ipv4(router.parse().unwrap()));
        ip_fields.insert("dst".into(), Value::Ipv4("127.0.0.1".parse().unwrap()));
        ip_fields.insert("ttl".into(), Value::Int(1));
        let mut icmp_fields = std::collections::BTreeMap::new();
        icmp_fields.insert("type".into(), Value::Int(11));
        icmp_fields.insert("code".into(), Value::Int(0));
        let spec = PacketSpec::new(
            vec![
                LayerSpec::with_fields("ipv4", ip_fields),
                LayerSpec::with_fields("icmp", icmp_fields),
            ],
            Some(Value::Bytes(probe.to_vec().into())),
        );
        encode(
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

    /// Echo reply from the target (icmp mode).
    fn echo_reply_v4(s: &TraceSession<'_>) -> Vec<u8> {
        packet::icmp_echo(
            &registry(),
            s.cfg.target,
            s.src,
            0,
            s.identity.id,
            s.identity.seq as u16,
        )
        .unwrap()
        .to_vec()
    }

    fn frame(bytes: Vec<u8>) -> Frame {
        Frame {
            bytes: Bytes::from(bytes),
            iface: "scripted".into(),
            ts: std::time::SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn icmp_walk_two_hops_then_reached() {
        let reg = registry();
        let mut s = TraceSession::new(
            &reg,
            cfg(TraceMode::Icmp, "127.0.0.1"),
            crate::target::ScanAddr::V4("127.0.0.1".parse().unwrap()),
            t0(),
        )
        .unwrap();
        // ttl 1
        let probe = send_probe(&mut s);
        let p = dissect(&reg, &probe, "ipv4");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[0].fields.get("ttl"), Some(&Value::Int(1)));
        assert_eq!(
            p.layers[1].fields.get("echo.id"),
            Some(&Value::Int(s.identity.id as u128))
        );

        let te = time_exceeded_v4(&s, "10.0.0.1", &probe);
        s.on_frame(frame(te), t0() + 5 * MS);
        let hops = drain_results(&mut s);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].hop, 1);
        assert_eq!(hops[0].state, "hop");
        assert_eq!(
            hops[0].hop_addr,
            Some(crate::target::ScanAddr::V4("10.0.0.1".parse().unwrap()))
        );
        assert_eq!(hops[0].attempts, 1);
        assert!(hops[0].rtt_ms.unwrap() >= 5);

        // ttl 2 → echo reply → reached, walk ends
        let probe2 = send_probe(&mut s);
        let p2 = dissect(&reg, &probe2, "ipv4");
        assert_eq!(p2.layers[0].fields.get("ttl"), Some(&Value::Int(2)));
        let reply = echo_reply_v4(&s);
        s.on_frame(frame(reply), t0() + 7 * MS);
        let hops = drain_results(&mut s);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].state, "reached");
        assert_eq!(hops[0].hop, 2);
        assert_eq!(hops[0].target.to_string(), "127.0.0.1");
        assert!(s.next_timeout().is_none(), "walk must end");
        assert!(s.poll_action().is_none());
    }

    #[test]
    fn silent_hop_then_max_hops_end() {
        let reg = registry();
        let mut s = TraceSession::new(
            &reg,
            TraceConfig::build(TraceMode::Icmp, "127.0.0.1", None, Some(2), SEC, 1, 1, 1).unwrap(),
            crate::target::ScanAddr::V4("127.0.0.1".parse().unwrap()),
            t0(),
        )
        .unwrap();
        send_probe(&mut s);
        // cross-talk quote first (must not resolve): a quote of someone
        // else's datagram.
        let foreign = packet::icmp_echo(
            &reg,
            crate::target::ScanAddr::V4("10.9.9.9".parse().unwrap()),
            crate::target::ScanAddr::V4("10.9.9.9".parse().unwrap()),
            8,
            0xdead,
            1,
        )
        .unwrap();
        let te = time_exceeded_v4(&s, "10.0.0.1", &foreign);
        s.on_frame(frame(te), t0() + MS);
        assert!(s.poll_result().is_none(), "cross-talk quote must not hop");

        // two attempts (retries 1) then silent hop 1
        s.on_timeout(t0() + 2 * SEC);
        assert!(s.poll_action().is_none(), "backoff gate holds the retry");
        s.on_timeout(t0() + 4 * SEC); // gate arrived → opened
        let probe = send_probe(&mut s); // retransmission, same ttl
        let p = dissect(&reg, &probe, "ipv4");
        assert_eq!(p.layers[0].fields.get("ttl"), Some(&Value::Int(1)));
        s.on_timeout(t0() + 6 * SEC); // retransmission deadline passes
        let hops = drain_results(&mut s);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].state, "silent");
        assert_eq!(hops[0].hop_addr, None);
        assert_eq!(hops[0].rtt_ms, None);
        assert_eq!(hops[0].attempts, 2);

        // hop 2: reached ends the walk (max_hops 2)
        let probe2 = send_probe(&mut s);
        let te2 = time_exceeded_v4(&s, "10.0.0.2", &probe2);
        // ttl advanced
        let p2 = dissect(&reg, &probe2, "ipv4");
        assert_eq!(p2.layers[0].fields.get("ttl"), Some(&Value::Int(2)));
        s.on_frame(frame(te2), t0() + 4 * SEC);
        let hops = drain_results(&mut s);
        assert_eq!(hops.len(), 1);
        // max_hops reached → walk done even on a plain hop
        assert_eq!(hops[0].state, "hop");
        assert!(s.next_timeout().is_none(), "max_hops ends the walk");
        assert!(s.poll_result().is_none());
    }

    #[test]
    fn udp_port_unreachable_ends_walk() {
        let reg = registry();
        let target = crate::target::ScanAddr::V4("127.0.0.1".parse().unwrap());
        let c = TraceConfig::build(TraceMode::Udp, "127.0.0.1", Some(40404), None, SEC, 0, 1, 7)
            .unwrap();
        let mut s = TraceSession::new(&reg, c.clone(), target, t0()).unwrap();
        let probe = send_probe(&mut s);
        let p = dissect(&reg, &probe, "ipv4");
        assert_eq!(p.layers[0].fields.get("ttl"), Some(&Value::Int(1)));
        assert_eq!(p.layers[1].kind, "udp");
        assert_eq!(p.layers[1].fields.get("dport"), Some(&Value::Int(40404)));

        // ICMP 3/3 quoting our datagram → reached (port unreachable)
        use wrex_core::encode::{EncodeOpts, encode};
        use wrex_core::spec::{LayerSpec, PacketSpec};
        let mut ip_fields = std::collections::BTreeMap::new();
        ip_fields.insert("src".into(), Value::Ipv4("127.0.0.1".parse().unwrap()));
        ip_fields.insert("dst".into(), Value::Ipv4("127.0.0.1".parse().unwrap()));
        ip_fields.insert("ttl".into(), Value::Int(64));
        let mut icmp_fields = std::collections::BTreeMap::new();
        icmp_fields.insert("type".into(), Value::Int(3));
        icmp_fields.insert("code".into(), Value::Int(3));
        let spec = PacketSpec::new(
            vec![
                LayerSpec::with_fields("ipv4", ip_fields),
                LayerSpec::with_fields("icmp", icmp_fields),
            ],
            Some(Value::Bytes(probe.to_vec().into())),
        );
        let unreach = encode(
            &reg,
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap()
        .bytes
        .to_vec();
        s.on_frame(frame(unreach), t0() + 3 * MS);
        let hops = drain_results(&mut s);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].state, "reached");
        assert!(s.next_timeout().is_none());
    }

    #[test]
    fn tcp_synack_reaches_and_backoff_paces() {
        let reg = registry();
        let target = crate::target::ScanAddr::V4("127.0.0.1".parse().unwrap());
        let c =
            TraceConfig::build(TraceMode::Tcp, "127.0.0.1", Some(443), None, SEC, 1, 2, 9).unwrap();
        let mut s = TraceSession::new(&reg, c, target, t0()).unwrap();
        let probe = send_probe(&mut s);
        let p = dissect(&reg, &probe, "ipv4");
        assert_eq!(p.layers[1].kind, "tcp");
        assert_eq!(p.layers[1].fields.get("dport"), Some(&Value::Int(443)));

        // time-exceeded quoting a FOREIGN datagram → cross-talk
        let foreign = packet::tcp(&reg, target, target, 1234, 80, 5, None, FLAG_SYN).unwrap();
        let te = time_exceeded_v4(&s, "10.0.0.1", &foreign);
        s.on_frame(frame(te), t0() + MS);
        assert!(s.poll_result().is_none());

        // deadline → backoff (base 2): next send is gated 2*wait out
        s.on_timeout(t0() + SEC);
        assert!(s.poll_action().is_none(), "backoff gates the retry");
        // ...until the gate opens
        s.on_frame(
            Frame {
                bytes: Bytes::new(),
                iface: "x".into(),
                ts: std::time::SystemTime::UNIX_EPOCH,
            },
            t0() + 2 * SEC,
        );
        let _retry = send_probe(&mut s);

        // SYN+ACK on our 4-tuple → reached
        let sa = packet::tcp(
            &reg,
            target,
            target,
            443,
            s.identity.sport,
            77,
            Some(s.identity.seq.wrapping_add(1)),
            FLAG_SYN | FLAG_ACK,
        )
        .unwrap()
        .to_vec();
        s.on_frame(frame(sa), t0() + 3 * SEC);
        let hops = drain_results(&mut s);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].state, "reached");
        assert!(s.next_timeout().is_none());
    }

    #[test]
    fn run_loop_scripted_walk() {
        // Same seed → identical identity: craft replies against a twin.
        let reg = registry();
        let clock = Arc::new(FakeClock::new());
        let t = clock.now();
        let target = crate::target::ScanAddr::V4("127.0.0.1".parse().unwrap());
        let c = cfg(TraceMode::Icmp, "127.0.0.1");

        let twin = TraceSession::new(&reg, c.clone(), target, t).unwrap();
        let mut twin = twin;
        let probe1 = match twin.poll_action() {
            Some(SessionAction::Send(b)) => b.to_vec(),
            _ => panic!("twin probe 1"),
        };
        let te1 = time_exceeded_v4(&twin, "10.0.0.1", &probe1);
        // advance ttl on the twin to learn probe 2's bytes
        twin.on_frame(frame(te1.clone()), t + MS);
        let probe2 = match twin.poll_action() {
            Some(SessionAction::Send(b)) => b.to_vec(),
            _ => panic!("twin probe 2"),
        };
        let te2 = time_exceeded_v4(&twin, "10.0.0.2", &probe2);
        twin.on_frame(frame(te2.clone()), t + 2 * MS);
        let probe3 = match twin.poll_action() {
            Some(SessionAction::Send(b)) => b.to_vec(),
            _ => panic!("twin probe 3"),
        };
        let _ = probe3;
        // the echo reply names the (same-seeded) identity
        let reply = packet::icmp_echo(
            &reg,
            target,
            target,
            0,
            twin.identity.id,
            twin.identity.seq as u16,
        )
        .unwrap()
        .to_vec();

        let mut session = TraceSession::new(&reg, c, target, t).unwrap();
        let mut driver = ScriptedDriver::new(clock.clone(), vec![te1, te2, reply]);
        let out = run(&mut session, &mut driver, clock.as_ref()).unwrap();
        assert_eq!(out.len(), 3, "{out:?}");
        assert_eq!(out[0].state, "hop");
        assert_eq!(out[1].state, "hop");
        assert_eq!(out[2].state, "reached");
        assert_eq!(out[2].hop, 3);
    }

    #[test]
    fn v6_walk_and_text_render() {
        let reg = registry();
        let target = crate::target::ScanAddr::V6("::1".parse().unwrap());
        let c = TraceConfig::build(TraceMode::Icmp, "::1", None, None, SEC, 1, 1, 3).unwrap();
        let mut s = TraceSession::new(&reg, c.clone(), target, t0()).unwrap();
        let probe = send_probe(&mut s);
        let p = dissect(&reg, &probe, "ipv6");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[0].fields.get("hop_limit"), Some(&Value::Int(1)));
        assert_eq!(p.layers[1].fields.get("type"), Some(&Value::Int(128)));

        // ICMPv6 time-exceeded (type 3) quoting our echo
        use wrex_core::encode::{EncodeOpts, encode};
        use wrex_core::spec::{LayerSpec, PacketSpec};
        let mut ip_fields = std::collections::BTreeMap::new();
        ip_fields.insert("src".into(), Value::Ipv6("fe80::1".parse().unwrap()));
        ip_fields.insert("dst".into(), Value::Ipv6("::1".parse().unwrap()));
        let mut icmp_fields = std::collections::BTreeMap::new();
        icmp_fields.insert("type".into(), Value::Int(3));
        icmp_fields.insert("code".into(), Value::Int(0));
        let spec = PacketSpec::new(
            vec![
                LayerSpec::with_fields("ipv6", ip_fields),
                LayerSpec::with_fields("icmpv6", icmp_fields),
            ],
            Some(Value::Bytes(probe.to_vec().into())),
        );
        let te = encode(
            &reg,
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap()
        .bytes
        .to_vec();
        s.on_frame(frame(te), t0() + MS);
        let hops = drain_results(&mut s);
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].state, "hop");
        assert_eq!(
            hops[0].hop_addr.map(|a| a.to_string()),
            Some("fe80::1".to_string())
        );
        // jsonl shape
        let j = serde_json::to_value(&hops[0]).unwrap();
        assert_eq!(j["hop"], 1);
        assert_eq!(j["target"], "::1");
        assert_eq!(j["state"], "hop");
        assert_eq!(j["attempts"], 1);
        // text rendering
        let mut s2 = TraceSession::new(&reg, c, target, t0()).unwrap();
        send_probe(&mut s2);
        // retries 1: retransmit once, then the second deadline silences.
        s2.on_timeout(t0() + 10 * SEC);
        s2.on_timeout(t0() + 11 * SEC); // backoff gate arrives → opens
        send_probe(&mut s2); // the retransmission
        s2.on_timeout(t0() + 20 * SEC);
        let silent = drain_results(&mut s2).pop().unwrap();
        assert_eq!(silent.text_line(), "1  *  silent");
        assert_eq!(silent.attempts, 2);
        assert!(silent.rtt_ms.is_none());
        assert_eq!(
            hops[0].text_line(),
            format!("1  fe80::1  hop  ({}ms)", hops[0].rtt_ms.unwrap())
        );
    }

    #[test]
    fn registry_and_family_gates() {
        let mut reg = Registry::empty();
        reg.register(&wrex_proto_ip::CODEC);
        let c = cfg(TraceMode::Icmp, "127.0.0.1");
        assert!(
            TraceSession::new(
                &reg,
                c,
                crate::target::ScanAddr::V4("127.0.0.1".parse().unwrap()),
                t0()
            )
            .is_err()
        );
        let reg = registry();
        // source family mismatch
        assert!(
            TraceSession::new(
                &reg,
                cfg(TraceMode::Icmp, "::1"),
                crate::target::ScanAddr::V4("127.0.0.1".parse().unwrap()),
                t0()
            )
            .is_err()
        );
    }
}
