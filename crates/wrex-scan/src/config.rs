//! Scan configuration: modes, defaults and validation (grammar errors
//! are `String`, mapped to exit-2 usage errors by the CLI).

use std::time::Duration;

use crate::target::{Family, ScanAddr, parse_ports, parse_targets};

/// Probe mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanMode {
    /// TCP SYN ("half-open") scan: SYN probe, SYN+ACK → open, RST →
    /// closed, exhaustion → filtered.
    Syn,
    /// TCP connect scan: complete the handshake (ACK) before
    /// classifying open, then RST to close.
    Connect,
    /// TCP FIN scan (nmap -sF): bare FIN probe, RST → closed, any
    /// SYN/ACK → unfiltered, exhaustion → open|filtered.
    Fin,
    /// TCP NULL scan (nmap -sN): flagless probe, same classification
    /// as FIN.
    Null,
    /// TCP XMAS scan (nmap -sX): FIN+PSH+URG probe, same
    /// classification as FIN.
    Xmas,
    /// TCP ACK scan (nmap -sA): bare ACK probe, any RST → unfiltered,
    /// exhaustion → filtered (the port open/closed question is not
    /// answered — this mode maps firewall filtering).
    Ack,
    /// UDP scan: empty datagram; any UDP reply → open, ICMP
    /// port-unreachable → closed, other ICMP unreachables → filtered,
    /// exhaustion → open|filtered.
    Udp,
    /// ICMP echo sweep (host discovery): ports are illegal. Over v6
    /// targets this is ICMPv6 echo (type 128/129).
    Icmp,
    /// ARP ping sweep (host discovery): ARP request per target over
    /// the Ethernet driver, reply → alive, exhaustion → dead. v4
    /// targets only, L2-adjacent by contract (frames inject on `-i`).
    Arp,
    /// NDP host discovery (v6): unicast Neighbor Solicitation per
    /// target (type 135, SLLA carried), Neighbor Advertisement →
    /// alive, exhaustion → dead. v6 targets only.
    Ndp,
    /// MLD group discovery (v6): MLDv1 query (type 130) per target
    /// (a multicast group address), MLDv1 report naming the group →
    /// alive (the group has members), exhaustion → dead. v6 only.
    Mld,
}

impl ScanMode {
    /// Default mode (`syn`).
    pub const DEFAULT: Self = Self::Syn;

    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw {
            None => Ok(Self::DEFAULT),
            Some("syn") => Ok(Self::Syn),
            Some("connect") => Ok(Self::Connect),
            Some("fin") => Ok(Self::Fin),
            Some("null") => Ok(Self::Null),
            Some("xmas") => Ok(Self::Xmas),
            Some("ack") => Ok(Self::Ack),
            Some("udp") => Ok(Self::Udp),
            Some("icmp") => Ok(Self::Icmp),
            Some("arp") => Ok(Self::Arp),
            Some("ndp") => Ok(Self::Ndp),
            Some("mld") => Ok(Self::Mld),
            Some(other) => Err(format!(
                "unknown scan mode `{other}` (syn|connect|fin|null|xmas|ack|udp|icmp|arp|ndp|mld)"
            )),
        }
    }

    /// Wire protocol name for result rendering over `family` (the icmp
    /// mode speaks icmpv6 over v6 targets).
    pub const fn proto_for(self, family: Family) -> &'static str {
        match self {
            Self::Syn | Self::Connect | Self::Fin | Self::Null | Self::Xmas | Self::Ack => "tcp",
            Self::Udp => "udp",
            Self::Icmp => family.echo_kind(),
            Self::Arp => "arp",
            Self::Ndp | Self::Mld => "icmpv6",
        }
    }

    /// Wire protocol name over IPv4 targets (source compatibility).
    pub const fn proto(self) -> &'static str {
        self.proto_for(Family::V4)
    }

    /// Registry kinds this mode needs registered over `family`.
    pub const fn needs_for(self, family: Family) -> &'static [&'static str] {
        match self {
            Self::Syn | Self::Connect | Self::Fin | Self::Null | Self::Xmas | Self::Ack => {
                match family {
                    Family::V4 => &["ipv4", "tcp"],
                    Family::V6 => &["ipv6", "tcp"],
                }
            }
            Self::Udp => match family {
                Family::V4 => &["ipv4", "udp"],
                Family::V6 => &["ipv6", "udp"],
            },
            Self::Icmp => match family {
                Family::V4 => &["ipv4", "icmp"],
                Family::V6 => &["ipv6", "icmpv6"],
            },
            Self::Arp => &["eth", "arp"],
            Self::Ndp | Self::Mld => &["ipv6", "icmpv6"],
        }
    }

    /// Registry kinds this mode needs over IPv4 targets (source compat).
    pub const fn needs(self) -> &'static [&'static str] {
        self.needs_for(Family::V4)
    }

    /// Host-discovery modes take one probe per target (no ports).
    pub const fn is_host_mode(self) -> bool {
        matches!(self, Self::Icmp | Self::Arp | Self::Ndp | Self::Mld)
    }

    /// The only family a host-discovery mode may run over (`None` =
    /// either family, the tcp/udp/icmp modes).
    pub const fn family_gate(self) -> Option<Family> {
        match self {
            Self::Arp => Some(Family::V4),
            Self::Ndp | Self::Mld => Some(Family::V6),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Syn => "syn",
            Self::Connect => "connect",
            Self::Fin => "fin",
            Self::Null => "null",
            Self::Xmas => "xmas",
            Self::Ack => "ack",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Arp => "arp",
            Self::Ndp => "ndp",
            Self::Mld => "mld",
        }
    }
}

/// Default pacing when neither `--rate` nor `--interval` is given:
/// uncapped burst, throttled by `concurrent` — nmap's parallelism
/// model (the perf-diff defaults row measured the old seeded 100pps
/// default ~80x slower out of the box than nmap's adaptive burst on
/// instant-RST loopback ports). `--rate`/`--interval`/`--jitter`
/// remain opt-in seeded pacing for polite or stealth runs.
pub const DEFAULT_INTERVAL: Duration = Duration::ZERO;

/// Extra attempts per probe beyond the first.
pub const DEFAULT_RETRIES: u32 = 1;

/// Per-attempt reply timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

/// Max in-flight probes.
pub const DEFAULT_CONCURRENT: usize = 256;

/// Timing templates `-T0..-T5` (nmap's `-T` sugar): each is a named
/// bundle of the T2 pacing vocabulary — a pacing step, a reply
/// timeout, extra attempts and a concurrency budget. Pure sugar:
/// every explicit `--rate/--interval/--timeout/--retries/--concurrent`
/// flag wins over the template (the recipe-over-CLI precedent).
/// `--seed` is NEVER implied — reproducibility stays explicit.
pub const TIMING_TEMPLATES: [TimingTemplate; 6] = [
    TimingTemplate {
        name: "T0",
        doc: "polite serial: 1s pacing, 5s timeout, one retransmission, 16 in flight",
        interval: Duration::from_secs(1),
        timeout: Duration::from_secs(5),
        retries: 2,
        concurrent: 16,
    },
    TimingTemplate {
        name: "T1",
        doc: "cautious: 200ms pacing, 3s timeout, one retransmission, 64 in flight",
        interval: Duration::from_millis(200),
        timeout: Duration::from_secs(3),
        retries: 1,
        concurrent: 64,
    },
    TimingTemplate {
        name: "T2",
        doc: "polite parallel: 50ms pacing, 2s timeout, 128 in flight",
        interval: Duration::from_millis(50),
        timeout: Duration::from_secs(2),
        retries: 1,
        concurrent: 128,
    },
    TimingTemplate {
        name: "T3",
        doc: "normal: uncapped burst, 1s timeout, one retransmission, 256 in flight (the defaults)",
        interval: DEFAULT_INTERVAL,
        timeout: DEFAULT_TIMEOUT,
        retries: DEFAULT_RETRIES,
        concurrent: DEFAULT_CONCURRENT,
    },
    TimingTemplate {
        name: "T4",
        doc: "aggressive: uncapped burst, 500ms timeout, no retransmission, 512 in flight",
        interval: DEFAULT_INTERVAL,
        timeout: Duration::from_millis(500),
        retries: 0,
        concurrent: 512,
    },
    TimingTemplate {
        name: "T5",
        doc: "insane: uncapped burst, 250ms timeout, no retransmission, 1024 in flight",
        interval: DEFAULT_INTERVAL,
        timeout: Duration::from_millis(250),
        retries: 0,
        concurrent: 1024,
    },
];

/// One `-T0..-T5` timing template (see [`TIMING_TEMPLATES`]).
#[derive(Clone, Copy, Debug)]
pub struct TimingTemplate {
    pub name: &'static str,
    pub doc: &'static str,
    pub interval: Duration,
    pub timeout: Duration,
    pub retries: u32,
    pub concurrent: usize,
}

impl TimingTemplate {
    /// Parse a `-T0..-T5` template selector (`None` → default T3).
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        let Some(raw) = raw else {
            return Ok(TIMING_TEMPLATES[3]);
        };
        // accept `T4`, `t4` and the bare `4` (clap hands the flag
        // value through untouched)
        let upper = raw.to_ascii_uppercase();
        let want = match upper.strip_prefix('T') {
            Some(rest) => format!("T{rest}"),
            None => format!("T{upper}"),
        };
        for t in TIMING_TEMPLATES {
            if t.name == want {
                return Ok(t);
            }
        }
        Err(timing_error(raw))
    }
}

fn timing_error(raw: &str) -> String {
    format!("unknown timing template `{raw}` (T0..T5)")
}

/// Probe-count guard: targets × ports beyond this is almost certainly a
/// typo (the single-threaded runtime would take hours) → usage error.
pub const MAX_PROBES: usize = 1 << 20;

/// Default TCP port list for `syn`/`connect` (a committed, documented
/// surface: exactly 100, sorted, unique). `udp` has no meaningful
/// default and requires `--ports`; `icmp` takes none.
pub const DEFAULT_TCP_PORTS: &[u16] = &[
    7, 9, 13, 21, 22, 23, 25, 37, 53, 67, 68, 69, 79, 80, 81, 82, 83, 84, 85, 88, 98, 99, 100, 109,
    110, 111, 113, 119, 123, 135, 137, 138, 139, 143, 144, 161, 162, 177, 179, 199, 213, 389, 407,
    427, 443, 444, 445, 464, 500, 502, 512, 513, 514, 515, 522, 523, 524, 526, 540, 543, 544, 548,
    554, 555, 563, 587, 591, 593, 601, 623, 631, 636, 646, 647, 664, 666, 691, 705, 706, 711, 749,
    750, 751, 777, 783, 800, 801, 808, 843, 873, 880, 888, 898, 900, 993, 995, 1080, 1433, 1521,
    2049,
];

/// A validated scan configuration.
#[derive(Clone, Debug)]
pub struct ScanConfig {
    pub mode: ScanMode,
    /// Expanded, deduplicated, sorted target addresses (one family per
    /// scan — enforced by the target grammar).
    pub targets: Vec<ScanAddr>,
    /// Expanded, deduplicated, sorted ports (empty for icmp).
    pub ports: Vec<u16>,
    /// Pacing step between probe sends (`ZERO` = uncapped burst).
    pub interval: Duration,
    /// Seeded jitter magnitude (±) applied to the pacing step.
    pub jitter: Duration,
    /// RNG seed (probe identities, jitter).
    pub seed: u64,
    /// Extra attempts per probe beyond the first.
    pub retries: u32,
    /// Per-attempt reply timeout.
    pub timeout: Duration,
    /// Max in-flight probes.
    pub concurrent: usize,
}

impl ScanConfig {
    /// Validate and build. `ports_raw` is the `--ports SPEC` (parsed
    /// here because the defaults are mode-dependent); `interval_raw` is
    /// the already-resolved pacing step (`--rate N` sugar included).
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        mode: ScanMode,
        targets_raw: &[String],
        ports_raw: Option<&str>,
        interval: Duration,
        jitter: Duration,
        seed: u64,
        retries: u32,
        timeout: Duration,
        concurrent: usize,
    ) -> Result<Self, String> {
        let targets = parse_targets(targets_raw)?;
        if targets.is_empty() {
            return Err("no targets given".to_string());
        }

        // Family gates: arp is Ethernet-adjacent v4 only; ndp/mld are
        // NDP/MLD v6 only (the T10b/T17b machinery).
        if let Some(gate) = mode.family_gate() {
            let family = targets.first().map(|t| t.family()).unwrap_or(Family::V4);
            if family != gate {
                return Err(format!(
                    "{} mode requires {} targets",
                    mode.as_str(),
                    gate.ip_kind()
                ));
            }
        }

        // Port resolution is mode-dependent.
        let ports = match (mode, ports_raw) {
            (ScanMode::Icmp, Some(_)) => {
                return Err("icmp mode takes no --ports (it is a host sweep)".to_string());
            }
            (ScanMode::Arp, Some(_)) => {
                return Err("arp mode takes no --ports (it is a host sweep)".to_string());
            }
            (ScanMode::Ndp, Some(_)) => {
                return Err("ndp mode takes no --ports (it is a host sweep)".to_string());
            }
            (ScanMode::Mld, Some(_)) => {
                return Err("mld mode takes no --ports (it is a group sweep)".to_string());
            }
            (ScanMode::Udp, None) => {
                return Err(
                    "udp mode requires --ports (there is no meaningful default)".to_string()
                );
            }
            (_, Some(spec)) => parse_ports(spec)?,
            (
                ScanMode::Syn
                | ScanMode::Connect
                | ScanMode::Fin
                | ScanMode::Null
                | ScanMode::Xmas
                | ScanMode::Ack,
                None,
            ) => DEFAULT_TCP_PORTS.to_vec(),
            (ScanMode::Icmp | ScanMode::Arp | ScanMode::Ndp | ScanMode::Mld, None) => Vec::new(),
        };

        // Probe-count guard.
        let probe_count = targets.len().saturating_mul(ports.len().max(1));
        if probe_count > MAX_PROBES {
            return Err(format!(
                "scan of {} probes exceeds the {} probe cap; narrow --ports or targets",
                probe_count, MAX_PROBES
            ));
        }

        if timeout.is_zero() {
            return Err("scan --timeout must be > 0".to_string());
        }
        if concurrent == 0 {
            return Err("scan --concurrent must be >= 1".to_string());
        }

        Ok(Self {
            mode,
            targets,
            ports,
            interval,
            jitter,
            seed,
            retries,
            timeout,
            concurrent,
        })
    }

    /// The shared target family (grammar-enforced single family).
    pub fn family(&self) -> Family {
        self.targets
            .first()
            .map(|t| t.family())
            .unwrap_or(Family::V4)
    }

    /// Total number of probes this scan will run.
    pub fn probe_count(&self) -> usize {
        match self.mode {
            ScanMode::Icmp | ScanMode::Arp | ScanMode::Ndp | ScanMode::Mld => self.targets.len(),
            _ => self.targets.len() * self.ports.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(mode: ScanMode, ports: Option<&str>) -> Result<ScanConfig, String> {
        ScanConfig::build(
            mode,
            &["127.0.0.1".to_string()],
            ports,
            Duration::from_millis(10),
            Duration::ZERO,
            42,
            1,
            Duration::from_secs(1),
            256,
        )
    }

    #[test]
    fn mode_parse() {
        assert_eq!(ScanMode::parse(None).unwrap(), ScanMode::Syn);
        assert_eq!(ScanMode::parse(Some("udp")).unwrap(), ScanMode::Udp);
        assert_eq!(ScanMode::parse(Some("fin")).unwrap(), ScanMode::Fin);
        assert_eq!(ScanMode::parse(Some("null")).unwrap(), ScanMode::Null);
        assert_eq!(ScanMode::parse(Some("xmas")).unwrap(), ScanMode::Xmas);
        assert_eq!(ScanMode::parse(Some("ack")).unwrap(), ScanMode::Ack);
        assert_eq!(ScanMode::parse(Some("arp")).unwrap(), ScanMode::Arp);
        assert_eq!(ScanMode::parse(Some("ndp")).unwrap(), ScanMode::Ndp);
        assert_eq!(ScanMode::parse(Some("mld")).unwrap(), ScanMode::Mld);
        assert!(ScanMode::parse(Some("synn")).is_err());
        assert_eq!(ScanMode::Udp.proto(), "udp");
        assert_eq!(ScanMode::Connect.needs(), &["ipv4", "tcp"]);
        assert_eq!(ScanMode::Fin.proto_for(Family::V6), "tcp");
        assert_eq!(ScanMode::Ack.needs_for(Family::V6), &["ipv6", "tcp"]);
        assert_eq!(ScanMode::Arp.needs(), &["eth", "arp"]);
        assert_eq!(ScanMode::Ndp.needs_for(Family::V6), &["ipv6", "icmpv6"]);
        assert_eq!(ScanMode::Mld.proto_for(Family::V6), "icmpv6");
        assert!(ScanMode::Arp.is_host_mode());
        assert_eq!(ScanMode::Arp.family_gate(), Some(Family::V4));
        assert_eq!(ScanMode::Mld.family_gate(), Some(Family::V6));
        assert_eq!(ScanMode::Syn.family_gate(), None);
        assert_eq!(ScanMode::Xmas.as_str(), "xmas");
    }

    #[test]
    fn timing_templates() {
        // default = T3 = the scan defaults
        let t3 = TimingTemplate::parse(None).unwrap();
        assert_eq!(t3.name, "T3");
        assert_eq!(t3.interval, DEFAULT_INTERVAL);
        assert_eq!(t3.timeout, DEFAULT_TIMEOUT);
        assert_eq!(t3.retries, DEFAULT_RETRIES);
        assert_eq!(t3.concurrent, DEFAULT_CONCURRENT);
        let t0 = TimingTemplate::parse(Some("T0")).unwrap();
        assert_eq!(t0.interval, Duration::from_secs(1));
        assert!(t0.concurrent < t3.concurrent);
        // case-insensitive T prefix, and the bare digit form
        assert_eq!(TimingTemplate::parse(Some("t5")).unwrap().name, "T5");
        assert_eq!(TimingTemplate::parse(Some("T4")).unwrap().name, "T4");
        assert_eq!(TimingTemplate::parse(Some("4")).unwrap().name, "T4");
        assert!(TimingTemplate::parse(Some("T6")).is_err());
        assert!(TimingTemplate::parse(Some("fast")).is_err());
        assert!(TimingTemplate::parse(Some("")).is_err());
        assert!(TimingTemplate::parse(Some("6")).is_err());
        // committed invariants: monotone aggression
        let names: Vec<&str> = TIMING_TEMPLATES.iter().map(|t| t.name).collect();
        assert_eq!(names, vec!["T0", "T1", "T2", "T3", "T4", "T5"]);
    }

    #[test]
    fn host_mode_family_gates_and_ports() {
        // arp: v4 only, no ports
        let cfg = build(ScanMode::Arp, None).unwrap();
        assert!(cfg.ports.is_empty());
        assert_eq!(cfg.probe_count(), 1);
        assert!(build(ScanMode::Arp, Some("22")).is_err());
        let e = ScanConfig::build(
            ScanMode::Arp,
            &["::1".to_string()],
            None,
            Duration::ZERO,
            Duration::ZERO,
            1,
            1,
            Duration::from_secs(1),
            256,
        )
        .unwrap_err();
        assert!(e.contains("arp mode requires ipv4 targets"), "{e}");
        // ndp/mld: v6 only, no ports
        assert!(
            ScanConfig::build(
                ScanMode::Ndp,
                &["::1".to_string()],
                None,
                Duration::ZERO,
                Duration::ZERO,
                1,
                1,
                Duration::from_secs(1),
                256,
            )
            .is_ok()
        );
        for mode in [ScanMode::Ndp, ScanMode::Mld] {
            let e = ScanConfig::build(
                mode,
                &["127.0.0.1".to_string()],
                None,
                Duration::ZERO,
                Duration::ZERO,
                1,
                1,
                Duration::from_secs(1),
                256,
            )
            .unwrap_err();
            assert!(e.contains("ipv6 targets"), "{e}");
        }
    }

    #[test]
    fn variant_modes_default_ports() {
        for mode in [ScanMode::Fin, ScanMode::Null, ScanMode::Xmas, ScanMode::Ack] {
            let cfg = build(mode, None).unwrap();
            assert_eq!(cfg.ports, DEFAULT_TCP_PORTS.to_vec(), "{:?}", mode);
        }
    }

    #[test]
    fn default_ports_applied_and_udp_requires() {
        let cfg = build(ScanMode::Syn, None).unwrap();
        assert_eq!(cfg.ports, DEFAULT_TCP_PORTS.to_vec());
        assert!(build(ScanMode::Udp, None).is_err());
        let cfg = build(ScanMode::Udp, Some("53")).unwrap();
        assert_eq!(cfg.ports, vec![53]);
        assert!(build(ScanMode::Icmp, Some("22")).is_err());
        let cfg = build(ScanMode::Icmp, None).unwrap();
        assert!(cfg.ports.is_empty());
        assert_eq!(cfg.probe_count(), 1);
    }

    #[test]
    fn guards() {
        assert!(build(ScanMode::Syn, Some("0")).is_err());
        // probe cap
        let e = ScanConfig::build(
            ScanMode::Syn,
            &["10.0.0.0/24".to_string()],
            Some("1-5000"),
            Duration::from_millis(10),
            Duration::ZERO,
            1,
            1,
            Duration::from_secs(1),
            256,
        )
        .unwrap_err();
        assert!(e.contains("probe cap"), "{e}");
        // timeout / concurrent validation
        let e = ScanConfig::build(
            ScanMode::Icmp,
            &["127.0.0.1".to_string()],
            None,
            Duration::ZERO,
            Duration::ZERO,
            1,
            1,
            Duration::ZERO,
            256,
        )
        .unwrap_err();
        assert!(e.contains("timeout"), "{e}");
        let e = ScanConfig::build(
            ScanMode::Icmp,
            &["127.0.0.1".to_string()],
            None,
            Duration::ZERO,
            Duration::ZERO,
            1,
            1,
            Duration::from_secs(1),
            0,
        )
        .unwrap_err();
        assert!(e.contains("concurrent"), "{e}");
    }

    #[test]
    fn default_tcp_ports_invariants() {
        assert_eq!(DEFAULT_TCP_PORTS.len(), 100, "committed list size");
        let mut sorted = DEFAULT_TCP_PORTS.to_vec();
        sorted.sort_unstable();
        assert_eq!(sorted, DEFAULT_TCP_PORTS, "committed list is sorted");
        sorted.dedup();
        assert_eq!(sorted.len(), 100, "committed list is unique");
        assert!(DEFAULT_TCP_PORTS.iter().all(|p| (1..=65535).contains(p)));
    }
}
