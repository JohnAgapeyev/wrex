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
    /// UDP scan: empty datagram; any UDP reply → open, ICMP
    /// port-unreachable → closed, other ICMP unreachables → filtered,
    /// exhaustion → open|filtered.
    Udp,
    /// ICMP echo sweep (host discovery): ports are illegal. Over v6
    /// targets this is ICMPv6 echo (type 128/129).
    Icmp,
}

impl ScanMode {
    /// Default mode (`syn`).
    pub const DEFAULT: Self = Self::Syn;

    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw {
            None => Ok(Self::DEFAULT),
            Some("syn") => Ok(Self::Syn),
            Some("connect") => Ok(Self::Connect),
            Some("udp") => Ok(Self::Udp),
            Some("icmp") => Ok(Self::Icmp),
            Some(other) => Err(format!(
                "unknown scan mode `{other}` (syn|connect|udp|icmp)"
            )),
        }
    }

    /// Wire protocol name for result rendering over `family` (the icmp
    /// mode speaks icmpv6 over v6 targets).
    pub fn proto_for(self, family: Family) -> &'static str {
        match self {
            Self::Syn | Self::Connect => "tcp",
            Self::Udp => "udp",
            Self::Icmp => family.echo_kind(),
        }
    }

    /// Wire protocol name over IPv4 targets (source compatibility).
    pub fn proto(self) -> &'static str {
        self.proto_for(Family::V4)
    }

    /// Registry kinds this mode needs registered over `family`.
    pub fn needs_for(self, family: Family) -> &'static [&'static str] {
        match self {
            Self::Syn | Self::Connect => match family {
                Family::V4 => &["ipv4", "tcp"],
                Family::V6 => &["ipv6", "tcp"],
            },
            Self::Udp => match family {
                Family::V4 => &["ipv4", "udp"],
                Family::V6 => &["ipv6", "udp"],
            },
            Self::Icmp => match family {
                Family::V4 => &["ipv4", "icmp"],
                Family::V6 => &["ipv6", "icmpv6"],
            },
        }
    }

    /// Registry kinds this mode needs over IPv4 targets (source compat).
    pub fn needs(self) -> &'static [&'static str] {
        self.needs_for(Family::V4)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Syn => "syn",
            Self::Connect => "connect",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }
}

/// Default send rate (packets/sec) when neither `--rate` nor `--interval`
/// is given: raw-injection into untrusted segments stays polite by
/// default. `--rate 0` (or `--interval 0`) removes the cap (burst).
pub const DEFAULT_RATE: u64 = 100;

/// Extra attempts per probe beyond the first.
pub const DEFAULT_RETRIES: u32 = 1;

/// Per-attempt reply timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

/// Max in-flight probes.
pub const DEFAULT_CONCURRENT: usize = 256;

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

        // Port resolution is mode-dependent.
        let ports = match (mode, ports_raw) {
            (ScanMode::Icmp, Some(_)) => {
                return Err("icmp mode takes no --ports (it is a host sweep)".to_string());
            }
            (ScanMode::Udp, None) => {
                return Err(
                    "udp mode requires --ports (there is no meaningful default)".to_string()
                );
            }
            (_, Some(spec)) => parse_ports(spec)?,
            (ScanMode::Syn | ScanMode::Connect, None) => DEFAULT_TCP_PORTS.to_vec(),
            (ScanMode::Icmp, None) => Vec::new(),
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
            ScanMode::Icmp => self.targets.len(),
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
        assert!(ScanMode::parse(Some("synn")).is_err());
        assert_eq!(ScanMode::Udp.proto(), "udp");
        assert_eq!(ScanMode::Connect.needs(), &["ipv4", "tcp"]);
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
