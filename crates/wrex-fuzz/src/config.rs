//! Prober configuration: modes, defaults and validation (grammar
//! errors are [`String`], mapped to exit-2 usage errors by the CLI).

use std::time::Duration;

use wrex_mut::Strategy;
use wrex_scan::target::{Family, ScanAddr, parse_ports, parse_targets};

/// Base probe packet shape (`wrex fuzz --mode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeMode {
    /// TCP SYN probe (like a syn scan): SYN, any matching segment
    /// (SYN+ACK, RST, …) is a recorded reply.
    Tcp,
    /// UDP empty datagram: any matching datagram is a reply; ICMP
    /// unreachables attribute per the quoted datagram.
    Udp,
    /// ICMP echo: type-0 replies with a matching id are recorded.
    Icmp,
}

impl ProbeMode {
    pub const DEFAULT: Self = Self::Udp;

    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw {
            None => Ok(Self::DEFAULT),
            Some("tcp") | Some("syn") => Ok(Self::Tcp),
            Some("udp") => Ok(Self::Udp),
            Some("icmp") => Ok(Self::Icmp),
            Some(other) => Err(format!("unknown fuzz mode `{other}` (tcp|udp|icmp)")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }

    /// Registry kinds this mode needs registered over `family`
    /// (tranche 7b: family-aware).
    pub fn needs_for(self, family: Family) -> &'static [&'static str] {
        match self {
            Self::Tcp => match family {
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
}

/// Mutated rounds per (target, port) beyond the optional baseline.
pub const DEFAULT_ROUNDS: u32 = 4;

/// A validated prober configuration.
#[derive(Clone, Debug)]
pub struct FuzzConfig {
    /// Probe base shape.
    pub mode: ProbeMode,
    /// Expanded, deduplicated, sorted target addresses (one family
    /// per run — enforced by the target grammar).
    pub targets: Vec<ScanAddr>,
    /// Expanded, deduplicated, sorted ports (empty for icmp).
    pub ports: Vec<u16>,
    /// Mutated rounds per (target, port).
    pub rounds: u32,
    /// Send one unmutated baseline probe per (target, port) first.
    pub baseline: bool,
    /// Mutation strategy for the mutated rounds.
    pub strategy: Strategy,
    /// Pacing step between probe sends (`ZERO` = uncapped burst).
    pub interval: Duration,
    /// Seeded jitter magnitude (±) applied to the pacing step.
    pub jitter: Duration,
    /// RNG seed (probe identities, mutation streams, jitter).
    pub seed: u64,
    /// Extra attempts per probe beyond the first.
    pub retries: u32,
    /// Per-attempt reply timeout.
    pub timeout: Duration,
    /// Max in-flight probes.
    pub concurrent: usize,
}

impl FuzzConfig {
    /// Validate and build. `ports_raw` is the `--ports SPEC` (the
    /// defaults are mode-dependent: tcp gets the committed top-100
    /// list, udp requires an explicit list, icmp takes none).
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        mode: ProbeMode,
        targets_raw: &[String],
        ports_raw: Option<&str>,
        rounds: u32,
        baseline: bool,
        strategy: Strategy,
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

        let ports = match (mode, ports_raw) {
            (ProbeMode::Icmp, Some(_)) => {
                return Err("icmp mode takes no --ports (it is a host sweep)".to_string());
            }
            (ProbeMode::Udp, None) => {
                return Err(
                    "udp mode requires --ports (there is no meaningful default)".to_string()
                );
            }
            // Icmp is a host sweep: ports stay empty; a `Some` was
            // rejected above and udp's `None` too, so `None` here is
            // only icmp (or tcp — which the next arm serves first).
            (_, Some(spec)) => parse_ports(spec)?,
            (ProbeMode::Tcp, None) => wrex_scan::DEFAULT_TCP_PORTS.to_vec(),
            // Only icmp reaches here (udp None returned above).
            (ProbeMode::Icmp, None) => Vec::new(),
        };

        if rounds == 0 && !baseline {
            return Err(
                "fuzz --rounds 0 sends nothing without --baseline (add rounds or --baseline)"
                    .to_string(),
            );
        }

        if timeout.is_zero() {
            return Err("fuzz --timeout must be > 0".to_string());
        }
        if concurrent == 0 {
            return Err("fuzz --concurrent must be >= 1".to_string());
        }

        Ok(Self {
            mode,
            targets,
            ports,
            rounds,
            baseline,
            strategy,
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

    /// Total probe count (baseline + mutated rounds per slot).
    pub fn probe_count(&self) -> usize {
        let per = self.rounds + u32::from(self.baseline);
        match self.mode {
            ProbeMode::Icmp => self.targets.len() * per.max(1) as usize,
            _ => self.targets.len() * self.ports.len().max(1) * per as usize,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(mode: ProbeMode, ports: Option<&str>) -> Result<FuzzConfig, String> {
        FuzzConfig::build(
            mode,
            &["127.0.0.1".to_string()],
            ports,
            4,
            true,
            Strategy::All,
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
        assert_eq!(ProbeMode::parse(None).unwrap(), ProbeMode::Udp);
        assert_eq!(ProbeMode::parse(Some("tcp")).unwrap(), ProbeMode::Tcp);
        assert_eq!(ProbeMode::parse(Some("syn")).unwrap(), ProbeMode::Tcp);
        assert!(ProbeMode::parse(Some("sctp")).is_err());
    }

    #[test]
    fn port_defaults_mirror_scan() {
        let cfg = build(ProbeMode::Tcp, None).unwrap();
        assert_eq!(cfg.ports, wrex_scan::DEFAULT_TCP_PORTS.to_vec());
        assert!(build(ProbeMode::Udp, None).is_err());
        assert!(build(ProbeMode::Udp, Some("53")).is_ok());
        assert!(build(ProbeMode::Icmp, Some("53")).is_err());
        let cfg = build(ProbeMode::Icmp, None).unwrap();
        assert!(cfg.ports.is_empty());
    }

    #[test]
    fn guards() {
        assert!(build(ProbeMode::Tcp, Some("0")).is_err());
        // rounds 0 without baseline sends nothing → usage error
        let e = FuzzConfig::build(
            ProbeMode::Udp,
            &["127.0.0.1".to_string()],
            Some("53"),
            0,
            false,
            Strategy::All,
            Duration::ZERO,
            Duration::ZERO,
            1,
            1,
            Duration::from_secs(1),
            256,
        )
        .unwrap_err();
        assert!(e.contains("--rounds 0"), "{e}");
        // baseline-only is legal
        assert!(
            FuzzConfig::build(
                ProbeMode::Udp,
                &["127.0.0.1".to_string()],
                Some("53"),
                0,
                true,
                Strategy::All,
                Duration::ZERO,
                Duration::ZERO,
                1,
                1,
                Duration::from_secs(1),
                256,
            )
            .is_ok()
        );
        let e = FuzzConfig::build(
            ProbeMode::Udp,
            &["127.0.0.1".to_string()],
            Some("53"),
            1,
            true,
            Strategy::All,
            Duration::ZERO,
            Duration::ZERO,
            1,
            1,
            Duration::ZERO,
            256,
        )
        .unwrap_err();
        assert!(e.contains("timeout"), "{e}");
    }

    #[test]
    fn probe_count_math() {
        let cfg = build(ProbeMode::Udp, Some("53,54")).unwrap(); // 2 ports, baseline+4
        assert_eq!(cfg.probe_count(), 2 * 5);
        let mut c = cfg.clone();
        c.rounds = 0;
        assert_eq!(c.probe_count(), 2);
        let c = build(ProbeMode::Icmp, None).unwrap();
        assert_eq!(c.probe_count(), 5);
    }
}
