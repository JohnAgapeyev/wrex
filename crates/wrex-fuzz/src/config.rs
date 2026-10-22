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
    /// HTTP/1.1 over kernel TCP (tranche 9b): the probe unit is one
    /// GET exchange — mutated *request* bytes (wrex-mut raw level),
    /// response bytes recorded until EOF/timeout.
    Http,
    /// DNS over kernel TCP (tranche 9b): the probe unit is one RFC 7766
    /// length-prefixed query — mutated seed bytes, response recorded.
    Dns,
}

impl ProbeMode {
    pub const DEFAULT: Self = Self::Udp;

    /// Is this an application-layer mode (kernel-stream transport)?
    pub fn is_app(self) -> bool {
        matches!(self, Self::Http | Self::Dns)
    }

    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw {
            None => Ok(Self::DEFAULT),
            Some("tcp") | Some("syn") => Ok(Self::Tcp),
            Some("udp") => Ok(Self::Udp),
            Some("icmp") => Ok(Self::Icmp),
            Some("http") => Ok(Self::Http),
            Some("dns") => Ok(Self::Dns),
            Some(other) => Err(format!(
                "unknown fuzz mode `{other}` (tcp|udp|icmp|http|dns)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Http => "http",
            Self::Dns => "dns",
        }
    }

    /// Registry kinds this mode needs registered over `family`
    /// (tranche 7b: family-aware). The app modes (http/dns, tranche
    /// 9b) need no codecs: their probes ride the kernel `TcpDriver`
    /// and mutation falls through to the request-bytes level.
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
            // The seed request is built verb-side (wrex-http /
            // wrex-dns); the raw-level mutation needs no registry.
            Self::Http | Self::Dns => &[],
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
    /// Wrap the app-mode probe connections in TLS (tranche 13b:
    /// https for `http`, DoT/RFC 7858 for `dns`). Requires an app
    /// mode; the raw modes inject at L3/L4 and never TLS-wrap.
    pub tls: bool,
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
        tls: bool,
    ) -> Result<Self, String> {
        // TLS wraps the kernel-stream app probes only: the raw modes
        // inject datagrams/frames at L3/L4 — there is no stream to
        // wrap (the T8a `TlsDriver` contract).
        if tls && !mode.is_app() {
            return Err(
                "--tls wraps the app-mode probes (http|dns); the raw modes inject at L3/L4"
                    .to_string(),
            );
        }
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
            // Tranche 9b app modes: conventional default ports (an
            // explicit --ports list still enumerates the slots);
            // tranche 13b: TLS picks the TLS-registered defaults
            // (https 443, DoT 853).
            (ProbeMode::Http, None) => vec![if tls { 443 } else { 80 }],
            (ProbeMode::Dns, None) => vec![if tls { 853 } else { 53 }],
            // Icmp is a host sweep: ports stay empty; a `Some` was
            // rejected above and udp's `None` too, so `None` here is
            // only icmp (or tcp — which the next arm serves first).
            (_, Some(spec)) => parse_ports(spec)?,
            (ProbeMode::Tcp, None) => wrex_scan::DEFAULT_TCP_PORTS.to_vec(),
            // Only icmp reaches here (udp/http/dns None returned above).
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
            tls,
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
        build_tls(mode, ports, false)
    }

    fn build_tls(mode: ProbeMode, ports: Option<&str>, tls: bool) -> Result<FuzzConfig, String> {
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
            tls,
        )
    }

    #[test]
    fn mode_parse() {
        assert_eq!(ProbeMode::parse(None).unwrap(), ProbeMode::Udp);
        assert_eq!(ProbeMode::parse(Some("tcp")).unwrap(), ProbeMode::Tcp);
        assert_eq!(ProbeMode::parse(Some("syn")).unwrap(), ProbeMode::Tcp);
        assert_eq!(ProbeMode::parse(Some("http")).unwrap(), ProbeMode::Http);
        assert_eq!(ProbeMode::parse(Some("dns")).unwrap(), ProbeMode::Dns);
        assert!(ProbeMode::parse(Some("sctp")).is_err());
        // tranche 9b: the app modes
        assert!(ProbeMode::Http.is_app());
        assert!(ProbeMode::Dns.is_app());
        assert!(!ProbeMode::Tcp.is_app());
        assert_eq!(ProbeMode::Http.as_str(), "http");
        assert_eq!(ProbeMode::Dns.as_str(), "dns");
        assert!(ProbeMode::Http.needs_for(Family::V4).is_empty());
    }

    #[test]
    fn app_mode_port_defaults() {
        // http defaults to 80, dns to 53 (explicit --ports overrides).
        let cfg = build(ProbeMode::Http, None).unwrap();
        assert_eq!(cfg.ports, vec![80]);
        let cfg = build(ProbeMode::Dns, None).unwrap();
        assert_eq!(cfg.ports, vec![53]);
        let cfg = build(ProbeMode::Http, Some("8080")).unwrap();
        assert_eq!(cfg.ports, vec![8080]);
        // --ports 0 stays a usage error for every mode.
        assert!(build(ProbeMode::Http, Some("0")).is_err());
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
            false,
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
                false,
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
            false,
        )
        .unwrap_err();
        assert!(e.contains("timeout"), "{e}");
    }

    /// Tranche 13b: `--tls` wraps the app-mode probes only.
    #[test]
    fn tls_gating_and_port_defaults() {
        // Raw modes reject --tls (L3/L4 injection has no stream).
        for mode in [ProbeMode::Tcp, ProbeMode::Udp, ProbeMode::Icmp] {
            let e = build_tls(mode, None, true).unwrap_err();
            assert!(e.contains("--tls"), "{e}");
        }
        // App modes accept it and pick the TLS-registered defaults.
        let cfg = build_tls(ProbeMode::Http, None, true).unwrap();
        assert!(cfg.tls);
        assert_eq!(cfg.ports, vec![443]);
        let cfg = build_tls(ProbeMode::Dns, None, true).unwrap();
        assert_eq!(cfg.ports, vec![853]);
        // Plain app defaults unchanged (80/53).
        assert_eq!(
            build_tls(ProbeMode::Http, None, false).unwrap().ports,
            vec![80]
        );
        assert_eq!(
            build_tls(ProbeMode::Dns, None, false).unwrap().ports,
            vec![53]
        );
        // An explicit --ports list overrides the TLS defaults too.
        assert_eq!(
            build_tls(ProbeMode::Http, Some("8443"), true)
                .unwrap()
                .ports,
            vec![8443]
        );
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
