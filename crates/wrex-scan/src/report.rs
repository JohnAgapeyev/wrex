//! Scan results: one record per resolved probe, streamed in resolution
//! order. `serde`-serializable for `--format json/jsonl`; text lines
//! render `127.0.0.1  443/tcp  open`.

use std::time::Duration;

use crate::service::ServiceMatch;
use crate::target::ScanAddr;

/// One resolved probe.
///
/// States: `open` / `closed` / `filtered` / `unfiltered` (tcp variants),
/// `open` / `closed` / `filtered` / `open|filtered` (udp), `alive` /
/// `dead` (icmp/arp/ndp/mld host discovery).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ScanResult {
    pub target: ScanAddr,
    /// Probed port (`None` for icmp/arp/ndp/mld).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// Wire protocol: `tcp` / `udp` / `icmp` / `icmpv6` / `arp`.
    pub proto: &'static str,
    /// Classification string (see type docs).
    pub state: &'static str,
    /// Sends performed for this probe (first + retransmissions).
    pub attempts: u32,
    /// Reply round-trip in milliseconds (`None` when no reply).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u64>,
    /// Service/version match (`--service` post-pass over open TCP
    /// ports; additive — absent unless the flag ran).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceMatch>,
}

impl ScanResult {
    /// Text rendering: `127.0.0.1  443/tcp  open` /
    /// `127.0.0.1  icmp  alive`, with the service suffix when the
    /// `--service` post-pass matched.
    pub fn text_line(&self) -> String {
        let base = match self.port {
            Some(port) => format!("{}  {}/{}  {}", self.target, port, self.proto, self.state),
            None => format!("{}  {}  {}", self.target, self.proto, self.state),
        };
        match &self.service {
            Some(m) => {
                let svc = match &m.version {
                    Some(v) => format!("{}/{}", m.service, v),
                    None => m.service.to_string(),
                };
                format!("{base}  {svc}")
            }
            None => base,
        }
    }

    /// Human milliseconds for the rtt (text suffix).
    pub fn rtt_hum(&self) -> Option<String> {
        self.rtt_ms.map(|ms| format!("{ms}ms"))
    }

    /// Round-trip from a duration, millisecond precision.
    pub fn rtt_from(d: Duration) -> u64 {
        d.as_millis().min(u64::MAX as u128) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_and_json() {
        let r = ScanResult {
            target: crate::target::ScanAddr::V4("127.0.0.1".parse().unwrap()),
            port: Some(443),
            proto: "tcp",
            state: "open",
            attempts: 1,
            rtt_ms: Some(2),
            service: None,
        };
        assert_eq!(r.text_line(), "127.0.0.1  443/tcp  open");
        let j = serde_json::to_value(&r).unwrap();
        assert_eq!(j["port"], 443);
        assert_eq!(j["target"], "127.0.0.1");
        assert_eq!(j["rtt_ms"], 2);
        assert!(j.get("payload").is_none());
        let r2 = ScanResult {
            target: crate::target::ScanAddr::V4("10.0.0.1".parse().unwrap()),
            port: None,
            proto: "icmp",
            state: "alive",
            attempts: 1,
            rtt_ms: None,
            service: None,
        };
        assert_eq!(r2.text_line(), "10.0.0.1  icmp  alive");
        let j2 = serde_json::to_value(&r2).unwrap();
        assert!(j2.get("port").is_none());
        assert!(j2.get("rtt_ms").is_none());
        let r3 = ScanResult {
            target: crate::target::ScanAddr::V6("::1".parse().unwrap()),
            port: Some(53),
            proto: "udp",
            state: "open",
            attempts: 1,
            rtt_ms: None,
            service: None,
        };
        assert_eq!(r3.text_line(), "::1  53/udp  open");
        let j3 = serde_json::to_value(&r3).unwrap();
        assert_eq!(j3["target"], "::1");
    }
}
