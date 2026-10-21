//! [`Finding`]: the recorded outcome of one prober round — everything
//! an offline differential (or a `wrex send` replay) needs.

use serde::Serialize;

/// Probe outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// A frame matching the probe's reply key arrived (reply bytes
    /// recorded).
    Reply,
    /// No matching reply before the attempt budget ran out.
    Silence,
    /// An ICMP unreachable (type 3) quoting this probe's datagram;
    /// the code is carried (3 = port unreachable, …).
    Unreachable(#[serde(rename = "code")] u8),
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reply => "reply",
            Self::Silence => "silence",
            Self::Unreachable(_) => "unreachable",
        }
    }
}

/// One probed round's record. `probe_hex` is the exact sent wire
/// bytes (mutated or baseline); `reply_hex` the matched reply, when
/// one arrived.
#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    /// Probed target address (pre-mutation intent).
    pub target: wrex_scan::ScanAddr,
    /// Probed port (`None` for icmp).
    pub port: Option<u16>,
    /// Wire protocol (`tcp`/`udp`/`icmp`).
    pub proto: &'static str,
    /// Mutated round number (`None` = the unmutated baseline).
    pub round: Option<u32>,
    /// Strategy label: `baseline` or the mutation strategy name.
    pub strategy: &'static str,
    pub outcome: Outcome,
    /// Sends performed (first + retransmissions).
    pub attempts: u32,
    /// Round-trip to the matched reply, when one arrived.
    pub rtt_ms: Option<u64>,
    /// The exact probe wire bytes (replayable with `wrex send`).
    pub probe_hex: String,
    /// The matched reply wire bytes, when one arrived.
    pub reply_hex: Option<String>,
}

impl Finding {
    /// One-line text rendering (the `--format text` shape).
    pub fn text_line(&self) -> String {
        let port = self
            .port
            .map(|p| format!("{p}/{}", self.proto))
            .unwrap_or_else(|| self.proto.to_string());
        let round = self
            .round
            .map(|r| format!("round {r}"))
            .unwrap_or_else(|| "baseline".to_string());
        let mut line = format!(
            "{}  {}  {} ({})  {}",
            self.target,
            port,
            self.outcome_str(),
            round,
            self.strategy
        );
        if let Some(rtt) = self.rtt_ms {
            line.push_str(&format!("  {rtt}ms"));
        }
        line.push_str(&format!("  probe={}", self.probe_hex));
        if let Some(reply) = &self.reply_hex {
            line.push_str(&format!("  reply={reply}"));
        }
        line
    }

    fn outcome_str(&self) -> String {
        match self.outcome {
            Outcome::Reply => "reply".to_string(),
            Outcome::Silence => "silence".to_string(),
            Outcome::Unreachable(code) => format!("unreachable:{code}"),
        }
    }
}
