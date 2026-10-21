//! Offline findings differential (tranche 12): diff two findings JSONL
//! files — a baseline run against a mutated run, or two targets probed
//! with the same corpus — into a structured report.
//!
//! Pure offline data plumbing on top of [`crate::report::Finding`]'s
//! pinned JSON: no codecs, no drivers, no sockets. Findings pair by
//! probe identity — `(target, port, proto, round)`; `strategy` is
//! carried, never matched on. Equal pairs are silent; every difference
//! renders one entry (an outcome delta, a reply-presence change,
//! divergent reply bytes, or a one-sided probe). `rtt` is wall-clock
//! noise and ignored; `attempts` changes are data and recorded.

use serde::{Deserialize, Serialize};

use crate::report::Outcome;

/// Deserialization mirror of [`crate::report::Finding`] (owned strings;
/// the wire type is `&'static str`, which does not deserialize). The
/// unit gate asserts field-for-field parity with the serialized
/// [`crate::report::Finding`].
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct FindingRecord {
    pub target: String,
    #[serde(default)]
    pub port: Option<u16>,
    pub proto: String,
    #[serde(default)]
    pub round: Option<u32>,
    #[serde(default)]
    pub strategy: String,
    pub outcome: Outcome,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default)]
    pub rtt_ms: Option<u64>,
    #[serde(default)]
    pub probe_hex: String,
    #[serde(default)]
    pub reply_hex: Option<String>,
}

/// Parse one findings JSONL document (blank lines skipped) into
/// records. Malformed lines are a pointed error carrying file + line.
pub fn parse_findings(name: &str, jsonl: &str) -> Result<Vec<FindingRecord>, String> {
    let mut out = Vec::new();
    for (i, line) in jsonl.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let rec: FindingRecord = serde_json::from_str(line)
            .map_err(|e| format!("{name}:{i}: malformed finding ({e})"))?;
        out.push(rec);
    }
    Ok(out)
}

/// Which file a one-sided probe was seen in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Side {
    /// The first (baseline) file.
    A,
    /// The second (mutated) file.
    B,
}

/// One difference between the paired findings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "delta", rename_all = "snake_case")]
pub enum Delta {
    /// The probe outcome changed (reply -> silence, …).
    Outcome { from: Outcome, to: Outcome },
    /// A reply arrived where the pair had none.
    ReplyAdded { reply_hex: String },
    /// The reply disappeared.
    ReplyRemoved { reply_hex: String },
    /// Both sides replied, with different bytes.
    ReplyChanged { from: String, to: String },
    /// The send attempt count changed.
    Attempts { from: u32, to: u32 },
}

/// One report entry: a changed probe pair, or a probe present in only
/// one of the two files.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiffEntry {
    /// A paired probe with at least one delta (equal pairs are silent).
    Changed {
        target: String,
        port: Option<u16>,
        proto: String,
        round: Option<u32>,
        a_strategy: String,
        b_strategy: String,
        deltas: Vec<Delta>,
    },
    /// A probe key present in only one file (with its record).
    OnlyIn {
        target: String,
        port: Option<u16>,
        proto: String,
        round: Option<u32>,
        side: Side,
        strategy: String,
        outcome: Outcome,
        probe_hex: String,
    },
}

impl DiffEntry {
    /// The probe-identity prefix shared by both variants (text lines).
    fn key_text(&self) -> String {
        let (target, port, proto, round) = match self {
            DiffEntry::Changed {
                target,
                port,
                proto,
                round,
                ..
            } => (target, port, proto, round),
            DiffEntry::OnlyIn {
                target,
                port,
                proto,
                round,
                ..
            } => (target, port, proto, round),
        };
        let slot = match port {
            Some(p) => format!("{p}/{proto}"),
            None => proto.to_string(),
        };
        let round = round
            .map(|r| format!("round {r}"))
            .unwrap_or_else(|| "baseline".to_string());
        format!("{target}  {slot}  {round}")
    }

    /// One-line text rendering (the `--format text` shape).
    pub fn text_line(&self) -> String {
        match self {
            DiffEntry::Changed {
                a_strategy,
                b_strategy,
                deltas,
                ..
            } => {
                let parts: Vec<String> = deltas.iter().map(delta_text).collect();
                format!(
                    "{}  {}  ({} -> {})",
                    self.key_text(),
                    parts.join("; "),
                    a_strategy,
                    b_strategy
                )
            }
            DiffEntry::OnlyIn {
                side,
                strategy,
                outcome,
                probe_hex,
                ..
            } => {
                let side = match side {
                    Side::A => "a",
                    Side::B => "b",
                };
                format!(
                    "{}  only in {side}  {}  ({})  probe={probe_hex}",
                    self.key_text(),
                    outcome_text(*outcome),
                    strategy,
                )
            }
        }
    }
}

/// Outcome as text (`reply`, `silence`, `unreachable:3`).
fn outcome_text(o: Outcome) -> String {
    match o {
        Outcome::Reply => "reply".to_string(),
        Outcome::Silence => "silence".to_string(),
        Outcome::Unreachable(code) => format!("unreachable:{code}"),
    }
}

/// One delta as text (`reply -> silence`, `+reply dead…`, …).
fn delta_text(d: &Delta) -> String {
    match d {
        Delta::Outcome { from, to } => {
            format!("{} -> {}", outcome_text(*from), outcome_text(*to))
        }
        Delta::ReplyAdded { reply_hex } => format!("+reply {reply_hex}"),
        Delta::ReplyRemoved { reply_hex } => format!("-reply {reply_hex}"),
        Delta::ReplyChanged { from, to } => format!("reply {from} -> {to}"),
        Delta::Attempts { from, to } => format!("attempts {from} -> {to}"),
    }
}

/// The probe-identity key (strategy carried, never matched).
type Key = (String, Option<u16>, String, Option<u32>);

fn key(rec: &FindingRecord) -> Key {
    (rec.target.clone(), rec.port, rec.proto.clone(), rec.round)
}

/// Diff two parsed findings files into report entries.
///
/// Pairing: same-key findings pair index-wise in file order (duplicate
/// keys never cross). Output order: keys in discovery order — `a`'s
/// first-seen keys, then `b`-only keys — and within a key, changed
/// pairs first, then a-only, then b-only leftovers. Deterministic: a
/// pure function of the two records vectors.
pub fn diff_findings(a: &[FindingRecord], b: &[FindingRecord]) -> Vec<DiffEntry> {
    use std::collections::{HashMap, HashSet};

    let mut a_groups: HashMap<Key, Vec<usize>> = HashMap::new();
    for (i, rec) in a.iter().enumerate() {
        a_groups.entry(key(rec)).or_default().push(i);
    }
    let mut b_groups: HashMap<Key, Vec<usize>> = HashMap::new();
    for (i, rec) in b.iter().enumerate() {
        b_groups.entry(key(rec)).or_default().push(i);
    }

    // Key discovery order: a's keys in file order, then b-only keys.
    let mut order: Vec<Key> = Vec::new();
    let mut seen: HashSet<Key> = HashSet::new();
    for rec in a {
        let k = key(rec);
        if seen.insert(k.clone()) {
            order.push(k);
        }
    }
    for rec in b {
        let k = key(rec);
        if seen.insert(k.clone()) {
            order.push(k);
        }
    }

    let mut out: Vec<DiffEntry> = Vec::new();
    for k in &order {
        let ai = a_groups.get(k).map(Vec::as_slice).unwrap_or(&[]);
        let bi = b_groups.get(k).map(Vec::as_slice).unwrap_or(&[]);
        let pairs = ai.len().min(bi.len());
        for n in 0..pairs {
            if let Some(entry) = pair_delta(&a[ai[n]], &b[bi[n]]) {
                out.push(entry);
            }
        }
        for &i in &ai[pairs..] {
            let r = &a[i];
            out.push(DiffEntry::OnlyIn {
                target: r.target.clone(),
                port: r.port,
                proto: r.proto.clone(),
                round: r.round,
                side: Side::A,
                strategy: r.strategy.clone(),
                outcome: r.outcome,
                probe_hex: r.probe_hex.clone(),
            });
        }
        for &i in &bi[pairs..] {
            let r = &b[i];
            out.push(DiffEntry::OnlyIn {
                target: r.target.clone(),
                port: r.port,
                proto: r.proto.clone(),
                round: r.round,
                side: Side::B,
                strategy: r.strategy.clone(),
                outcome: r.outcome,
                probe_hex: r.probe_hex.clone(),
            });
        }
    }
    out
}

/// The deltas of one paired (a, b) finding pair; `None` when equal
/// (ignoring rtt — wall-clock noise — and strategy, which is carried
/// on the entry instead).
fn pair_delta(a: &FindingRecord, b: &FindingRecord) -> Option<DiffEntry> {
    let mut deltas = Vec::new();
    if a.outcome != b.outcome {
        deltas.push(Delta::Outcome {
            from: a.outcome,
            to: b.outcome,
        });
    }
    match (&a.reply_hex, &b.reply_hex) {
        (Some(x), Some(y)) if x != y => deltas.push(Delta::ReplyChanged {
            from: x.clone(),
            to: y.clone(),
        }),
        (Some(x), None) => deltas.push(Delta::ReplyRemoved {
            reply_hex: x.clone(),
        }),
        (None, Some(y)) => deltas.push(Delta::ReplyAdded {
            reply_hex: y.clone(),
        }),
        _ => {}
    }
    if a.attempts != b.attempts {
        deltas.push(Delta::Attempts {
            from: a.attempts,
            to: b.attempts,
        });
    }
    if deltas.is_empty() {
        return None;
    }
    Some(DiffEntry::Changed {
        target: a.target.clone(),
        port: a.port,
        proto: a.proto.clone(),
        round: a.round,
        a_strategy: a.strategy.clone(),
        b_strategy: b.strategy.clone(),
        deltas,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::Finding;

    fn finding(
        port: Option<u16>,
        proto: &'static str,
        round: Option<u32>,
        strategy: &'static str,
        outcome: Outcome,
        reply: Option<&str>,
    ) -> Finding {
        Finding {
            target: wrex_scan::ScanAddr::V4("127.0.0.1".parse().unwrap()),
            port,
            proto,
            round,
            strategy,
            outcome,
            attempts: 1,
            rtt_ms: None,
            probe_hex: "00".to_string(),
            reply_hex: reply.map(str::to_string),
        }
    }

    fn rec(json: &str) -> FindingRecord {
        serde_json::from_str(json).expect("record")
    }

    /// The mirror struct parses what `Finding` serializes, field for
    /// field (the drift gate).
    #[test]
    fn record_parses_finding_json() {
        let f = finding(
            Some(53),
            "udp",
            Some(2),
            "field",
            Outcome::Unreachable(3),
            Some("dead"),
        );
        let json = serde_json::to_string(&f).unwrap();
        let r: FindingRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r.target, "127.0.0.1");
        assert_eq!(r.port, Some(53));
        assert_eq!(r.proto, "udp");
        assert_eq!(r.round, Some(2));
        assert_eq!(r.strategy, "field");
        assert_eq!(r.outcome, Outcome::Unreachable(3));
        assert_eq!(r.attempts, 1);
        assert_eq!(r.probe_hex, "00");
        assert_eq!(r.reply_hex.as_deref(), Some("dead"));
    }

    #[test]
    fn parse_skips_blank_and_points_at_malformed_lines() {
        let doc = "\n\n{\"target\":\"127.0.0.1\",\"proto\":\"udp\",\"outcome\":\"reply\"}\n\n";
        let rs = parse_findings("a.jsonl", doc).unwrap();
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].outcome, Outcome::Reply);
        let err = parse_findings("b.jsonl", "not json").unwrap_err();
        assert!(err.contains("b.jsonl:0"), "{err}");
    }

    #[test]
    fn outcome_and_reply_deltas() {
        let base = rec(r#"{"target":"127.0.0.1","port":53,"proto":"udp","round":1,
                "strategy":"field","outcome":"reply","attempts":1,
                "probe_hex":"00","reply_hex":"aa"}"#);
        let mutated = rec(r#"{"target":"127.0.0.1","port":53,"proto":"udp","round":1,
                "strategy":"field","outcome":"silence","attempts":3,
                "probe_hex":"00"}"#);
        let out = diff_findings(std::slice::from_ref(&base), std::slice::from_ref(&mutated));
        assert_eq!(out.len(), 1);
        match &out[0] {
            DiffEntry::Changed {
                deltas, a_strategy, ..
            } => {
                assert_eq!(a_strategy, "field");
                assert!(deltas.contains(&Delta::Outcome {
                    from: Outcome::Reply,
                    to: Outcome::Silence
                }));
                assert!(deltas.contains(&Delta::ReplyRemoved {
                    reply_hex: "aa".into()
                }));
                assert!(deltas.contains(&Delta::Attempts { from: 1, to: 3 }));
            }
            other => panic!("{other:?}"),
        }
        // Equal pair (strategy aside, rtt is wall-clock noise) is silent.
        let noisy = base.clone();
        assert!(diff_findings(&[base], &[noisy]).is_empty());
    }

    #[test]
    fn one_sided_and_order() {
        let a = [
            rec(
                r#"{"target":"10.0.0.1","proto":"icmp","strategy":"baseline","outcome":"reply","probe_hex":"01"}"#,
            ),
            rec(
                r#"{"target":"10.0.0.2","proto":"icmp","strategy":"baseline","outcome":"silence","probe_hex":"02"}"#,
            ),
        ];
        let b = [
            // pairs equal with a[0] (strategy carried, never matched):
            // the equal pair is silent.
            rec(
                r#"{"target":"10.0.0.1","proto":"icmp","strategy":"len","outcome":"reply","probe_hex":"01"}"#,
            ),
            rec(
                r#"{"target":"10.0.0.3","proto":"icmp","strategy":"field","outcome":"reply","probe_hex":"03"}"#,
            ),
        ];
        let out = diff_findings(&a, &b);
        // a's key order first (10.0.0.2 only in a), then b-only
        // (10.0.0.3); the equal 10.0.0.1 pair is silent.
        assert_eq!(out.len(), 2);
        match &out[0] {
            DiffEntry::OnlyIn { target, side, .. } => {
                assert_eq!(target, "10.0.0.2");
                assert_eq!(*side, Side::A);
            }
            other => panic!("{other:?}"),
        }
        match &out[1] {
            DiffEntry::OnlyIn { target, side, .. } => {
                assert_eq!(target, "10.0.0.3");
                assert_eq!(*side, Side::B);
            }
            other => panic!("{other:?}"),
        }
        let text = out.iter().map(DiffEntry::text_line).collect::<Vec<_>>();
        assert!(text[0].contains("only in a"), "{text:?}");
        assert!(text[1].contains("only in b"), "{text:?}");
        assert!(
            text[1].contains("round") || text[1].contains("baseline"),
            "{text:?}"
        );
    }

    #[test]
    fn duplicate_keys_pair_in_order() {
        let a = [
            rec(
                r#"{"target":"10.0.0.1","proto":"udp","round":1,"strategy":"field","outcome":"reply","probe_hex":"aa","reply_hex":"11"}"#,
            ),
            rec(
                r#"{"target":"10.0.0.1","proto":"udp","round":1,"strategy":"field","outcome":"reply","probe_hex":"ab","reply_hex":"22"}"#,
            ),
        ];
        let b = [
            rec(
                r#"{"target":"10.0.0.1","proto":"udp","round":1,"strategy":"len","outcome":"reply","probe_hex":"aa","reply_hex":"11"}"#,
            ),
            rec(
                r#"{"target":"10.0.0.1","proto":"udp","round":1,"strategy":"len","outcome":"reply","probe_hex":"ab","reply_hex":"99"}"#,
            ),
        ];
        let out = diff_findings(&a, &b);
        assert_eq!(out.len(), 1);
        match &out[0] {
            DiffEntry::Changed { deltas, .. } => {
                assert_eq!(
                    deltas,
                    &vec![Delta::ReplyChanged {
                        from: "22".into(),
                        to: "99".into()
                    }]
                );
            }
            other => panic!("{other:?}"),
        }
    }
}
