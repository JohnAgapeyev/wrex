//! HP3-a field-coverage gates (the [verification
//! doctrine](https://github.com/JohnAgapeyev/wrex/blob/main/docs/verification.md)):
//! harnesses that make the schema itself the completion oracle.
//!
//! **G1 — strategy-completeness audit.** Every settable schema field
//! must appear in the codec's own proptest strategy output with a
//! randomized value. A field the strategy never sets is a field whose
//! bit-position errors are invisible to every downstream gate (the
//! mf bug: the ipv4 strategy sampled `tos/id/ttl/frag_off/src/dst/
//! options` and never `flags`, so every compared frame had all flag
//! bits zero — a bit-*position* error is invisible at value 0). The
//! audit runs each codec's strategy N times and fails with a pointed
//! `never randomized` / `constant` list.
//!
//! Exemptions are recorded, never blanket:
//!
//! - [`Codec::derived`](wrex_core::Codec::derived) names are exempt by
//!   construction (autofill recomputes them; a strategy value would be
//!   overwritten anyway).
//! - Dissect-only record sections are exempt by construction
//!   (`settable: false`).
//! - [`STRATEGY_EXEMPT`] carries every hand-recorded exemption with a
//!   reason; an entry here is a reviewed decision, not a suppression.

use std::collections::BTreeMap;

use proptest::prelude::*;
use proptest::strategy::BoxedStrategy;
use proptest::test_runner::TestRunner;
use wrex_core::Registry;
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;

/// The per-codec `LayerSpec` strategies — the same functions the stack
/// strategies aggregate, dispatched by kind for schema-driven audits.
/// `None` for kinds without a strategy (none in the standard registry).
pub fn codec_strategy(kind: &str) -> Option<BoxedStrategy<LayerSpec>> {
    match kind {
        "eth" => Some(wrex_proto_eth::strategy::strategy()),
        "arp" => Some(wrex_proto_arp::strategy::strategy()),
        "vlan" => Some(wrex_proto_vlan::strategy::strategy()),
        "ipv4" => Some(wrex_proto_ip::strategy::strategy()),
        "ipv6" => Some(wrex_proto_ip6::strategy::strategy()),
        "hopopts" => Some(wrex_proto_ip6ext::strategy::hopopts()),
        "dstopts" => Some(wrex_proto_ip6ext::strategy::dstopts()),
        "routing" => Some(wrex_proto_ip6ext::strategy::routing()),
        "frag" => Some(wrex_proto_ip6ext::strategy::frag()),
        "ah" => Some(wrex_proto_ip6ext::strategy::ah()),
        "esp" => Some(wrex_proto_ip6ext::strategy::esp()),
        "nonext" => Some(wrex_proto_ip6ext::strategy::nonext()),
        "icmp" => Some(wrex_proto_icmp::strategy::strategy()),
        "icmpv6" => Some(wrex_proto_icmpv6::strategy::strategy()),
        "udp" => Some(wrex_proto_udp::strategy::strategy()),
        "tcp" => Some(wrex_proto_tcp::strategy::strategy()),
        "dns" => Some(wrex_proto_dns::strategy::strategy()),
        "dhcp" => Some(wrex_proto_dhcp::strategy::strategy()),
        "dhcp6" => Some(wrex_proto_dhcp6::strategy::strategy()),
        _ => None,
    }
}

/// Hand-recorded strategy exemptions: `(kind, field, reason)`. Every
/// entry is a reviewed decision named in the audit failure output when
/// stale; new entries need the reason to stay true.
pub const STRATEGY_EXEMPT: &[(&str, &str, &str)] = &[
    // count fields: autofilled from the crafted question; count
    // recomputation is ill-defined under desync (the T11b-β decision,
    // re-affirmed at T13a/T14: the dissector trusts the count).
    (
        "dns",
        "qdcount",
        "autofill: derived from the question section",
    ),
    (
        "dns",
        "ancount",
        "autofill: 0 (no settable answer records at craft)",
    ),
    (
        "dns",
        "nscount",
        "autofill: 0 (no settable authority records at craft)",
    ),
    (
        "dns",
        "arcount",
        "autofill: 0 (no settable additional records at craft)",
    ),
    // header geometry: recomputed by the codec's own autofill, not
    // strategy-meaningful (an explicit value is kept verbatim — the
    // craft rule — but randomizing it only produces malformed frames
    // the differentials cannot compare).
    (
        "tcp",
        "data_off",
        "autofill: derived from the options length",
    ),
    (
        "ipv6",
        "next_header",
        "autofill: derived from the next layer",
    ),
    (
        "ipv6",
        "ver",
        "autofill: always 6 (a random value is not an ipv6 header)",
    ),
    (
        "ipv4",
        "ver",
        "autofill: always 4 (a random value is not an ipv4 header)",
    ),
    ("ipv4", "ihl", "autofill: derived from the options length"),
    (
        "ipv4",
        "proto",
        "autofill: derived from the next layer (the eth.type rule)",
    ),
    ("dhcp", "cookie", "autofill: the RFC 2131 magic 0x63825363"),
    // the v6 extension-header next_header fields follow the same
    // autofill rule (T17a: "next_header (autofill, the `eth.type`
    // rule)").
    (
        "hopopts",
        "next_header",
        "autofill: derived from the next layer",
    ),
    (
        "dstopts",
        "next_header",
        "autofill: derived from the next layer",
    ),
    (
        "routing",
        "next_header",
        "autofill: derived from the next layer",
    ),
    (
        "frag",
        "next_header",
        "autofill: derived from the next layer",
    ),
    ("ah", "next_header", "autofill: derived from the next layer"),
    // arp geometry: the codec writes the fixed 28-byte Ethernet/IPv4
    // frame; hlen/plen are descriptive of the actual address sizes and
    // etherparse length-derives its parse from them, so randomizing
    // would desync the sha/spa/tha/tpa renderings the differential
    // compares. Their wire positions are pinned by the G3 KAV table
    // (RFC 826) instead — deterministic, not statistical.
    (
        "arp",
        "htype",
        "fixed Ethernet geometry; positions pinned by the G3 KAV table",
    ),
    (
        "arp",
        "ptype",
        "fixed IPv4 geometry; positions pinned by the G3 KAV table",
    ),
    (
        "arp",
        "hlen",
        "descriptive of the fixed 6-byte addresses; G3 KAV table",
    ),
    (
        "arp",
        "plen",
        "descriptive of the fixed 4-byte addresses; G3 KAV table",
    ),
];

/// One codec's audit result.
#[derive(Debug, Default)]
pub struct StrategyAudit {
    pub kind: String,
    /// Settable schema fields the strategy NEVER produced.
    pub never_set: Vec<String>,
    /// Settable schema fields produced with < `min_distinct` distinct
    /// values — `(field, distinct_count)`.
    pub constant: Vec<(String, usize)>,
}

impl StrategyAudit {
    pub fn is_clean(&self) -> bool {
        self.never_set.is_empty() && self.constant.is_empty()
    }

    /// The pointed failure message (the doctrine's list format).
    pub fn message(&self) -> String {
        let mut lines = String::new();
        for f in &self.never_set {
            lines.push_str(&format!("{}.{f}: never randomized\n", self.kind));
        }
        for (f, n) in &self.constant {
            lines.push_str(&format!(
                "{}.{f}: constant ({n} distinct value{})\n",
                self.kind,
                if *n == 1 { "" } else { "s" }
            ));
        }
        lines
    }
}

/// Run `kind`'s strategy `samples` times; every settable schema field
/// (minus recorded exemptions and `Codec::derived` names) must appear
/// with ≥ `min_distinct` distinct values.
///
/// Returns `None` when the kind has no strategy (nothing to audit).
pub fn audit_strategy(
    registry: &Registry,
    kind: &str,
    samples: usize,
    min_distinct: usize,
) -> Option<StrategyAudit> {
    let strategy = codec_strategy(kind)?;
    let codec = registry.get(kind)?;
    let schema = codec.schema();

    // The exempt surface: derived fields (by construction), recorded
    // hand exemptions, dissect-only record sections.
    let mut exempt: Vec<&str> = codec.derived().iter().map(|d| d.field()).collect();
    for (k, field, _) in STRATEGY_EXEMPT {
        if *k == kind {
            exempt.push(field);
        }
    }
    for record in schema.records {
        if !record.settable {
            for f in record.fields {
                exempt.push(f.name);
            }
        }
    }

    // The expected surface: flat fields + settable record fields at
    // their bounded index (`qd.0.name`; every settable record today
    // carries `max: Some(1)` — the flag-shorthand bound).
    let mut expected: Vec<String> = Vec::new();
    for f in schema.fields {
        if exempt.contains(&f.name) {
            continue;
        }
        expected.push(f.name.to_string());
    }
    for record in schema.records {
        if !record.settable {
            continue;
        }
        for f in record.fields {
            if exempt.contains(&f.name) {
                continue;
            }
            let index = record.max.unwrap_or(1).saturating_sub(1);
            expected.push(format!("{}.{}.{}", record.name, index, f.name));
        }
    }

    // Sample the strategy; collect every produced value per field.
    let mut seen: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    // The case budget is irrelevant here: the audit drives `new_tree`
    // directly, `samples` times.
    let mut runner = TestRunner::new(ProptestConfig::default());
    for _ in 0..samples {
        let tree = strategy
            .new_tree(&mut runner)
            .expect("strategy generation must not fail");
        let spec = tree.current();
        for (k, v) in &spec.fields {
            let entry = seen.entry(k.clone()).or_default();
            if !entry.contains(v) {
                entry.push(v.clone());
            }
        }
    }

    let mut audit = StrategyAudit {
        kind: kind.to_string(),
        ..Default::default()
    };
    for field in &expected {
        match seen.get(field) {
            None => audit.never_set.push(field.clone()),
            Some(values) => {
                if values.len() < min_distinct {
                    audit.constant.push((field.clone(), values.len()));
                }
            }
        }
    }
    Some(audit)
}
