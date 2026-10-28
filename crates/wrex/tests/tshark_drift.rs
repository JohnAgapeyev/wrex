//! tshark field-map drift guard (`cargo test -- differential`):
//! the oracle's comparison helpers skip silently when an oracle field
//! is absent, so a tshark release that renames a JSON key would turn
//! a comparison into a permanent non-comparison — nothing fails, the
//! coverage just quietly disappears (exactly how the tranche-17a
//! ext-header arms stayed dead: they read layer keys tshark 4.x never
//! emitted, fixed in pass 2).
//!
//! This suite pins the contract the other direction: for one fixture
//! frame per protocol family, every tshark JSON key the field map
//! consumes MUST be present in `tshark -T json -x` output. A renamed
//! key fails here, loudly, naming the missing path. The tshark
//! version is stamped into skip/failure notices so drift reports are
//! diagnosable.
//!
//! tshark subprocess: env-gated like the rest of the differential
//! family (`WREX_DIFF_TSHARK=1` or tshark on PATH); ignored under Miri.

#![cfg_attr(miri, ignore = "tshark subprocess; not Miri-safe")]

use std::process::Command;

use wrex_core::value::Value;
use wrex_test::oracle::{Oracle, TsharkOracle};

fn tshark_enabled() -> bool {
    TsharkOracle.available()
}

fn tshark_version() -> String {
    Command::new("tshark")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().next().map(str::to_string))
        .unwrap_or_else(|| "unknown".into())
}

/// One fixture family: corpus name, all its frames (tshark may dissect
/// different ext headers on different frames — ip6ext spreads them),
/// and the required tshark JSON keys, each of which must appear in at
/// least ONE frame's JSON. Keys are listed ONLY where the field map
/// actually reads them (see `wrex_test::oracle::tshark_map`).
type Fixture = (&'static str, Vec<Vec<u8>>, Vec<&'static str>);

fn fixtures() -> Vec<Fixture> {
    let corpora = wrex_test::corpus::Corpus::load_all();
    let mut out = Vec::new();
    let frames_of = |c: &wrex_test::corpus::Corpus| -> Vec<Vec<u8>> {
        c.frames.iter().map(|f| f.bytes.clone()).collect()
    };
    let mut family = |name: &'static str, keys: &[&'static str]| {
        if let Some(c) = corpora.iter().find(|c| c.name == name) {
            out.push((name, frames_of(c), keys.to_vec()));
        }
    };
    family(
        "udp",
        &[
            "eth.dst",
            "eth.src",
            "eth.type",
            "ip.ttl",
            "ip.src",
            "udp.srcport",
            "udp.dstport",
        ],
    );
    family("tcp", &["tcp.seq", "tcp.ack", "tcp.window_size_value"]);
    family("icmp", &["icmp.type"]);
    family(
        "arp",
        &["arp.opcode", "arp.src.hw_mac", "arp.dst.proto_ipv4"],
    );
    family(
        "dhcp",
        &[
            "dhcp.type",
            "dhcp.hw.mac_addr",
            "dhcp.ip.client",
            "dhcp.server",
        ],
    );
    // Tranche 17c: the fixed-header keys the dhcpv6 map block reads.
    family("dhcp6", &["dhcpv6.msgtype", "dhcpv6.xid"]);
    family(
        "vlan",
        &["vlan.priority", "vlan.dei", "vlan.id", "vlan.etype"],
    );
    family("icmpv6", &["icmpv6.type", "icmpv6.code"]);
    family("ipv6", &["ipv6.hlim", "ipv6.nxt", "ipv6.src"]);
    family(
        "ip6ext",
        &[
            "ipv6.hopopts.nxt",
            "ipv6.hopopts.len",
            "ipv6.dstopts.nxt",
            "ipv6.dstopts.len",
            "ipv6.routing.nxt",
            "ipv6.routing.segleft",
            "ah.next_header",
            "ah.spi",
            "ah.sequence",
        ],
    );
    out
}

/// Extract `tshark -T json -x` layers for frame 0 of a pcap.
fn tshark_layers(frame: &[u8]) -> Option<serde_json::Value> {
    let mut pcap = wrex_test::oracle::PcapWriter::new();
    pcap.push_frame(frame);
    let dir = std::env::temp_dir().join("wrex-tshark-drift");
    std::fs::create_dir_all(&dir).ok();
    let path = dir.join(format!("drift-{}.pcap", std::process::id()));
    std::fs::write(&path, pcap.finish()).ok()?;
    let out = Command::new("tshark")
        .arg("-r")
        .arg(&path)
        .arg("-T")
        .arg("json")
        .arg("-x")
        .arg("-o")
        .arg("tcp.relative_sequence_numbers:FALSE")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).ok()?;
    Some(json[0]["_source"]["layers"].clone())
}

/// Deep search: does `key` exist anywhere in the JSON tree (nested
/// dicts included — `ipv6.hopopts` lives inside `ipv6`, `ah` too)?
fn has_key_deep(v: &serde_json::Value, key: &str) -> bool {
    match v {
        serde_json::Value::Object(m) => m.iter().any(|(k, val)| k == key || has_key_deep(val, key)),
        _ => false,
    }
}

#[test]
fn tshark_field_map_keys_present() {
    if !tshark_enabled() {
        eprintln!(
            "drift guard: skipping (tshark unavailable; {})",
            tshark_version()
        );
        return;
    }
    let version = tshark_version();
    eprintln!("drift guard: tshark version: {version}");
    let mut checked = 0;
    for (name, frames, keys) in fixtures() {
        // Dissect every frame once; a key must appear in at least one.
        let all_layers: Vec<serde_json::Value> =
            frames.iter().filter_map(|f| tshark_layers(f)).collect();
        assert!(
            !all_layers.is_empty(),
            "tshark refused every {name} fixture frame (version {version})"
        );
        for key in keys {
            let present = all_layers.iter().any(|layers| has_key_deep(layers, key));
            assert!(
                present,
                "{name}: tshark {version} no longer emits `{key}` — the field-map \
                 comparison for this path is silently dead. Update \
                 wrex-test/src/oracle.rs::tshark_map (and this fixture list): \
                 run `tshark -r <fixture> -T json -x` and diff the keys."
            );
            checked += 1;
        }
    }
    // The guard is load-bearing: it must actually check every family.
    // 9 families x >=3 keys each; a corpus layout change that empties
    // fixtures() must fail loudly, not silently pass.
    assert!(
        checked >= 30,
        "only {checked} keys checked — the fixture table is incomplete"
    );
}

/// A map-side typo (`get("ipv6.routing.segleft_BROKEN")`) returns None
/// and the comparison silently dies — the keys-present guard above
/// cannot catch it (tshark still emits the correct key). This test
/// proves the comparisons are LIVE end-to-end instead: per family,
/// corrupt ONE mapped field in OUR dissection (`actual`) and the
/// tshark oracle (which reads the untouched bytes) MUST report that
/// path as a mismatch — a dead arm (`get()` → None) misses it.
#[test]
fn tshark_comparisons_are_live() {
    if !tshark_enabled() {
        eprintln!(
            "drift guard: skipping liveness (tshark unavailable; {})",
            tshark_version()
        );
        return;
    }
    let reg = wrex::standard();
    // (corpus family, our layer kind, field name) — one mapped field
    // per family, spread across the map's arms.
    let probes: &[(&str, &str, &str, &str)] = &[
        ("udp", "udp", "sport", "sport"),
        ("tcp", "tcp", "sport", "sport"),
        ("icmp", "icmp", "type", "type"),
        ("arp", "arp", "oper", "oper"),
        ("dhcp", "dhcp", "op", "op"),
        ("dhcp6", "dhcp6", "trans_id", "trans_id"),
        // cmp_vlan_tag pushes one whole-tag mismatch, path "vlan tag (…)".
        ("vlan", "vlan", "vid", "vlan tag"),
        ("icmpv6", "icmpv6", "type", "type"),
        ("ipv6", "ipv6", "hop_limit", "hop_limit"),
        ("ip6ext", "hopopts", "len", "len"),
    ];
    let corpora = wrex_test::corpus::Corpus::load_all();
    for (family, kind, field, frag) in probes {
        let Some(c) = corpora.iter().find(|c| c.name == *family) else {
            continue;
        };
        // Find a corpus frame that dissects the probe layer.
        let Some(frame) = c.frames.iter().find(|f| {
            wrex_core::dissect::dissect(&reg, &f.bytes, "eth")
                .layers
                .iter()
                .any(|l| l.kind == *kind)
        }) else {
            panic!("{family}: no corpus frame dissects a {kind} layer");
        };
        let mut packet = wrex_core::dissect::dissect(&reg, &frame.bytes, "eth");
        let Some(layer) = packet.layers.iter_mut().find(|l| l.kind == *kind) else {
            panic!("{family}: no {kind} layer in the dissected frame");
        };
        let had = layer
            .fields
            .get(*field)
            .cloned()
            .unwrap_or_else(|| panic!("{family}: dissected {kind} has no field `{field}`"));
        // Corrupt: a value the wire bytes can never produce.
        layer.fields.insert((*field).into(), Value::Int(u128::MAX));
        let report = wrex_test::oracle::TsharkOracle
            .dissect_diff(&frame.bytes, &packet)
            .expect_err("a corrupted field must mismatch");
        let hit = report
            .mismatches
            .iter()
            .any(|(path, _, _)| path.contains(frag));
        assert!(
            hit,
            "{family}: corrupting `{kind}.{field}` ({had:?}) produced no \
             `{kind}.{field}` comparison — that map arm is DEAD. {}",
            tshark_version()
        );
    }
}
