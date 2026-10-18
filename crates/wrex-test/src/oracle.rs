//! Differential oracles: in-process etherparse and subprocess tshark.

use std::net::Ipv4Addr;

use serde_json::Value as Json;
use wrex_core::dissect::DissectedPacket;
use wrex_core::value::Value;

/// A diff report from an oracle: field path → (ours, theirs).
#[derive(Debug, Default)]
pub struct DiffReport {
    pub mismatches: Vec<(String, String, String)>,
}

impl DiffReport {
    fn push(&mut self, path: &str, ours: String, theirs: String) {
        self.mismatches.push((path.to_string(), ours, theirs));
    }
}

/// Differential oracle contract.
pub trait Oracle: Send + Sync {
    fn name(&self) -> &'static str;
    fn is_available(&self) -> bool;
    /// Compare our dissection of `input` against the oracle; `Err` on diff.
    fn dissect_diff(&self, input: &[u8], actual: &DissectedPacket) -> Result<(), DiffReport>;
}

/// In-process etherparse oracle (always available).
pub struct EtherparseOracle;

impl Oracle for EtherparseOracle {
    fn name(&self) -> &'static str {
        "etherparse"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn dissect_diff(&self, input: &[u8], actual: &DissectedPacket) -> Result<(), DiffReport> {
        let mut report = DiffReport::default();
        let parsed = etherparse::SlicedPacket::from_ethernet(input);
        let parsed = match parsed {
            Ok(p) => p,
            Err(_) => {
                // etherparse refuses (truncated etc): only compare when both
                // sides claim a parse.
                return Ok(());
            }
        };
        etherparse_map(&parsed, actual, &mut report);
        if report.mismatches.is_empty() {
            Ok(())
        } else {
            Err(report)
        }
    }
}

/// Map etherparse's parsed header onto our dissected fields.
/// One module so etherparse API drift stays contained.
fn etherparse_map(
    parsed: &etherparse::SlicedPacket<'_>,
    actual: &DissectedPacket,
    report: &mut DiffReport,
) {
    let by_kind = |k: &str| actual.layers.iter().find(|l| l.kind == k);
    if let (Some(etherparse::LinkSlice::Ethernet2(eth)), Some(ours)) =
        (&parsed.link, by_kind("eth"))
    {
        field_eq(report, "eth.dst", ours, &Value::Mac(eth.destination()));
        field_eq(report, "eth.src", ours, &Value::Mac(eth.source()));
        field_eq(
            report,
            "eth.type",
            ours,
            &Value::Int(u16::from(eth.ether_type()) as u128),
        );
    }
    if let (Some(etherparse::NetSlice::Ipv4(ip)), Some(ours)) = (&parsed.net, by_kind("ipv4")) {
        let ip = ip.header();
        field_eq(report, "ipv4.ttl", ours, &Value::Int(ip.ttl() as u128));
        field_eq(
            report,
            "ipv4.proto",
            ours,
            &Value::Int(u8::from(ip.protocol()) as u128),
        );
        field_eq(
            report,
            "ipv4.src",
            ours,
            &Value::Ipv4(Ipv4Addr::from(ip.source())),
        );
        field_eq(
            report,
            "ipv4.dst",
            ours,
            &Value::Ipv4(Ipv4Addr::from(ip.destination())),
        );
        field_eq(
            report,
            "ipv4.id",
            ours,
            &Value::Int(ip.identification() as u128),
        );
        // flags: df/mf (MSB-first aggregate [df,mf] → bit1/bit0)
        let mut names = Vec::new();
        if ip.dont_fragment() {
            names.push(Value::Str("df".into()));
        }
        if ip.more_fragments() {
            names.push(Value::Str("mf".into()));
        }
        field_eq(report, "ipv4.flags", ours, &Value::List(names));
        field_eq(
            report,
            "ipv4.frag_off",
            ours,
            &Value::Int(u16::from(ip.fragments_offset()) as u128),
        );
    }
    if let (Some(etherparse::TransportSlice::Udp(header)), Some(ours)) =
        (&parsed.transport, by_kind("udp"))
    {
        field_eq(
            report,
            "udp.sport",
            ours,
            &Value::Int(header.source_port() as u128),
        );
        field_eq(
            report,
            "udp.dport",
            ours,
            &Value::Int(header.destination_port() as u128),
        );
        field_eq(
            report,
            "udp.length",
            ours,
            &Value::Int(header.length() as u128),
        );
    }
    if let (Some(etherparse::TransportSlice::Tcp(header)), Some(ours)) =
        (&parsed.transport, by_kind("tcp"))
    {
        field_eq(
            report,
            "tcp.sport",
            ours,
            &Value::Int(header.source_port() as u128),
        );
        field_eq(
            report,
            "tcp.dport",
            ours,
            &Value::Int(header.destination_port() as u128),
        );
        field_eq(
            report,
            "tcp.seq",
            ours,
            &Value::Int(header.sequence_number() as u128),
        );
        field_eq(
            report,
            "tcp.ack",
            ours,
            &Value::Int(header.acknowledgment_number() as u128),
        );
        field_eq(
            report,
            "tcp.window",
            ours,
            &Value::Int(header.window_size() as u128),
        );
    }
}

fn field_eq(
    report: &mut DiffReport,
    path: &str,
    layer: &wrex_core::dissect::LayerView,
    want: &Value,
) {
    let ours = layer
        .fields
        .get(path.rsplit('.').next().unwrap_or(path))
        .cloned()
        .unwrap_or(Value::Int(u64::MAX as u128));
    if &ours != want {
        report.push(path, format!("{ours:?}"), format!("{want:?}"));
    }
}

/// Minimal classic-pcap writer (global header + per-packet records,
/// DLT_EN10MB) — hand-written, no pcap dependency (~40 lines).
pub struct PcapWriter {
    out: Vec<u8>,
}

impl Default for PcapWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl PcapWriter {
    pub fn new() -> Self {
        // Global header (24 bytes): magic, v2.4, thiszone 0, sigfigs 0,
        let mut out = Vec::with_capacity(24 + 16);
        out.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0xffffu32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        Self { out }
    }

    /// Append one frame (ts = unix epoch).
    pub fn push_frame(&mut self, bytes: &[u8]) {
        let ts: u32 = 0;
        self.out.extend_from_slice(&ts.to_le_bytes());
        self.out.extend_from_slice(&ts.to_le_bytes());
        self.out
            .extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        self.out
            .extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        self.out.extend_from_slice(bytes);
    }

    pub fn finish(self) -> Vec<u8> {
        self.out
    }
}

/// Subprocess tshark oracle (`tshark -T json -x` over a minimal pcap).
pub struct TsharkOracle;

impl TsharkOracle {
    pub fn available(&self) -> bool {
        std::env::var("WREX_DIFF_TSHARK").as_deref() == Ok("1") || which_tshark().is_some()
    }
}

fn which_tshark() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|p| p.join("tshark"))
        .find(|p| p.is_file())
}

impl Oracle for TsharkOracle {
    fn name(&self) -> &'static str {
        "tshark"
    }

    fn is_available(&self) -> bool {
        TsharkOracle.available()
    }

    fn dissect_diff(&self, input: &[u8], actual: &DissectedPacket) -> Result<(), DiffReport> {
        let Some(tshark) = which_tshark() else {
            return Ok(()); // skip
        };
        let mut pcap = PcapWriter::new();
        pcap.push_frame(input);
        let dir = std::env::temp_dir().join("wrex-tshark-diff");
        std::fs::create_dir_all(&dir).ok();
        let pcap_path = dir.join(format!("diff-{}.pcap", std::process::id()));
        std::fs::write(&pcap_path, pcap.finish()).map_err(|_| DiffReport::default())?;
        let out = std::process::Command::new(&tshark)
            .arg("-r")
            .arg(&pcap_path)
            .arg("-T")
            .arg("json")
            .arg("-x")
            .output()
            .map_err(|_| DiffReport::default())?;
        if !out.status.success() {
            return Ok(()); // tshark refused the bytes: skip (never fatal)
        }
        let json: Json = serde_json::from_slice(&out.stdout).map_err(|_| DiffReport::default())?;
        let mut report = DiffReport::default();
        tshark_map(&json, actual, &mut report);
        if report.mismatches.is_empty() {
            Ok(())
        } else {
            Err(report)
        }
    }
}

/// Map `tshark -T json` output onto our dissected fields.
fn tshark_map(json: &Json, actual: &DissectedPacket, report: &mut DiffReport) {
    let Some(frames) = json.as_array() else {
        return;
    };
    let Some(first) = frames.first() else { return };
    let layers = &first["_source"]["layers"];
    let by_kind = |k: &str| actual.layers.iter().find(|l| l.kind == k);

    // eth
    if let Some(eth_json) = layers.get("eth") {
        if let Some(ours) = by_kind("eth") {
            let get = |k: &str| eth_json[k].as_str().map(|s| s.to_string());
            cmp_str(report, "eth.dst", ours, get("eth.dst"));
            cmp_str(report, "eth.src", ours, get("eth.src"));
            cmp_int_prefix(report, "eth.type", ours, get("eth.type"));
        }
    }
    // ip
    if let Some(ip_json) = layers.get("ip") {
        if let Some(ours) = by_kind("ipv4") {
            let get = |k: &str| ip_json[k].as_str().map(|s| s.to_string());
            cmp_int_str(report, "ipv4.ttl", ours, get("ip.ttl"));
            cmp_int_str(report, "ipv4.proto", ours, get("ip.proto"));
            cmp_str(report, "ipv4.src", ours, get("ip.src"));
            cmp_str(report, "ipv4.dst", ours, get("ip.dst"));
            cmp_int_str(report, "ipv4.id", ours, get("ip.id"));
        }
    }
    // udp / tcp
    if let Some(udp_json) = layers.get("udp") {
        if let Some(ours) = by_kind("udp") {
            let get = |k: &str| udp_json[k].as_str().map(|s| s.to_string());
            cmp_int_str(report, "udp.sport", ours, get("udp.srcport"));
            cmp_int_str(report, "udp.dport", ours, get("udp.dstport"));
            cmp_int_str(report, "udp.length", ours, get("udp.length"));
        }
    }
    if let Some(tcp_json) = layers.get("tcp") {
        if let Some(ours) = by_kind("tcp") {
            let get = |k: &str| tcp_json[k].as_str().map(|s| s.to_string());
            cmp_int_str(report, "tcp.sport", ours, get("tcp.srcport"));
            cmp_int_str(report, "tcp.dport", ours, get("tcp.dstport"));
            cmp_int_str(report, "tcp.seq", ours, get("tcp.seq"));
            cmp_int_str(report, "tcp.ack", ours, get("tcp.ack"));
            cmp_int_str(report, "tcp.window", ours, get("tcp.window_size_value"));
        }
    }
    // arp
    if let Some(arp_json) = layers.get("arp") {
        if let Some(ours) = by_kind("arp") {
            let get = |k: &str| arp_json[k].as_str().map(|s| s.to_string());
            cmp_int_str(report, "arp.oper", ours, get("arp.opcode"));
            cmp_str(report, "arp.sha", ours, get("arp.src.hw_mac"));
            cmp_str(report, "arp.tha", ours, get("arp.dst.hw_mac"));
            cmp_str(report, "arp.spa", ours, get("arp.src.proto_ipv4"));
            cmp_str(report, "arp.tpa", ours, get("arp.dst.proto_ipv4"));
        }
    }
    // icmp
    if let Some(icmp_json) = layers.get("icmp") {
        if let Some(ours) = by_kind("icmp") {
            if let Some(t) = icmp_json["icmp.type"].as_str() {
                cmp_int_str(report, "icmp.type", ours, Some(t.to_string()));
            }
        }
    }
}

fn cmp_str(
    report: &mut DiffReport,
    path: &str,
    layer: &wrex_core::dissect::LayerView,
    theirs: Option<String>,
) {
    let name = path.rsplit('.').next().unwrap_or(path);
    if let Some(theirs) = theirs {
        let ours_norm = match layer.fields.get(name) {
            Some(Value::Mac(m)) => wrex_core::mac_string(*m),
            Some(Value::Ipv4(a)) => a.to_string(),
            Some(Value::Int(v)) => v.to_string(),
            other => format!("{other:?}"),
        };
        let theirs_norm = theirs.trim().to_ascii_lowercase();
        let ours_norm = ours_norm.to_ascii_lowercase();
        if ours_norm != theirs_norm {
            report.push(path, ours_norm, theirs_norm);
        }
    }
}

fn cmp_int_str(
    report: &mut DiffReport,
    path: &str,
    layer: &wrex_core::dissect::LayerView,
    theirs: Option<String>,
) {
    let name = path.rsplit('.').next().unwrap_or(path);
    if let Some(theirs) = theirs {
        let theirs_int: u128 = parse_int_value(&theirs);
        match layer.fields.get(name) {
            Some(Value::Int(v)) if *v == theirs_int => {}
            other => report.push(path, format!("{other:?}"), theirs),
        }
    }
}

/// Integer parsing for tshark string fields: `0x0800`, `2048`, or
/// `8 (Echo (ping) request)` (leading value wins; descriptions ignored).
fn parse_int_value(raw: &str) -> u128 {
    let s = raw.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        let digits: String = hex.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        return u128::from_str_radix(&digits, 16).unwrap_or(u128::MAX);
    }
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().unwrap_or(u128::MAX)
}
fn cmp_int_prefix(
    report: &mut DiffReport,
    path: &str,
    layer: &wrex_core::dissect::LayerView,
    theirs: Option<String>,
) {
    cmp_int_str(report, path, layer, theirs)
}

/// Run every available oracle against our dissection.
pub fn check_all_oracles(
    input: &[u8],
    actual: &DissectedPacket,
) -> Vec<(&'static str, DiffReport)> {
    let mut failures = Vec::new();
    let ether = EtherparseOracle;
    if let Err(d) = ether.dissect_diff(input, actual) {
        failures.push((ether.name(), d));
    }
    let tshark = TsharkOracle;
    if tshark.is_available() {
        if let Err(d) = tshark.dissect_diff(input, actual) {
            failures.push((tshark.name(), d));
        }
    }
    failures
}
