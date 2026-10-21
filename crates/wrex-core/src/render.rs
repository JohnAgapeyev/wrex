//! Dissection rendering: `text` (indented field tree + `!` anomaly lines +
//! trailing payload hexdump), `json`/`jsonl` (pinned shape).

use serde_json::{Map, Value as JsonValue, json};

use crate::dissect::{Anomaly, DissectedPacket, LayerView};
use crate::value::Value as WValue;
use crate::value::mac_string;

/// Ethertype → protocol name (for rendering `eth.type` / `vlan.type`).
pub fn ethertype_name(v: u16) -> Option<&'static str> {
    Some(match v {
        0x0800 => "ipv4",
        0x0806 => "arp",
        0x8100 => "vlan",
        0x86dd => "ipv6",
        _ => return None,
    })
}

/// IP protocol → name (for rendering `ipv4.proto`).
pub fn ip_proto_name(v: u8) -> Option<&'static str> {
    Some(match v {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        _ => return None,
    })
}

/// IPv6 next-header → name (for rendering `ipv6.next_header`).
pub fn ip6_next_header_name(v: u8) -> Option<&'static str> {
    Some(match v {
        58 => "icmpv6",
        6 => "tcp",
        17 => "udp",
        _ => return None,
    })
}

fn field_json(layer_kind: &str, name: &str, value: &WValue) -> JsonValue {
    if layer_kind == "eth"
        && name == "type"
        && let WValue::Int(v) = value
        && let Some(n) = ethertype_name(*v as u16)
    {
        return json!(n);
    }
    if layer_kind == "vlan"
        && name == "type"
        && let WValue::Int(v) = value
        && let Some(n) = ethertype_name(*v as u16)
    {
        return json!(n);
    }
    if layer_kind == "ipv4"
        && name == "proto"
        && let WValue::Int(v) = value
        && let Some(n) = ip_proto_name(*v as u8)
    {
        return json!(n);
    }
    if layer_kind == "ipv6"
        && name == "next_header"
        && let WValue::Int(v) = value
        && let Some(n) = ip6_next_header_name(*v as u8)
    {
        return json!(n);
    }
    match value {
        WValue::Bool(b) => json!(b),
        WValue::Int(v) => json!(v),
        WValue::Bytes(b) => json!(hex::encode(b)),
        WValue::Str(s) => json!(s),
        WValue::Ipv4(a) => json!(a.to_string()),
        WValue::Ipv6(a) => json!(a.to_string()),
        WValue::Mac(m) => json!(mac_string(*m)),
        WValue::List(items) => json!(
            items
                .iter()
                .map(|v| field_json(layer_kind, name, v))
                .collect::<Vec<_>>()
        ),
    }
}

fn fields_json(layer: &LayerView) -> Map<String, JsonValue> {
    let mut out = Map::new();
    for (name, value) in &layer.fields {
        out.insert(name.clone(), field_json(layer.kind, name, value));
    }
    out
}

/// The pinned dissection JSON object.
pub fn dissect_to_json(p: &DissectedPacket) -> JsonValue {
    json!({
        "start": p.start,
        "layers": p.layers.iter().map(|l| json!({
            "kind": l.kind,
            "span": [l.span.start, l.span.end],
            "fields": fields_json(l),
        })).collect::<Vec<_>>(),
        "payload_hex": hex::encode(&p.payload),
        "anomalies": p.anomalies.iter().map(anomaly_json).collect::<Vec<_>>(),
    })
}

fn anomaly_json(a: &Anomaly) -> JsonValue {
    json!({ "path": a.path, "message": a.message })
}

/// `jsonl`: one line per packet.
pub fn dissect_to_jsonl(p: &DissectedPacket) -> String {
    dissect_to_json(p).to_string()
}

fn field_text(kind: &str, name: &str, value: &WValue) -> String {
    if kind == "eth"
        && name == "type"
        && let WValue::Int(v) = value
        && let Some(n) = ethertype_name(*v as u16)
    {
        return n.to_string();
    }
    if kind == "vlan"
        && name == "type"
        && let WValue::Int(v) = value
        && let Some(n) = ethertype_name(*v as u16)
    {
        return n.to_string();
    }
    if kind == "ipv4"
        && name == "proto"
        && let WValue::Int(v) = value
        && let Some(n) = ip_proto_name(*v as u8)
    {
        return n.to_string();
    }
    if kind == "ipv6"
        && name == "next_header"
        && let WValue::Int(v) = value
        && let Some(n) = ip6_next_header_name(*v as u8)
    {
        return n.to_string();
    }
    match value {
        WValue::Bool(b) => b.to_string(),
        WValue::Int(v) => v.to_string(),
        WValue::Bytes(b) => hex::encode(b),
        WValue::Str(s) => s.clone(),
        WValue::Ipv4(a) => a.to_string(),
        WValue::Ipv6(a) => a.to_string(),
        WValue::Mac(m) => mac_string(*m),
        WValue::List(items) => {
            let parts: Vec<String> = items
                .iter()
                .map(|v| match v {
                    WValue::Str(s) => s.clone(),
                    other => field_text(kind, name, other),
                })
                .collect();
            parts.join(",")
        }
    }
}

/// Hexdump `payload (N bytes):` + 16-per-line hex pairs.
pub fn hexdump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let hexes: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        out.push_str(&format!("  {:04x}  {}\n", i * 16, hexes.join(" ")));
    }
    out
}

/// `text` format: indented field tree, `! path: message` anomaly lines,
/// trailing payload hexdump.
pub fn dissect_to_text(p: &DissectedPacket) -> String {
    let mut out = String::new();
    for (i, layer) in p.layers.iter().enumerate() {
        let indent = "  ".repeat(i);
        out.push_str(&format!("{indent}{}\n", layer.kind));
        for (name, value) in &layer.fields {
            out.push_str(&format!(
                "{indent}  {name}: {}\n",
                field_text(layer.kind, name, value)
            ));
        }
    }
    if !p.payload.is_empty() {
        out.push_str(&format!("payload ({} bytes):\n", p.payload.len()));
        out.push_str(&hexdump(&p.payload));
    } else {
        out.push_str("payload (0 bytes)\n");
    }
    for a in &p.anomalies {
        out.push_str(&format!("{a}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::{Anomaly, LayerView};
    use bytes::Bytes as B;
    use std::collections::BTreeMap;

    fn sample() -> DissectedPacket {
        let mut eth_fields = BTreeMap::new();
        eth_fields.insert("dst".to_string(), WValue::Mac([0xff; 6]));
        eth_fields.insert("src".to_string(), WValue::Mac([0; 6]));
        eth_fields.insert("type".to_string(), WValue::Int(0x0800));
        let mut udp_fields = BTreeMap::new();
        udp_fields.insert("sport".to_string(), WValue::Int(4444));
        DissectedPacket {
            start: "eth",
            layers: vec![
                LayerView {
                    kind: "eth",
                    span: 0..14,
                    field_spans: Default::default(),
                    fields: eth_fields,
                },
                LayerView {
                    kind: "udp",
                    span: 14..22,
                    field_spans: Default::default(),
                    fields: udp_fields,
                },
            ],
            payload: B::from_static(&[0xde, 0xad, 0xbe, 0xef]),
            anomalies: vec![Anomaly::new(
                "ipv4.checksum",
                "mismatch (computed 0x7ccb, found 0x1234)",
            )],
            frame: B::new(),
            facts: Default::default(),
        }
    }

    #[test]
    fn json_shape() {
        let v = dissect_to_json(&sample());
        assert_eq!(v["start"], "eth");
        assert_eq!(v["layers"][0]["kind"], "eth");
        assert_eq!(v["layers"][0]["span"][0], 0);
        assert_eq!(v["layers"][0]["span"][1], 14);
        assert_eq!(v["layers"][0]["fields"]["dst"], "ff:ff:ff:ff:ff:ff");
        assert_eq!(v["layers"][0]["fields"]["type"], "ipv4");
        assert_eq!(v["layers"][1]["fields"]["sport"], 4444);
        assert_eq!(v["payload_hex"], "deadbeef");
        assert_eq!(
            v["anomalies"][0]["message"],
            "mismatch (computed 0x7ccb, found 0x1234)"
        );
        let s = v.to_string();
        assert!(s.contains("\"start\":\"eth\""));
        assert!(s.contains("\"payload_hex\":\"deadbeef\""));
    }

    #[test]
    fn text_tree_and_anomalies() {
        let t = dissect_to_text(&sample());
        assert!(t.contains("eth\n"), "{t}");
        assert!(t.contains("  dst: ff:ff:ff:ff:ff:ff\n"), "{t}");
        assert!(t.contains("  type: ipv4\n"), "{t}");
        assert!(t.contains("  udp\n"), "{t}");
        assert!(t.contains("payload (4 bytes):\n"), "{t}");
        assert!(t.contains("de ad be ef"), "{t}");
        assert!(
            t.contains("! ipv4.checksum: mismatch (computed 0x7ccb, found 0x1234)\n"),
            "{t}"
        );
    }

    #[test]
    fn name_maps() {
        assert_eq!(ethertype_name(0x0800), Some("ipv4"));
        assert_eq!(ethertype_name(0x0806), Some("arp"));
        assert_eq!(ethertype_name(0x1234), None);
        assert_eq!(ip_proto_name(6), Some("tcp"));
        assert_eq!(ip_proto_name(17), Some("udp"));
        assert_eq!(ip_proto_name(253), None);
        assert_eq!(ip6_next_header_name(58), Some("icmpv6"));
        assert_eq!(ip6_next_header_name(6), Some("tcp"));
        assert_eq!(ip6_next_header_name(0), None);
    }
}
