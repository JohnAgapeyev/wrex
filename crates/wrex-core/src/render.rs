//! Dissection rendering: `text` (indented field tree + `!` anomaly lines +
//! trailing payload hexdump), `json`/`jsonl` (pinned shape).

use serde_json::{Map, Value as JsonValue, json};

use crate::dissect::{Anomaly, DissectedPacket, FieldSpan, LayerView};
use crate::value::Value as WValue;
use crate::value::mac_string;

/// Ethertype → protocol name (for rendering `eth.type` / `vlan.type`).
pub const fn ethertype_name(v: u16) -> Option<&'static str> {
    Some(match v {
        0x0800 => "ipv4",
        0x0806 => "arp",
        0x8100 => "vlan",
        0x86dd => "ipv6",
        _ => return None,
    })
}

/// IP protocol → name (for rendering `ipv4.proto`).
pub const fn ip_proto_name(v: u8) -> Option<&'static str> {
    Some(match v {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        _ => return None,
    })
}

/// IPv6 next-header → name (for rendering `ipv6.next_header`).
pub const fn ip6_next_header_name(v: u8) -> Option<&'static str> {
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

/// One field span as JSON (tranche 11b-γ, `dissect --spans`): the closed
/// `FieldSpan` taxonomy, geometry only (semantics stay in the schema).
pub fn field_span_json(span: &FieldSpan) -> JsonValue {
    match span {
        FieldSpan::Bytes(r) => json!({
            "type": "bytes",
            "start": r.start,
            "end": r.end,
        }),
        FieldSpan::Bits {
            container,
            shift,
            width,
        } => json!({
            "type": "bits",
            "start": container.start,
            "end": container.end,
            "shift": shift,
            "width": width,
        }),
        FieldSpan::ReEncode(r) => json!({
            "type": "reencode",
            "start": r.start,
            "end": r.end,
        }),
        FieldSpan::None => json!("none"),
    }
}

fn spans_json(layer: &LayerView) -> Map<String, JsonValue> {
    let mut out = Map::new();
    for (name, span) in &layer.field_spans {
        out.insert(name.clone(), field_span_json(span));
    }
    out
}

/// The pinned dissection JSON object.
pub fn dissect_to_json(p: &DissectedPacket) -> JsonValue {
    dissect_to_json_spans(p, false, false)
}

/// [`dissect_to_json`] with the opt-in extras: the span taxonomy
/// (`dissect --spans`: per-layer `spans` objects plus the payload span)
/// and the retained frame (`dissect --frame`, tranche 14: a top-level
/// `frame` hex key — the input bytes verbatim, the T11a retention).
/// Without the flags the shape is byte-identical to [`dissect_to_json`].
pub fn dissect_to_json_spans(p: &DissectedPacket, spans: bool, frame: bool) -> JsonValue {
    let mut out = json!({
        "start": p.start,
        "layers": p.layers.iter().map(|l| {
            let mut obj = json!({
                "kind": l.kind,
                "span": [l.span.start, l.span.end],
                "fields": fields_json(l),
            });
            if spans {
                obj.as_object_mut()
                    .expect("object literal")
                    .insert("spans".into(), json!(spans_json(l)));
            }
            obj
        }).collect::<Vec<_>>(),
        "payload_hex": hex::encode(&p.payload),
        "anomalies": p.anomalies.iter().map(anomaly_json).collect::<Vec<_>>(),
    });
    if spans {
        let payload_at = p.frame.len() - p.payload.len();
        out.as_object_mut()
            .expect("object literal")
            .insert("payload_span".into(), json!([payload_at, p.frame.len()]));
    }
    if frame {
        out.as_object_mut()
            .expect("object literal")
            .insert("frame".into(), json!(hex::encode(&p.frame)));
    }
    out
}

fn anomaly_json(a: &Anomaly) -> JsonValue {
    json!({ "path": a.path, "message": a.message })
}

/// `jsonl`: one line per packet.
pub fn dissect_to_jsonl(p: &DissectedPacket) -> String {
    dissect_to_json(p).to_string()
}

/// [`dissect_to_jsonl`] with the opt-in extras (spans / frame), the
/// json mirror of [`dissect_to_json_spans`].
pub fn dissect_to_jsonl_spans(p: &DissectedPacket, spans: bool, frame: bool) -> String {
    dissect_to_json_spans(p, spans, frame).to_string()
}

/// One field span as text (`bytes @0..6`, `bits @14..16 shift0 width2`,
/// `reencode @240..304`, `none`).
pub fn field_span_text(span: &FieldSpan) -> String {
    match span {
        FieldSpan::Bytes(r) => format!("bytes @{r:?}"),
        FieldSpan::Bits {
            container,
            shift,
            width,
        } => format!("bits @{container:?} shift{shift} width{width}"),
        FieldSpan::ReEncode(r) => format!("reencode @{r:?}"),
        FieldSpan::None => "none".to_string(),
    }
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
        WValue::Str(s) => s.to_string(),
        WValue::Ipv4(a) => a.to_string(),
        WValue::Ipv6(a) => a.to_string(),
        WValue::Mac(m) => mac_string(*m),
        WValue::List(items) => {
            let parts: Vec<String> = items
                .iter()
                .map(|v| match v {
                    WValue::Str(s) => s.to_string(),
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
    dissect_to_text_spans(p, false, false)
}

/// [`dissect_to_text`] with the opt-in extras: the span taxonomy
/// (`dissect --spans`: a `spans:` section per layer plus a payload span
/// line) and the retained frame (`dissect --frame`, tranche 14: a
/// `frame (N bytes): <hex>` line after the payload section). Without
/// the flags the text is byte-identical to [`dissect_to_text`].
pub fn dissect_to_text_spans(p: &DissectedPacket, spans: bool, frame: bool) -> String {
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
        if spans {
            out.push_str(&format!("{indent}  spans:\n"));
            for (name, span) in &layer.field_spans {
                out.push_str(&format!("{indent}    {name}: {}\n", field_span_text(span)));
            }
        }
    }
    if !p.payload.is_empty() {
        out.push_str(&format!("payload ({} bytes):\n", p.payload.len()));
        out.push_str(&hexdump(&p.payload));
    } else {
        out.push_str("payload (0 bytes)\n");
    }
    if frame {
        out.push_str(&format!(
            "frame ({} bytes): {}\n",
            p.frame.len(),
            hex::encode(&p.frame)
        ));
    }
    if spans {
        let payload_at = p.frame.len() - p.payload.len();
        out.push_str(&format!("payload span @{payload_at}..{}\n", p.frame.len()));
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

    #[test]
    fn spans_opt_in_shapes() {
        let s = spans_sample();
        // Off: byte-identical to the pinned shapes (no spans keys).
        let plain = dissect_to_json(&s);
        assert!(plain["layers"][0].get("spans").is_none());
        assert!(plain.get("payload_span").is_none());
        assert_eq!(plain, dissect_to_json_spans(&s, false, false));

        // On: per-layer spans maps + the payload span.
        let sp = dissect_to_json_spans(&s, true, false);
        assert_eq!(
            sp["layers"][0]["spans"]["dst"],
            json!({"type": "bytes", "start": 0, "end": 6})
        );
        assert_eq!(
            sp["layers"][0]["spans"]["type"],
            json!({
                "type": "bits",
                "start": 12,
                "end": 14,
                "shift": 0,
                "width": 16,
            })
        );
        assert_eq!(sp["layers"][1]["spans"]["sport"], "none");
        assert_eq!(
            sp["layers"][1]["spans"]["flags.syn"],
            json!({
                "type": "bits", "start": 20, "end": 21, "shift": 0, "width": 1,
            })
        );
        assert_eq!(sp["payload_span"], json!([22, 26]));

        // Text: a spans section per layer + the payload span line,
        // absent without the flag.
        let text = dissect_to_text_spans(&s, true, false);
        assert!(text.contains("spans:\n"), "{text}");
        assert!(text.contains("dst: bytes @0..6\n"), "{text}");
        assert!(text.contains("sport: none\n"), "{text}");
        assert!(text.contains("payload span @22..26\n"), "{text}");
        assert!(!dissect_to_text(&s).contains("spans:"), "{text}");
    }

    /// Tranche 14 (`dissect --frame`): the retained input frame as hex,
    /// opt-in and additive — default shapes carry no `frame` at all.
    #[test]
    fn frame_opt_in_shapes() {
        let s = spans_sample();
        // Off: no frame key/line anywhere (the pinned shapes).
        let plain = dissect_to_json(&s);
        assert!(plain.get("frame").is_none());
        assert!(!dissect_to_text(&s).contains("frame ("), "default text");

        // On (json): a top-level `frame` hex key — the input bytes
        // verbatim (26 zero bytes in the fixture).
        let v = dissect_to_json_spans(&s, false, true);
        assert_eq!(v["frame"], json!(hex::encode(&s.frame[..])));
        // jsonl rides the same object.
        let line = dissect_to_jsonl_spans(&s, false, true);
        let parsed: JsonValue = serde_json::from_str(&line).expect("jsonl line");
        assert_eq!(parsed["frame"], v["frame"]);

        // On (text): a `frame (N bytes): <hex>` line after the payload
        // section; fields/anomalies unchanged.
        let text = dissect_to_text_spans(&s, false, true);
        assert!(
            text.contains(&format!(
                "frame ({} bytes): {}\n",
                s.frame.len(),
                hex::encode(&s.frame[..])
            )),
            "{text}"
        );
        // composes with --spans.
        assert!(dissect_to_text_spans(&s, true, true).contains("frame ("));
    }

    /// A sample carrying field spans (bytes, bits, sub-bit, none).
    fn spans_sample() -> DissectedPacket {
        let s = sample();
        let mut eth_spans = BTreeMap::new();
        eth_spans.insert("dst".to_string(), FieldSpan::Bytes(0..6));
        eth_spans.insert("src".to_string(), FieldSpan::Bytes(6..12));
        eth_spans.insert(
            "type".to_string(),
            FieldSpan::Bits {
                container: 12..14,
                shift: 0,
                width: 16,
            },
        );
        let mut udp_spans = BTreeMap::new();
        udp_spans.insert("sport".to_string(), FieldSpan::None);
        udp_spans.insert(
            "flags.syn".to_string(),
            FieldSpan::Bits {
                container: 20..21,
                shift: 0,
                width: 1,
            },
        );
        let mut p = s.clone();
        p.layers[0].field_spans = eth_spans;
        p.layers[1].field_spans = udp_spans;
        // The coverage invariant: layers 0..14, 14..22, payload 22..26.
        p.frame = B::from(vec![0u8; 26]);
        p
    }
}
