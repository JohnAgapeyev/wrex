//! Dissection output model and chain-walk engine.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::ops::Range;

use bytes::Bytes;

use crate::codec::{Next, ReadOutcome, Registry};
use crate::error::DecodeError;
use crate::value::Value;

/// Facts propagated along the dissection chain (recorded by network-layer
/// codecs, consumed by L4 checksum verification).
#[derive(Clone, Copy, Debug)]
pub struct NetFacts {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Facts {
    pub net: Option<NetFacts>,
    /// Interface MAC (send `-i`): eth.src autofill source.
    pub link_src: Option<[u8; 6]>,
    /// Interface MAC for dst autofill (reserved; unused in tranche 1).
    pub link_dst: Option<[u8; 6]>,
}

/// One dissected layer: kind, byte span in the input, and local fields.
#[derive(Clone, Debug)]
pub struct LayerView {
    pub kind: &'static str,
    pub span: Range<usize>,
    pub fields: BTreeMap<String, Value>,
}

/// A non-fatal dissection anomaly (`! path: message` in text output).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anomaly {
    pub path: String,
    pub message: String,
}

impl Anomaly {
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Anomaly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "! {}: {}", self.path, self.message)
    }
}

/// A fully dissected packet. Never fatal: structural failures become
/// [`Anomaly`]s plus a synthetic `unknown` layer holding the remaining bytes.
#[derive(Clone, Debug)]
pub struct DissectedPacket {
    pub start: &'static str,
    pub layers: Vec<LayerView>,
    pub payload: Bytes,
    pub anomalies: Vec<Anomaly>,
}

/// Per-chain-walk decode context handed to [`crate::codec::Codec::read`].
pub struct DecodeCtx<'a> {
    /// Absolute offset of `bytes` within the full input.
    pub offset: usize,
    /// Facts recorded by earlier layers in this chain.
    pub facts: Facts,
    /// Non-fatal anomalies pushed by codecs (checksum mismatches etc.).
    pub anomalies: Vec<Anomaly>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> DecodeCtx<'a> {
    pub fn new(offset: usize) -> Self {
        Self {
            offset,
            facts: Facts::default(),
            anomalies: Vec::new(),
            _lifetime: PhantomData,
        }
    }
}

/// Auto-start heuristic for `dissect --start auto`:
/// `bytes[0] >> 4 == 4` → ipv4; `== 6` → unknown (ipv6 unsupported this
/// tranche); else len ≥ 14 → eth; else unknown.
pub fn auto_start(bytes: &[u8]) -> &'static str {
    match bytes.first() {
        None => "unknown",
        Some(&b) if b >> 4 == 4 => "ipv4",
        // 6 is the IPv6 version nibble; unsupported in tranche 1.
        Some(&b) if b >> 4 == 6 => "unknown",
        Some(_) if bytes.len() >= 14 => "eth",
        _ => "unknown",
    }
}

/// Synthesize the terminal `unknown` layer holding `bytes` as one `hex` field.
fn unknown_layer(bytes: &[u8], offset: usize) -> LayerView {
    let mut fields = BTreeMap::new();
    fields.insert(
        "hex".to_string(),
        Value::Bytes(Bytes::copy_from_slice(bytes)),
    );
    LayerView {
        kind: "unknown",
        span: offset..offset + bytes.len(),
        fields,
    }
}

/// Dissect `bytes` starting at `start` (a registry kind or `"auto"`).
///
/// `start` is resolved through the registry so [`DissectedPacket::start`] is
/// always a registered `&'static str` (or the literal `"unknown"`).
pub fn dissect(registry: &Registry, bytes: &[u8], start: &str) -> DissectedPacket {
    let start: &'static str = if start == "auto" {
        auto_start(bytes)
    } else {
        match registry.get(start) {
            Some(codec) => codec.schema().kind,
            None => "unknown",
        }
    };
    let mut layers: Vec<LayerView> = Vec::new();
    let mut anomalies: Vec<Anomaly> = Vec::new();
    let mut facts = Facts::default();
    let mut offset = 0usize;
    let mut chain = Some(Next::Kind(start));
    let mut payload_start = None;

    while let Some(next) = chain {
        match next {
            Next::Payload => {
                payload_start = Some(offset);
                chain = None;
            }
            Next::Kind(kind) => {
                let rest = &bytes[offset.min(bytes.len())..];
                match registry.get(kind) {
                    Some(codec) => {
                        let mut ctx = DecodeCtx::new(offset);
                        ctx.facts = facts;
                        match codec.read(rest, &mut ctx) {
                            ReadOutcome::Layer(view, next) => {
                                offset += view.span.len();
                                facts = ctx.facts;
                                anomalies.append(&mut ctx.anomalies);
                                layers.push(view);
                                chain = Some(next.unwrap_or(Next::Payload));
                            }
                            ReadOutcome::Anomaly(err, _next) => {
                                facts = ctx.facts;
                                anomalies.append(&mut ctx.anomalies);
                                anomalies.push(anomaly_for(&err));
                                // Structural failure: keep the remaining bytes
                                // as partial data in a synthetic layer.
                                layers.push(unknown_layer(rest, offset));
                                offset = bytes.len();
                                payload_start = Some(bytes.len());
                                chain = None;
                            }
                            ReadOutcome::Empty => {
                                facts = ctx.facts;
                                anomalies.append(&mut ctx.anomalies);
                                payload_start = Some(offset);
                                chain = None;
                            }
                        }
                    }
                    None => {
                        // Unknown/unregistered kind (unknown ethertype, ipv6,
                        // `--start unknown`): synthetic hex layer, terminal.
                        layers.push(unknown_layer(rest, offset));
                        offset = bytes.len();
                        payload_start = Some(bytes.len());
                        chain = None;
                    }
                }
            }
        }
    }

    let payload_at = payload_start.unwrap_or(bytes.len()).min(bytes.len());
    DissectedPacket {
        start,
        layers,
        payload: Bytes::copy_from_slice(&bytes[payload_at..]),
        anomalies,
    }
}

fn anomaly_for(err: &DecodeError) -> Anomaly {
    match err {
        DecodeError::Truncated { kind, need, have } => {
            Anomaly::new(*kind, format!("truncated: need {need} bytes, have {have}"))
        }
        DecodeError::BadField { path, reason } => Anomaly::new(path.clone(), reason.clone()),
        DecodeError::Unsupported { kind } => Anomaly::new(*kind, "unsupported".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heuristic_table() {
        assert_eq!(auto_start(&[]), "unknown");
        assert_eq!(auto_start(&[0x45, 0x00]), "ipv4");
        assert_eq!(auto_start(&[0x60, 0x00, 0x00, 0x00]), "unknown"); // ipv6
        assert_eq!(auto_start(&[0xff; 14]), "eth");
        assert_eq!(auto_start(&[0xff; 13]), "unknown");
        assert_eq!(auto_start(&[0x00, 0x11, 0x22]), "unknown");
    }

    #[test]
    fn empty_input_is_never_fatal() {
        let r = Registry::empty();
        let p = dissect(&r, &[], "auto");
        assert_eq!(p.start, "unknown");
        assert_eq!(p.layers.len(), 1);
        assert_eq!(p.layers[0].kind, "unknown");
        assert_eq!((p.layers[0].span.start, p.layers[0].span.end), (0, 0));
        assert!(p.payload.is_empty());
    }

    #[test]
    fn unknown_start_kind_synthesizes() {
        let r = Registry::empty();
        let p = dissect(&r, &[0xaa, 0xbb], "eth");
        // no eth codec registered: unknown layer holding the bytes
        assert_eq!(p.layers.len(), 1);
        assert_eq!(p.layers[0].kind, "unknown");
        assert_eq!(p.layers[0].span, 0..2);
        match p.layers[0].fields.get("hex") {
            Some(Value::Bytes(b)) => assert_eq!(&b[..], &[0xaa, 0xbb]),
            other => panic!("no hex field: {other:?}"),
        }
    }
}
