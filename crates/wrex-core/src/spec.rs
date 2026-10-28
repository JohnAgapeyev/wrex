//! Packet specification model (`PacketSpec`/`LayerSpec`) feeding the encode
//! engine.

use std::borrow::Cow;
use std::collections::BTreeMap;

use serde::Serialize;

use crate::value::Value;

/// One layer of a packet specification.
///
/// `fields` keys are field names or dotted subpaths (`"flags.syn"`). `kind`
/// is always a registry kind (`&'static str` from a validated `--layer` or
/// implied from field flags).
#[derive(Clone, Debug, Serialize)]
pub struct LayerSpec {
    pub kind: &'static str,
    pub fields: BTreeMap<Cow<'static, str>, Value>,
}

impl LayerSpec {
    pub fn new(kind: &'static str) -> Self {
        Self {
            kind,
            fields: BTreeMap::new(),
        }
    }

    pub fn with_fields(kind: &'static str, fields: BTreeMap<Cow<'static, str>, Value>) -> Self {
        Self { kind, fields }
    }
}

/// A full packet: outer→inner layer order, plus the terminal payload.
#[derive(Clone, Debug, Serialize, Default)]
pub struct PacketSpec {
    pub layers: Vec<LayerSpec>,
    pub payload: Option<Value>,
}

impl PacketSpec {
    pub fn new(layers: Vec<LayerSpec>, payload: Option<Value>) -> Self {
        Self { layers, payload }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_spec_constructors_and_defaults() {
        let bare = LayerSpec::new("eth");
        assert_eq!(bare.kind, "eth");
        assert!(bare.fields.is_empty());
        let mut fields = BTreeMap::new();
        fields.insert("dst".into(), Value::Int(1));
        let with = LayerSpec::with_fields("eth", fields.clone());
        assert_eq!(with.kind, "eth");
        assert_eq!(with.fields.len(), 1);
        // Clone is distinct (derive smoke).
        let cloned = with.clone();
        assert_eq!(cloned.fields, fields);
    }

    #[test]
    fn packet_spec_default_and_new() {
        let d = PacketSpec::default();
        assert!(d.layers.is_empty());
        assert!(d.payload.is_none());
        let p = PacketSpec::new(vec![LayerSpec::new("eth")], Some(Value::Int(7)));
        assert_eq!(p.layers.len(), 1);
        assert_eq!(p.layers[0].kind, "eth");
        assert_eq!(p.payload, Some(Value::Int(7)));
    }

    /// The specs Serialize (jsonl lines carry them); shape smoke so a
    /// serde rename can't slip through unnoticed.
    #[test]
    fn packet_spec_serializes() {
        let mut fields = BTreeMap::new();
        fields.insert("type".into(), Value::Int(2048));
        let p = PacketSpec::new(
            vec![LayerSpec::with_fields("eth", fields)],
            Some(Value::Int(1)),
        );
        let j = serde_json::to_string(&p).expect("serialize");
        assert!(j.contains(r#""kind":"eth""#), "kind field: {j}");
        assert!(j.contains(r#""layers""#), "layers field: {j}");
        assert!(j.contains(r#""payload""#), "payload field: {j}");
    }
}
