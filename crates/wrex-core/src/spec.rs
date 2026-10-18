//! Packet specification model (`PacketSpec`/`LayerSpec`) feeding the encode
//! engine.

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
    pub fields: BTreeMap<String, Value>,
}

impl LayerSpec {
    pub fn new(kind: &'static str) -> Self {
        Self {
            kind,
            fields: BTreeMap::new(),
        }
    }

    pub fn with_fields(kind: &'static str, fields: BTreeMap<String, Value>) -> Self {
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
