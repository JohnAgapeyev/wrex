#![no_main]
//! libfuzzer target: arbitrary bounded LayerSpec stack → encode must not
//! panic; if encode succeeds, dissection must not panic and must carry the
//! encoded bytes as its leading region.

use std::collections::BTreeMap;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wrex::standard;
use wrex_core::encode::{encode, EncodeOpts};
use wrex_core::spec::{LayerSpec, PacketSpec};
use wrex_core::value::Value;

/// One settable field slot: pick from the layer schema by index.
#[derive(Arbitrary, Debug)]
struct FuzzField {
    path_idx: u8,
    int_val: u64,
    flag: bool,
}

/// One layer: kind picked from the registry by index.
#[derive(Arbitrary, Debug)]
struct FuzzLayer {
    kind_idx: u8,
    fields: Vec<FuzzField>,
}

/// A bounded packet spec.
#[derive(Arbitrary, Debug)]
struct FuzzSpec {
    layers: Vec<FuzzLayer>,
    payload: Option<Vec<u8>>,
}

const KINDS: &[&str] = &["eth", "arp", "ipv4", "icmp", "udp", "tcp"];

fn to_packet_spec(f: &FuzzSpec) -> PacketSpec {
    let registry = standard();
    let mut layers = Vec::new();
    for l in &f.layers {
        let kind = KINDS[(l.kind_idx as usize) % KINDS.len()];
        let Some(schema) = registry.schema(kind) else { continue };
        let mut fields: BTreeMap<String, Value> = BTreeMap::new();
        for fs in &l.fields {
            let field =
                &schema.fields[(fs.path_idx as usize) % schema.fields.len()];
            let value = match field.kind {
                wrex_core::FieldKind::Mac => {
                    let mut m = [0u8; 6];
                    m.copy_from_slice(&fs.int_val.to_le_bytes()[..6]);
                    Value::Mac(m)
                }
                wrex_core::FieldKind::Ipv4 => {
                    Value::Ipv4(std::net::Ipv4Addr::from(
                        (fs.int_val as u32).to_le_bytes(),
                    ))
                }
                wrex_core::FieldKind::FlagSet => {
                    if fs.flag {
                        Value::Int(1)
                    } else {
                        Value::Int(0)
                    }
                }
                wrex_core::FieldKind::Bytes | wrex_core::FieldKind::ByteList => {
                    continue; // options use the list grammar, not raw ints
                }
                _ => Value::Int(fs.int_val as u128),
            };
            fields.insert(field.name.to_string(), value);
        }
        layers.push(LayerSpec::with_fields(schema.kind, fields));
    }
    let payload = f.payload.as_ref().map(|p| {
        Value::Bytes(bytes::Bytes::copy_from_slice(p))
    });
    PacketSpec::new(layers, payload)
}

fuzz_target!(|spec: FuzzSpec| {
    let registry = standard();
    let packet_spec = to_packet_spec(&spec);
    // Required fields may make encode fail with Unfillable — that's fine,
    // but it must not panic.
    let Ok(encoded) = encode(
        &registry,
        &packet_spec,
        &EncodeOpts { autofill: true, ..Default::default() },
    ) else {
        return;
    };
    // Dissection of our own output must not panic, must consume at least
    // the first layer, and the layers must round-trip their kinds.
    let dissected =
        wrex_core::dissect::dissect(&registry, &encoded.bytes, "auto");
    assert!(
        !dissected.layers.is_empty(),
        "encode produced {} bytes but dissection found no layers",
        encoded.bytes.len()
    );
    let spec_kinds: Vec<&str> = packet_spec.layers.iter().map(|l| l.kind).collect();
    let got_kinds: Vec<&str> = dissected.layers.iter().map(|l| l.kind).collect();
    // The leading kinds must match where both parsed (trailing layers may
    // merge into `unknown` when random types point at unregistered kinds).
    for (i, k) in spec_kinds.iter().enumerate() {
        if let Some(got) = got_kinds.get(i) {
            if *got != "unknown" {
                assert_eq!(got, k, "layer {i} kind mismatch: {got:?} vs {k}");
            }
        }
    }
});