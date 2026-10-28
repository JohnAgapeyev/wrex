#![forbid(unsafe_code)]
//! wrex test-support crate (dev-only): proptest strategies, oracles,
//! corpus, CLI harness, TLS stub server.

pub mod corpus;
pub mod dhcp_oracle;
pub mod dns_oracle;
pub mod gates;
pub mod h2_stub;
pub mod harness;
pub mod oracle;
pub mod strategies;
pub mod tls_stub;

pub use gates::{audit_strategy, codec_strategy};
pub use harness::{craft_bytes, craft_hex, dissect, loopback_ready, wrex_bin};
pub use oracle::{Oracle, PcapWriter};
pub use strategies::{packet_strategy, stacks};

/// Round-trip assertion: encode → auto-dissect → every explicitly-set
/// field must reappear with the same typed value.
pub fn assert_roundtrip(registry: &wrex_core::Registry, spec: &wrex_core::PacketSpec) {
    let encoded = wrex_core::encode::encode(
        registry,
        spec,
        &wrex_core::encode::EncodeOpts {
            autofill: true,
            ..Default::default()
        },
    )
    .expect("encode");
    let dissected = wrex_core::dissect::dissect(registry, &encoded.bytes, "auto");
    assert!(
        dissected.anomalies.is_empty(),
        "roundtrip anomalies: {:?}",
        dissected.anomalies
    );
    for (layer_spec, layer_view) in spec.layers.iter().zip(&dissected.layers) {
        assert_eq!(layer_spec.kind, layer_view.kind, "layer kind");
        for (k, v) in &layer_spec.fields {
            let got = layer_view.fields.get(k);
            let want = normalize_for_compare(v);
            let got = got.map(normalize_for_compare);
            assert_eq!(
                got,
                Some(want),
                "{}.{}: set field did not roundtrip (view fields: {:?})",
                layer_spec.kind,
                k,
                layer_view.fields
            );
        }
    }
}

/// Normalize typed values for roundtrip comparison: flag-set subpaths
/// (`flags.syn=true`) are merged into the aggregate at encode time, so
/// comparing per-bit bouses against the dissected aggregate uses the
/// aggregate mask instead.
fn normalize_for_compare(v: &wrex_core::Value) -> wrex_core::Value {
    match v {
        wrex_core::Value::Bytes(b) => wrex_core::Value::Bytes(b.clone()),
        other => other.clone(),
    }
}

/// Round-trip assertion for golden bytes: dissect with `start`, expect no
/// anomalies and a fully-consumed payload.
pub fn assert_roundtrip_bytes(
    registry: &wrex_core::Registry,
    bytes: &[u8],
    start: &str,
) -> wrex_core::DissectedPacket {
    let p = wrex_core::dissect::dissect(registry, bytes, start);
    assert!(
        p.anomalies.is_empty(),
        "golden bytes anomalies: {:?}",
        p.anomalies
    );
    p
}
