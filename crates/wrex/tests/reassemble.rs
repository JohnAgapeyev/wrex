//! Tranche 11a gate (`cargo test -- reassemble`): the byte-fidelity
//! contract. `DissectedPacket` retains the original frame and
//! `reassemble` stitches the layer spans + payload back out of it —
//! with zero edits that is byte-identical **by construction**, for any
//! input dissection accepts, malformed included: no field is ever
//! re-derived on the path.
//!
//! Three gates:
//! 1. every stack strategy: encode → dissect → reassemble == encoded;
//! 2. every corpus frame (golden + captured traffic): dissect(auto) →
//!    reassemble == frame bytes;
//! 3. a deliberately wrong checksum survives verbatim — the anomaly is
//!    carried, never healed (the future tranche-11b span-patch engine's
//!    `preserve` semantics ride this same property).
//!
//! Proptest-based: ignored under Miri (the deterministic engine/codec
//! unit tests run there).
#![cfg_attr(miri, ignore = "proptest; not Miri-safe")]

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

use wrex_core::Registry;
use wrex_core::dissect;
use wrex_core::encode::{EncodeOpts, encode};
use wrex_core::spec::{LayerSpec, PacketSpec};
use wrex_core::value::Value;
use wrex_test::corpus::Corpus;
use wrex_test::strategies::{packet_strategy, stacks};

fn registry() -> Registry {
    wrex::standard()
}

/// One (stack, spec) pair: pick a stack, generate its spec (the
/// differential-suite pattern).
fn stack_spec() -> impl Strategy<Value = (&'static str, PacketSpec)> {
    proptest::sample::select(stacks().to_vec())
        .prop_flat_map(|stack| packet_strategy(stack).prop_map(move |spec| (stack, spec)))
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Gate 1: encode → dissect → reassemble == encoded bytes, every
    /// stack. The frame is retained and the coverage invariant (layer
    /// spans ordered, non-overlapping, payload tail) is debug-asserted
    /// inside `reassemble` — a codec that mis-spans fails here.
    #[test]
    fn reassemble_matches_encoded_bytes((stack, spec) in stack_spec()) {
        let reg = registry();
        let encoded = encode(
            &reg,
            &spec,
            &EncodeOpts { autofill: true, ..Default::default() },
        )
        .expect("encode must not panic");
        // Dissect from the spec's own first layer (the differential-suite
        // rule: `auto` would misfire the start heuristic on random
        // eth.dst bytes).
        let start = spec.layers.first().map_or("auto", |l| l.kind);
        let p = dissect(&reg, &encoded.bytes, start);
        prop_assert_eq!(&p.frame[..], &encoded.bytes[..], "frame retained: {}", stack);
        prop_assert_eq!(
            &p.reassemble()[..],
            &encoded.bytes[..],
            "reassemble == encoded: {}", stack
        );
    }
}

/// Gate 2: every corpus frame — golden vectors and real captured
/// traffic — dissects (auto) and reassembles to the identical bytes.
/// Malformed corpus fixtures are included: never-fatal dissection keeps
/// their bytes verbatim too.
#[test]
fn reassemble_corpus_frames() {
    let reg = registry();
    let corpora = Corpus::load_all();
    assert!(!corpora.is_empty(), "no corpora found");
    let mut checked = 0usize;
    for corpus in &corpora {
        for frame in &corpus.frames {
            let p = dissect(&reg, &frame.bytes, "auto");
            assert_eq!(
                &p.reassemble()[..],
                &frame.bytes[..],
                "corpus {}.{}",
                corpus.name,
                frame.name
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no corpus frames checked");
}

/// Gate 3: a deliberately wrong checksum (explicit field wins, autofill
/// does not heal it) survives dissection as an anomaly and reassembles
/// byte-identically — invalidity is preserved, not repaired.
#[test]
fn reassemble_preserves_deliberate_invalidity() {
    let reg = registry();
    let mut eth = LayerSpec::new("eth");
    eth.fields.insert("dst".into(), Value::Mac([0xff; 6]));
    eth.fields.insert("src".into(), Value::Mac([0x00; 6]));
    // eth.type derived from the next layer (autofill)
    let mut ipv4 = LayerSpec::new("ipv4");
    ipv4.fields.insert(
        "src".into(),
        Value::Ipv4("127.0.0.1".parse().expect("loopback")),
    );
    ipv4.fields.insert(
        "dst".into(),
        Value::Ipv4("127.0.0.1".parse().expect("loopback")),
    );
    ipv4.fields.insert("proto".into(), Value::Int(17));
    // Deliberate garbage: the explicit value wins over autofill.
    ipv4.fields.insert("checksum".into(), Value::Int(0x1234));
    let spec = PacketSpec::new(
        vec![eth, ipv4],
        Some(Value::Bytes(b"deadbeef".as_slice().into())),
    );
    let encoded = encode(
        &reg,
        &spec,
        &EncodeOpts {
            autofill: true,
            ..Default::default()
        },
    )
    .expect("encode with explicit checksum");
    let p = dissect(&reg, &encoded.bytes, "eth");
    assert!(
        p.anomalies
            .iter()
            .any(|a| a.path.starts_with("ipv4.checksum")),
        "wrong checksum must carry an anomaly: {:?}",
        p.anomalies
    );
    // ...and the wrong bytes themselves survive the stitch untouched.
    assert_eq!(&p.reassemble()[..], &encoded.bytes[..]);
    // Sanity: the wire really does carry the garbage (not healed).
    // eth(14) + ipv4 checksum at offset 10 of its header.
    let checksum_bytes = &encoded.bytes[24..26];
    assert_eq!(checksum_bytes, &[0x12, 0x34]);
}
