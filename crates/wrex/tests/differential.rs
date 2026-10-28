//! Differential suite (`cargo test -- differential`): random specs from the
//! per-proto strategies → encode → dissect; field roundtrip + both oracles
//! (etherparse in-process, tshark subprocess) must agree. tshark skips
//! (with a printed notice) when unavailable.
//!
//! Proptest-based and tshark-spawning: ignored under Miri (the
//! deterministic engine/codec unit tests run there).
#![cfg_attr(miri, ignore = "proptest + subprocess tshark; not Miri-safe")]

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

use wrex_core::Registry;
use wrex_core::encode::{EncodeOpts, encode};
use wrex_core::schema::{FieldKind, ResolvedField};
use wrex_core::value::Value;
use wrex_test::oracle::{EtherparseOracle, Oracle, TsharkOracle};
use wrex_test::strategies::{packet_strategy, stacks};

/// One skip notice per test binary, not one per proptest case.
static SKIP_NOTICE: std::sync::Once = std::sync::Once::new();

fn registry() -> Registry {
    wrex::standard()
}

/// One (stack, spec) pair: pick a stack, generate its spec.
fn stack_spec() -> impl Strategy<Value = (&'static str, wrex_core::PacketSpec)> {
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

    /// Differential: encode → dissect → roundtrip + etherparse agreement.
    #[test]
    fn differential_roundtrip_and_oracles((stack, spec) in stack_spec()) {
        let reg = registry();
        let encoded = encode(
            &reg,
            &spec,
            &EncodeOpts { autofill: true, ..Default::default() },
        )
        .expect("encode must not panic");
        // Dissect from the spec's own first layer: `auto` would misfire the
        // start heuristic on random eth.dst bytes (whose first-byte nibble
        // can look like an IP version). This is a spec roundtrip, so the
        // start is known.
        let start = spec.layers.first().map_or("auto", |l| l.kind);
        let packet = wrex_core::dissect::dissect(&reg, &encoded.bytes, start);
        // never fatal; anomalies may only concern layers OUTSIDE the spec's
        // stack (an explicit eth.type can point at unregistered kinds —
        // that's data, not a bug in our specs).
        let stack_kinds: Vec<&str> = spec.layers.iter().map(|l| l.kind).collect();
        for a in &packet.anomalies {
            let layer_kind = a.path.split('.').next().unwrap_or("");
            prop_assert!(
                !stack_kinds.contains(&layer_kind),
                "stack {stack}: anomaly on our own layer: {a}"
            );
        }
        // Field roundtrip for explicitly-set whole fields. Layer kinds must
        // match while the chain follows the spec; a diverging explicit
        // eth.type legally ends the comparable prefix.
        let mut ok = true;
        for (i, (layer_spec, layer_view)) in
            spec.layers.iter().zip(&packet.layers).enumerate()
        {
            if layer_spec.kind != layer_view.kind {
                prop_assert!(i > 0, "stack {stack}: first layer kind mismatch");
                ok = false;
            }
            if !ok {
                break;
            }
            for (k, v) in &layer_spec.fields {
                // Schema-driven skips (the G1 fix made dotted names and
                // flag sets common): per-bit subpaths (`flags.syn=true`)
                // merge into their aggregate at encode time; list-grammar
                // fields (`options`, icmpv6 `mld`) render as record
                // sections on dissection, not typed-equal values.
                let resolved = reg
                    .schema(layer_spec.kind)
                    .and_then(|s| s.resolve(k));
                if matches!(resolved, Some(ResolvedField::FlagBit { .. })) {
                    continue; // per-bit subpaths merge into their aggregate
                }
                if k == "options" || k == "mld" {
                    continue; // list grammars → raw bytes/records, not typed-equal
                }
                if let Some(ResolvedField::Field(f)) = resolved
                    && f.kind == FieldKind::FlagSet
                {
                    // Flag-set aggregate: spec holds a mask, dissection a
                    // name list in `bit_names` MSB-first order — compare
                    // semantically through the schema (any layer's flags,
                    // not just tcp's: ipv4 [mf,df,res] randomizes since
                    // the G1 sweep).
                    let Value::Int(mask) = v else { continue };
                    let n = f.bit_names.len();
                    let want: Vec<String> = f
                        .bit_names
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| mask & (1u128 << (n - 1 - i)) != 0)
                        .map(|(_, name)| name.to_string())
                        .collect();
                    let got: Vec<String> = match layer_view.fields.get(k) {
                        Some(Value::List(items)) => items
                            .iter()
                            .filter_map(|v| match v {
                                Value::Str(s) => Some(s.to_string()),
                                _ => None,
                            })
                            .collect(),
                        _ => Vec::new(),
                    };
                    prop_assert!(
                        got == want,
                        "{stack} {}.{k}: got {got:?} want {want:?}",
                        layer_spec.kind
                    );
                    continue;
                }
                let got = layer_view.fields.get(k).cloned();
                prop_assert!(
                    values_equal(&got, v),
                    "{stack} {}.{}: set {v:?} got {got:?}",
                    layer_spec.kind,
                    k
                );
            }
        }
        // in-process etherparse oracle
        let ep = EtherparseOracle;
        prop_assert!(ep.is_available());
        if let Err(report) = ep.dissect_diff(&encoded.bytes, &packet) {
            prop_assert!(
                report.mismatches.is_empty(),
                "stack {stack}: etherparse diffs {:?}",
                report.mismatches
            );
        }
    }

    /// tshark differential (subprocess) over the same generated frames.
    /// tshark absent → skip with one printed notice and a plain early
    /// return per case; `prop_assume!(false)` would burn proptest's
    /// global reject budget (1024) and abort the run.
    #[test]
    fn differential_tshark((stack, spec) in stack_spec()) {
        let tshark = TsharkOracle;
        if !tshark.is_available() {
            SKIP_NOTICE.call_once(|| {
                eprintln!(
                    "differential_tshark: skipping (tshark not on PATH, WREX_DIFF_TSHARK unset)"
                );
            });
            return Ok(());
        }
        let reg = registry();
        let encoded = encode(
            &reg,
            &spec,
            &EncodeOpts { autofill: true, ..Default::default() },
        )
        .expect("encode");
        let start = spec.layers.first().map_or("auto", |l| l.kind);
        let packet = wrex_core::dissect::dissect(&reg, &encoded.bytes, start);
        if let Err(report) = tshark.dissect_diff(&encoded.bytes, &packet) {
            prop_assert!(
                report.mismatches.is_empty(),
                "stack {stack}: tshark diffs {:?}",
                report.mismatches
            );
        }
    }
}

/// Loose typed equality for roundtrip comparison.
fn values_equal(a: &Option<wrex_core::Value>, b: &wrex_core::Value) -> bool {
    match (a, b) {
        (Some(wrex_core::Value::Int(x)), wrex_core::Value::Int(y)) => x == y,
        (Some(wrex_core::Value::Ipv4(x)), wrex_core::Value::Ipv4(y)) => x == y,
        (Some(wrex_core::Value::Ipv6(x)), wrex_core::Value::Ipv6(y)) => x == y,
        (Some(wrex_core::Value::Mac(x)), wrex_core::Value::Mac(y)) => x == y,
        (Some(wrex_core::Value::Str(x)), wrex_core::Value::Str(y)) => x == y,
        (Some(wrex_core::Value::Bool(x)), wrex_core::Value::Bool(y)) => x == y,
        (Some(wrex_core::Value::Bytes(x)), wrex_core::Value::Bytes(y)) => x == y,
        _ => false,
    }
}
