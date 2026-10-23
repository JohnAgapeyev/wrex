//! Tranche 14 verification at the engine + CLI-library level (no
//! binary spawns, no sockets — except the tshark oracle, which is
//! Miri-ignored):
//!
//! 1. **Identity sweep** — every corpus frame, every `span-Bytes` field:
//!    a self-value `--set` through the REAL verb grammar (`wrex::edit`)
//!    under preserve semantics (`Scope::none`) reproduces the input
//!    bytes exactly. Nothing is re-derived, so identity holds for any
//!    input dissection accepts, malformed included (the T11a contract
//!    transposed to the edit path).
//! 2. **Normalize degenerate** — zero edits + `Scope::all` on an
//!    anomaly-free corpus frame is byte-identity: recomputation of a
//!    consistent frame writes the same bytes ("normalize" never
//!    invents changes).
//! 3. **Never-panic proptest** — random edit sets over corpus frames:
//!    the grammar resolves to bytes or a pointed error, and a resolved
//!    output re-dissects.
//! 4. **tshark differential** — patched frames (field edit, payload
//!    insert/delete, vlan insert/delete) against the independent
//!    lineage oracle (ADR 2's inversion rule; wrex's zero-anomaly
//!    re-dissection is the checksum ground truth).
use std::sync::LazyLock;

use bytes::Bytes;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use wrex_core::dissect::{FieldSpan, dissect};
use wrex_core::encode::{EncodeOpts, encode};
use wrex_core::patch::{Edit, Scope, patch};
use wrex_core::spec::{LayerSpec, PacketSpec};
use wrex_core::value::Value;
use wrex_core::{FieldKind, Registry};
use wrex_test::corpus::Corpus;

fn registry() -> Registry {
    wrex::standard()
}

/// Every corpus frame, flattened (golden + captured traffic).
static FRAMES: LazyLock<Vec<Vec<u8>>> = LazyLock::new(|| {
    Corpus::load_all()
        .into_iter()
        .flat_map(|c| c.frames.into_iter().map(|f| f.bytes))
        .collect()
});

/// Render a dissected value back into the CLI value grammar, keyed on
/// the SCHEMA kind (the dissected value may be typed differently — A
/// record rdata is schema-Bytes behind an Ipv4 value): the spelling a
/// user would type to reproduce the current field's wire bytes.
/// `None` = no grammar round-trip exists (resolved-name rdata: the
/// value is not the wire bytes).
fn self_value_expr(kind: FieldKind, v: &Value) -> Option<String> {
    match (kind, v) {
        (_, Value::Int(x)) => Some(x.to_string()),
        (FieldKind::Ipv4, Value::Ipv4(a)) => Some(a.to_string()),
        (FieldKind::Ipv6, Value::Ipv6(a)) => Some(a.to_string()),
        (FieldKind::Mac, Value::Mac(m)) => Some(wrex_core::mac_string(*m)),
        (FieldKind::Bytes | FieldKind::ByteList, Value::Bytes(b)) => {
            Some(format!("hex:{}", hex::encode(b)))
        }
        // A/AAAA rdata: schema-Bytes behind a typed address — the wire
        // bytes ARE the octets.
        (FieldKind::Bytes | FieldKind::ByteList, Value::Ipv4(a)) => {
            Some(format!("hex:{}", hex::encode(a.octets())))
        }
        (FieldKind::Bytes | FieldKind::ByteList, Value::Ipv6(a)) => {
            Some(format!("hex:{}", hex::encode(a.octets())))
        }
        // Str fields reach materialize and refuse there (the pointed
        // wire:HEX redirect) — the sweep asserts that refusal.
        (FieldKind::Str, Value::Str(s)) => Some(s.to_string()),
        // schema-Bytes behind a resolved-name value (CNAME/NS/PTR
        // rdata): the presentation is not the wire bytes — no
        // round-trip to assert.
        (FieldKind::Bytes | FieldKind::ByteList, Value::Str(_)) => None,
        // flagset lists / bools never carry Bytes spans (bit windows)
        _ => None,
    }
}

#[test]
fn identity_sweep_self_value_edits_are_byte_identical() {
    let reg = registry();
    assert!(!FRAMES.is_empty(), "no corpus frames found");
    let mut checked = 0usize;
    let mut str_refusals = 0usize;
    for frame in FRAMES.iter() {
        let p = dissect(&reg, frame, "auto");
        for (li, layer) in p.layers.iter().enumerate() {
            if layer.kind == "unknown" {
                continue; // synthesized, not a registry kind
            }
            // The engine addresses the FIRST layer of a kind (documented
            // resolve_span semantics): a QinQ frame's second vlan.type
            // is not reachable as `vlan.type` — later same-kind layers
            // are out of the sweep's (and the verb's) reach.
            if p.layers[..li].iter().any(|l| l.kind == layer.kind) {
                continue;
            }
            let Some(schema) = reg.schema(layer.kind) else {
                continue;
            };
            for (name, span) in &layer.field_spans {
                let FieldSpan::Bytes(_) = span else {
                    continue;
                };
                let Some(value) = layer.fields.get(name) else {
                    continue;
                };
                let Some(resolved) = schema.resolve(name) else {
                    continue;
                };
                let kind = match resolved {
                    wrex_core::ResolvedField::Field(f) => f.kind,
                    wrex_core::ResolvedField::RecordField { field, .. } => field.kind,
                    // sub-bit paths never carry Bytes spans
                    wrex_core::ResolvedField::FlagBit { .. } => continue,
                };
                let Some(expr) = self_value_expr(kind, value) else {
                    continue;
                };
                let set = format!("{}.{}={expr}", layer.kind, name);
                let edit_set = wrex::edit::parse_edits(
                    &reg,
                    &Scope::none(),
                    std::slice::from_ref(&set),
                    &[],
                    &[],
                )
                .unwrap_or_else(|e| panic!("{set}: parse: {e}"));
                match edit_set.materialize(&p) {
                    Ok(edits) => {
                        // Non-Str values always serialize to their own
                        // wire bytes: a self-value edit under preserve
                        // semantics is byte-identity, by construction.
                        assert!(
                            kind != FieldKind::Str,
                            "{set}: a typed Str over a raw span must refuse"
                        );
                        let out = patch(&reg, &p, &edits, &Scope::none())
                            .unwrap_or_else(|e| panic!("{set}: patch: {e}"));
                        assert_eq!(
                            &out[..],
                            &frame[..],
                            "{set}: a self-value edit under preserve semantics"
                        );
                        checked += 1;
                    }
                    // Str-typed fields over raw spans refuse pointedly:
                    // their presentation is not their wire encoding
                    // (dns names are label-encoded; dns type/class are
                    // u16s behind names) — never silent ASCII bytes.
                    Err(e) => {
                        assert_eq!(kind, FieldKind::Str, "{set}: refused: {e}");
                        assert!(
                            e.to_string().contains("wire:HEX"),
                            "{set}: refusal must point at the escape: {e}"
                        );
                        str_refusals += 1;
                    }
                }
            }
        }
    }
    assert!(checked > 40, "the sweep exercised only {checked} fields");
    assert!(str_refusals > 0, "no Str-over-raw-span fields swept");
}

/// Zero edits + `Scope::all` is the normalize verb: recomputing every
/// derived field of an anomaly-free frame yields another anomaly-free
/// frame, and normalize is a FIXED POINT (idempotent — the second pass
/// writes the same bytes). The corpus sweep caught the v6 payload_len
/// formula here (the first pass wrote a length claiming 52 payload
/// bytes that do not exist; the re-dissection truncated).
#[test]
fn zero_edit_scope_all_normalize_is_a_consistent_fixed_point() {
    let reg = registry();
    let mut checked = 0usize;
    for frame in FRAMES.iter() {
        let p = dissect(&reg, frame, "auto");
        if !p.anomalies.is_empty() {
            continue; // normalize claims consistency for clean frames
        }
        let out1 = patch(&reg, &p, &[], &Scope::all()).expect("patch");
        let fresh = dissect(&reg, &out1, "auto");
        assert!(
            fresh.anomalies.is_empty(),
            "normalize broke a consistent frame: {:?}",
            fresh.anomalies
        );
        let out2 = patch(&reg, &fresh, &[], &Scope::all()).expect("patch");
        assert_eq!(&out1[..], &out2[..], "normalize is idempotent");
        checked += 1;
    }
    assert!(checked > 10, "only {checked} consistent corpus frames");
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        cases: 256,
        ..ProptestConfig::default()
    })]
    /// A random edit set (seeded picks over one corpus frame's fields,
    /// plus shape edits) must never panic: the grammar resolves to
    /// bytes or a pointed error, and a resolved output re-dissects
    /// cleanly (never-panic, the fuzz_mut_strategies rule transposed
    /// to the verb's own grammar).
    #[test]
    fn random_edit_sets_never_panic(seed in any::<u64>(), fi in any::<usize>()) {
        let reg = registry();
        let frames = &*FRAMES;
        prop_assume!(!frames.is_empty());
        let frame = &frames[fi % frames.len()];
        let mut rng = wrex_io::Rng::new(seed);
        let p = dissect(&reg, frame, "auto");
        // candidate paths: every field key of every registry layer.
        let candidates: Vec<String> = p
            .layers
            .iter()
            .filter(|l| l.kind != "unknown")
            .flat_map(|l| l.fields.keys().map(|k| format!("{}.{}", l.kind, k)))
            .collect();
        let mut sets: Vec<String> = Vec::new();
        for _ in 0..(rng.next_u64() % 4) {
            if candidates.is_empty() {
                break;
            }
            let path = &candidates[(rng.next_u64() as usize) % candidates.len()];
            let value = match rng.next_u64() % 6 {
                0 => "1".to_string(),
                1 => "0x1234".to_string(),
                2 => "true".to_string(),
                3 => "10.0.0.1".to_string(),
                4 => format!("hex:{}", hex::encode([(rng.next_u64() % 256) as u8; 2])),
                _ => "wire:aabb".to_string(),
            };
            sets.push(format!("{path}={value}"));
        }
        let mut inserts = Vec::new();
        if rng.next_u64().is_multiple_of(2) {
            let at = (rng.next_u64() as usize) % (frame.len() + 1);
            inserts.push(format!("{at}:aabb"));
        }
        let mut deletes = Vec::new();
        if rng.next_u64().is_multiple_of(4) && frame.len() > 1 {
            let at = (rng.next_u64() as usize) % frame.len();
            deletes.push(format!("{at}:1"));
        }
        let scope = if rng.next_u64().is_multiple_of(2) {
            Scope::all()
        } else {
            Scope::none()
        };
        if let Ok(edit_set) = wrex::edit::parse_edits(&reg, &scope, &sets, &inserts, &deletes)
            && let Ok(edits) = edit_set.materialize(&p)
            && let Ok(out) = patch(&reg, &p, &edits, &scope)
        {
            let _ = dissect(&reg, &out, "auto"); // must not panic
        }
    }
}

// --- tshark differential over patched frames ---------------------------------

fn layer(kind: &'static str, fields: &[(&'static str, Value)]) -> LayerSpec {
    let mut map = std::collections::BTreeMap::new();
    for (k, v) in fields {
        map.insert(k.to_string(), v.clone());
    }
    LayerSpec::with_fields(kind, map)
}

/// eth + ipv4 + udp + payload, autofilled (valid checksums) — the
/// shape-change fixture.
fn udp_frame(reg: &Registry, payload: &[u8]) -> Bytes {
    let spec = PacketSpec::new(
        vec![
            layer("eth", &[("dst", Value::Mac([0xff; 6]))]),
            layer(
                "ipv4",
                &[
                    ("src", Value::Ipv4("127.0.0.1".parse().unwrap())),
                    ("dst", Value::Ipv4("127.0.0.1".parse().unwrap())),
                    ("proto", Value::Int(17)),
                ],
            ),
            layer(
                "udp",
                &[("sport", Value::Int(4444)), ("dport", Value::Int(5555))],
            ),
        ],
        Some(Value::Bytes(Bytes::copy_from_slice(payload))),
    );
    encode(
        reg,
        &spec,
        &EncodeOpts {
            autofill: true,
            ..Default::default()
        },
    )
    .expect("encode")
    .bytes
}

/// Patched frames through the independent-lineage oracle: a real field
/// edit, payload insert/delete (lengths + checksums recompute), and
/// the vlan insert/delete workflows. tshark absent → skip with a
/// notice (the differential.rs precedent). The name carries
/// `differential` so the CI differential job (tshark installed,
/// `-- differential` filter) picks it up.
#[test]
#[cfg_attr(miri, ignore = "spawns tshark; not Miri-safe")]
fn patched_frames_tshark_differential() {
    use wrex_test::oracle::{Oracle, TsharkOracle};

    let tshark = TsharkOracle;
    if !tshark.is_available() {
        eprintln!("patched_frames_match_tshark: skipping (tshark not on PATH)");
        return;
    }
    let reg = registry();
    let frame = udp_frame(&reg, &[0xde, 0xad, 0xbe, 0xef]);
    let p = dissect(&reg, &frame, "eth");
    assert!(p.anomalies.is_empty());

    let check = |out: Bytes, what: &str| {
        let fresh = dissect(&reg, &out, "eth");
        assert!(fresh.anomalies.is_empty(), "{what}: {fresh:?}");
        if let Err(report) = tshark.dissect_diff(&out, &fresh) {
            panic!("{what}: tshark diffs: {:?}", report.mismatches);
        }
    };

    // 1. one real field edit.
    let out = patch(
        &reg,
        &p,
        &[Edit::SetField {
            path: "ipv4.dst".into(),
            bytes: Bytes::from_static(&[10, 1, 2, 3]),
        }],
        &Scope::all(),
    )
    .unwrap();
    check(out, "field edit");

    // 2. payload insert: lengths + checksums recompute (the frame
    // grows by 4; udp payload starts at 42).
    let out = patch(
        &reg,
        &p,
        &[Edit::Insert {
            at: 42,
            bytes: Bytes::from_static(&[1, 2, 3, 4]),
        }],
        &Scope::all(),
    )
    .unwrap();
    assert_eq!(out.len(), frame.len() + 4);
    check(out, "payload insert");

    // 3. payload delete.
    let out = patch(
        &reg,
        &p,
        &[Edit::Delete {
            at: frame.len() - 2..frame.len(),
        }],
        &Scope::all(),
    )
    .unwrap();
    assert_eq!(out.len(), frame.len() - 2);
    check(out, "payload delete");

    // 4. insert a vlan tag: TCI (vid=100) at offset 14 + eth.type →
    // 0x8100; the dissection grows a vlan layer, everything re-derives.
    let out = patch(
        &reg,
        &p,
        &[
            Edit::Insert {
                at: 14,
                bytes: Bytes::from_static(&[0x00, 0x64]),
            },
            Edit::SetField {
                path: "eth.type".into(),
                bytes: Bytes::from_static(&[0x81, 0x00]),
            },
        ],
        &Scope::all(),
    )
    .unwrap();
    let vlan_dissected = dissect(&reg, &out, "eth");
    assert!(
        vlan_dissected
            .layers
            .iter()
            .any(|l| l.kind == "vlan" && l.fields.get("vid") == Some(&Value::Int(100))),
        "vlan insert: {vlan_dissected:?}"
    );
    check(out, "vlan insert");

    // 5. delete the vlan tag back out: TCI gone + eth.type → 0x0800.
    let out = patch(
        &reg,
        &vlan_dissected,
        &[
            Edit::Delete { at: 14..16 },
            Edit::SetField {
                path: "eth.type".into(),
                bytes: Bytes::from_static(&[0x08, 0x00]),
            },
        ],
        &Scope::all(),
    )
    .unwrap();
    assert_eq!(&out[..], &frame[..], "vlan delete restores the original");
    check(out, "vlan delete");
}
