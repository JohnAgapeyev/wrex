//! Tranche 11b integration gate (`cargo test -- patch_engine`): the
//! span-patch engine over the real registry.
//!
//! 1. **Population gate** — the total-presence invariant: every corpus
//!    frame, every layer, every dissected field key resolves in
//!    `field_spans` (a real span, or `None` by policy); FlagSet
//!    aggregates carry every bit subpath.
//! 2. **Real patches** — L2–L4 stacks: `SetField` (bytes + bit-masked),
//!    `Insert`/`Delete` (shape), the caller-selected consistency scope
//!    (all / outer-only / none), pointed conflicts, and determinism.
//!    Ground truth: re-dissecting the patched frame — scope `all` ⇒
//!    zero anomalies (everything consistent), scope `none` ⇒ the stale
//!    checksums are carried, not healed.
//!
//! Proptest-free (deterministic fixtures); Miri-safe (pure engine).
use std::collections::BTreeMap;

use bytes::Bytes;

use wrex_core::encode::{EncodeOpts, encode};
use wrex_core::patch::{Edit, PatchError, Scope, patch};
use wrex_core::spec::{LayerSpec, PacketSpec};
use wrex_core::value::Value;
use wrex_core::{Registry, dissect};
use wrex_test::corpus::Corpus;

fn registry() -> Registry {
    wrex::standard()
}

fn layer(kind: &'static str, fields: &[(&'static str, Value)]) -> LayerSpec {
    let mut map = BTreeMap::new();
    for (k, v) in fields {
        map.insert(k.to_string(), v.clone());
    }
    LayerSpec::with_fields(kind, map)
}

/// eth + ipv4 + udp + payload, autofilled (valid checksums).
fn udp_frame(reg: &Registry, payload: &[u8]) -> Bytes {
    let spec = PacketSpec::new(
        vec![
            layer(
                "eth",
                &[
                    ("dst", Value::Mac([0xff; 6])),
                    ("src", Value::Mac([0x00; 6])),
                ],
            ),
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

#[test]
fn population_gate_total_presence() {
    let reg = registry();
    let corpora = Corpus::load_all();
    assert!(!corpora.is_empty(), "no corpora found");
    let mut checked = 0usize;
    for corpus in &corpora {
        for frame in &corpus.frames {
            let p = dissect(&reg, &frame.bytes, "auto");
            for l in &p.layers {
                for key in l.fields.keys() {
                    assert!(
                        l.field_spans.contains_key(key),
                        "corpus {}.{}: layer {} field {key:?} has no span entry",
                        corpus.name,
                        frame.name,
                        l.kind
                    );
                }
                // FlagSet aggregates carry every bit subpath — but only
                // where the aggregate itself is spanned (dns `flags`
                // carries None until its tranche-11b slice).
                let Some(codec) = reg.get(l.kind) else {
                    continue;
                };
                for f in codec.schema().fields {
                    if f.kind != wrex_core::FieldKind::FlagSet {
                        continue;
                    }
                    let Some(span) = l.field_spans.get(f.name) else {
                        continue;
                    };
                    if matches!(span, wrex_core::FieldSpan::None) {
                        continue;
                    }
                    for bit in f.bit_names {
                        let path = format!("{}.{bit}", f.name);
                        assert!(
                            l.field_spans.contains_key(&path),
                            "corpus {}.{}: layer {} flag subpath {path:?} missing",
                            corpus.name,
                            frame.name,
                            l.kind
                        );
                    }
                }
            }
            checked += 1;
        }
    }
    assert!(checked > 0, "no corpus frames checked");
}

#[test]
fn set_field_recompute_all_is_consistent() {
    let reg = registry();
    let frame = udp_frame(&reg, &[0xde, 0xad, 0xbe, 0xef]);
    let p = dissect(&reg, &frame, "eth");
    assert!(p.anomalies.is_empty());
    // Patch ipv4.ttl → scope all: everything recomputed.
    let out = patch(
        &reg,
        &p,
        &[Edit::SetField {
            path: "ipv4.ttl".to_string(),
            bytes: Bytes::from_static(&[7]),
        }],
        &Scope::all(),
    )
    .expect("patch");
    // ttl landed (layer-relative offset 8 → absolute 22)
    assert_eq!(out[14 + 8], 7);
    // and the whole frame re-dissects consistently: no anomalies at all.
    let fresh = dissect(&reg, &out, "eth");
    assert!(fresh.anomalies.is_empty(), "{:?}", fresh.anomalies);
}

#[test]
fn set_field_scope_none_preserves_stale_checksum() {
    let reg = registry();
    let frame = udp_frame(&reg, &[0xde, 0xad]);
    let p = dissect(&reg, &frame, "eth");
    // Patch ttl with NO recomputation: the ipv4 checksum goes stale.
    let out = patch(
        &reg,
        &p,
        &[Edit::SetField {
            path: "ipv4.ttl".to_string(),
            bytes: Bytes::from_static(&[7]),
        }],
        &Scope::none(),
    )
    .expect("patch");
    assert_eq!(out[14 + 8], 7);
    let fresh = dissect(&reg, &out, "eth");
    assert!(
        fresh
            .anomalies
            .iter()
            .any(|a| a.path.starts_with("ipv4.checksum")),
        "stale checksum carried: {:?}",
        fresh.anomalies
    );
    // udp checksum covers only the udp segment: still valid.
    assert!(
        !fresh
            .anomalies
            .iter()
            .any(|a| a.path.starts_with("udp.checksum")),
        "{:?}",
        fresh.anomalies
    );
}

#[test]
fn set_field_bits_masked_and_recomputed() {
    let reg = registry();
    let frame = udp_frame(&reg, &[0xde]);
    let p = dissect(&reg, &frame, "eth");
    // ipv4.flags.df is one bit (byte 20, bit 6); 1 byte value.
    let out = patch(
        &reg,
        &p,
        &[Edit::SetField {
            path: "ipv4.flags.df".to_string(),
            bytes: Bytes::from_static(&[1]),
        }],
        &Scope::all(),
    )
    .expect("patch");
    let fresh = dissect(&reg, &out, "eth");
    assert!(fresh.anomalies.is_empty(), "{:?}", fresh.anomalies);
    // df is set on the wire: byte 20 top bits = 0x40.
    assert_eq!(out[14 + 6] & 0x40, 0x40);
    // frag_off (low 13 bits of the same u16) preserved: was 0.
    assert_eq!(out[14 + 6] & 0x3f, 0);
    assert_eq!(out[14 + 7], 0);
}

#[test]
fn insert_recompute_length_and_checksums() {
    let reg = registry();
    let frame = udp_frame(&reg, &[0xde]);
    let p = dissect(&reg, &frame, "eth");
    let old_len = frame.len();
    // Insert 3 bytes into the payload region (after the udp header).
    let out = patch(
        &reg,
        &p,
        &[Edit::Insert {
            at: 14 + 20 + 8,
            bytes: Bytes::from_static(&[1, 2, 3]),
        }],
        &Scope::all(),
    )
    .expect("patch");
    assert_eq!(out.len(), old_len + 3);
    let fresh = dissect(&reg, &out, "eth");
    assert!(fresh.anomalies.is_empty(), "{:?}", fresh.anomalies);
    // total_len and udp.length carry the new size.
    let total = u16::from_be_bytes([out[16], out[17]]) as usize;
    assert_eq!(total, out.len() - 14, "ipv4 total_len recomputed");
    let ulen = u16::from_be_bytes([out[14 + 20 + 4], out[14 + 20 + 5]]) as usize;
    assert_eq!(ulen, out.len() - 14 - 20, "udp length recomputed");
    // ...and NOT under scope none:
    let out2 = patch(
        &reg,
        &p,
        &[Edit::Insert {
            at: 14 + 20 + 8,
            bytes: Bytes::from_static(&[1, 2, 3]),
        }],
        &Scope::none(),
    )
    .expect("patch");
    assert_eq!(&out2[16..18], &frame[16..18], "total_len stays stale");
}

#[test]
fn delete_recomputes_lengths() {
    let reg = registry();
    let frame = udp_frame(&reg, &[0xde, 0xad, 0xbe, 0xef]);
    let p = dissect(&reg, &frame, "eth");
    // Delete 2 payload bytes (tail).
    let out = patch(
        &reg,
        &p,
        &[Edit::Delete {
            at: frame.len() - 2..frame.len(),
        }],
        &Scope::all(),
    )
    .expect("patch");
    assert_eq!(out.len(), frame.len() - 2);
    let fresh = dissect(&reg, &out, "eth");
    assert!(fresh.anomalies.is_empty(), "{:?}", fresh.anomalies);
}

#[test]
fn edit_scope_conflict_and_pointed_errors() {
    let reg = registry();
    let frame = udp_frame(&reg, &[0xde]);
    let p = dissect(&reg, &frame, "eth");
    // Editing a derived field while the scope recomputes it: pointed.
    let err = patch(
        &reg,
        &p,
        &[Edit::SetField {
            path: "udp.checksum".to_string(),
            bytes: Bytes::from_static(&[0, 1]),
        }],
        &Scope::all(),
    )
    .unwrap_err();
    assert!(matches!(err, PatchError::EditScopeConflict(_)), "{err}");
    // outer-only scope leaves udp alone: the edit lands.
    let scope = Scope::select(&["ipv4.*"]).expect("scope");
    let out = patch(
        &reg,
        &p,
        &[Edit::SetField {
            path: "udp.checksum".to_string(),
            bytes: Bytes::from_static(&[0, 1]),
        }],
        &scope,
    )
    .expect("patch");
    assert_eq!(&out[14 + 20 + 6..14 + 20 + 8], &[0, 1]);
    // ipv4 recompute still happened (ttl untouched, but checksum
    // enforced): re-dissect shows exactly the stale udp checksum.
    let fresh = dissect(&reg, &out, "eth");
    assert!(
        fresh
            .anomalies
            .iter()
            .any(|a| a.path.starts_with("udp.checksum")),
        "{:?}",
        fresh.anomalies
    );
    assert!(
        !fresh.anomalies.iter().any(|a| a.path.starts_with("ipv4.")),
        "{:?}",
        fresh.anomalies
    );
    // dns (dynamic layouts until its slice) → UnsupportedPath.
    let corpora = Corpus::load_all();
    let mut dns_done = false;
    for corpus in &corpora {
        for frame in &corpus.frames {
            let q = dissect(&reg, &frame.bytes, "auto");
            if q.layers.iter().any(|l| l.kind == "dns")
                && let Some(l) = q.layers.iter().find(|l| l.kind == "dns")
                && let Some(key) = l.fields.keys().next()
            {
                let path = format!("dns.{key}");
                let err = patch(
                    &reg,
                    &q,
                    &[Edit::SetField {
                        path: path.clone(),
                        bytes: Bytes::new(),
                    }],
                    &Scope::none(),
                )
                .unwrap_err();
                assert!(
                    matches!(err, PatchError::UnsupportedPath(_)),
                    "{path}: {err}"
                );
                dns_done = true;
            }
        }
    }
    assert!(
        dns_done,
        "no dns corpus frame found for the UnsupportedPath gate"
    );
}

#[test]
fn determinism_same_edits_same_bytes() {
    let reg = registry();
    let frame = udp_frame(&reg, &[0xde, 0xad]);
    let p = dissect(&reg, &frame, "eth");
    let edits = vec![Edit::SetField {
        path: "ipv4.ttl".to_string(),
        bytes: Bytes::from_static(&[7]),
    }];
    let a = patch(&reg, &p, &edits, &Scope::all()).expect("patch");
    let b = patch(&reg, &p, &edits, &Scope::all()).expect("patch");
    assert_eq!(a, b);
    // zero edits + scope none: byte-identity (the T11a degenerate).
    let c = patch(&reg, &p, &[], &Scope::none()).expect("patch");
    assert_eq!(&c[..], &frame[..]);
}

#[test]
fn vlan_bits_patch() {
    let reg = registry();
    // eth + vlan + ipv4 + udp (derived vlan.type chain).
    let spec = PacketSpec::new(
        vec![
            layer(
                "eth",
                &[
                    ("dst", Value::Mac([0xff; 6])),
                    ("src", Value::Mac([0x00; 6])),
                ],
            ),
            layer("vlan", &[("vid", Value::Int(100))]),
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
                &[("sport", Value::Int(9999)), ("dport", Value::Int(9999))],
            ),
        ],
        Some(Value::Bytes(Bytes::from_static(&[0xde]))),
    );
    let frame = encode(
        &reg,
        &spec,
        &EncodeOpts {
            autofill: true,
            ..Default::default()
        },
    )
    .expect("encode")
    .bytes;
    let p = dissect(&reg, &frame, "eth");
    assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
    // vid is a 12-bit window in the first TCI u16: patch to 4095.
    let out = patch(
        &reg,
        &p,
        &[Edit::SetField {
            path: "vlan.vid".to_string(),
            // 12-bit value: ceil(12/8) = 2 bytes, BE.
            bytes: Bytes::from_static(&[0x0f, 0xff]),
        }],
        &Scope::all(),
    )
    .expect("patch");
    // vid bits: tci low 12 bits = 0x0fff; pcp/dei untouched (were 0).
    let tci = u16::from_be_bytes([out[14], out[15]]);
    assert_eq!(tci, 0x0fff);
    let fresh = dissect(&reg, &out, "eth");
    assert!(fresh.anomalies.is_empty(), "{:?}", fresh.anomalies);
    // and vid reads back through the real codec:
    let vlan_layer = fresh.layers.iter().find(|l| l.kind == "vlan").unwrap();
    assert_eq!(vlan_layer.fields["vid"], Value::Int(4095));
}
