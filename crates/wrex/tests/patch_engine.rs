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
}

/// A synthetic DNS reply, by construction: one question
/// ("example.com" A IN) and one answer whose name is a **compression
/// pointer** back to offset 12 — the tranche-11b pointer-resolved
/// policy fixture.
fn dns_reply() -> Bytes {
    let mut m = Vec::new();
    m.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    m.extend_from_slice(&0x8180u16.to_be_bytes()); // qr+rd+ra
    m.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    m.extend_from_slice(&1u16.to_be_bytes()); // ancount
    m.extend_from_slice(&0u16.to_be_bytes()); // nscount
    m.extend_from_slice(&0u16.to_be_bytes()); // arcount
    m.extend_from_slice(b"\x07example\x03com\x00"); // question name @12
    m.extend_from_slice(&1u16.to_be_bytes()); // A
    m.extend_from_slice(&1u16.to_be_bytes()); // IN
    m.extend_from_slice(&[0xC0, 0x0C]); // answer name: pointer @12
    m.extend_from_slice(&1u16.to_be_bytes()); // A
    m.extend_from_slice(&1u16.to_be_bytes()); // IN
    m.extend_from_slice(&300u32.to_be_bytes()); // ttl
    m.extend_from_slice(&4u16.to_be_bytes()); // rdlength
    m.extend_from_slice(&[1, 2, 3, 4]); // rdata
    Bytes::from(m)
}

/// Tranche 11b-β: pointer-resolved names carry `FieldSpan::None` —
/// a patch through the pointer is a pointed error, never a silent
/// wrong-target write. The other record fields patch normally.
#[test]
fn dns_pointer_names_are_none_but_record_fields_patch() {
    let reg = registry();
    let frame = dns_reply();
    let p = dissect(&reg, &frame, "dns");
    assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
    let dns = p.layers.iter().find(|l| l.kind == "dns").unwrap();
    assert!(
        matches!(dns.field_spans["an.0.name"], wrex_core::FieldSpan::None),
        "compressed name: {:?}",
        dns.field_spans["an.0.name"]
    );
    assert!(matches!(
        dns.field_spans["an.0.rdata"],
        wrex_core::FieldSpan::Bytes(_)
    ));
    let err = patch(
        &reg,
        &p,
        &[Edit::SetField {
            path: "dns.an.0.name".to_string(),
            bytes: Bytes::new(),
        }],
        &Scope::none(),
    )
    .unwrap_err();
    assert!(matches!(err, PatchError::UnsupportedPath(_)), "{err}");
    // The question name is UNCOMPRESSED: a real span, patchable.
    let out = patch(
        &reg,
        &p,
        &[Edit::SetField {
            path: "dns.qd.0.type".to_string(),
            bytes: Bytes::from_static(&[0x00, 0x0F]), // MX
        }],
        &Scope::none(),
    )
    .expect("patch");
    let fresh = dissect(&reg, &out, "dns");
    let dns = fresh.layers.iter().find(|l| l.kind == "dns").unwrap();
    assert_eq!(dns.fields["qd.0.type"], Value::Str("MX".into()));
    // the answer name still resolves through the pointer (untouched).
    assert_eq!(dns.fields["an.0.name"], Value::Str("example.com".into()));
}

/// The dns flags word is scattered: the aggregate is `None`, every
/// subbit is a real single-bit window — a masked write must not
/// disturb opcode/rcode.
#[test]
fn dns_scattered_flags_subbits_mask() {
    let reg = registry();
    let frame = dns_reply();
    let p = dissect(&reg, &frame, "dns");
    let dns = p.layers.iter().find(|l| l.kind == "dns").unwrap();
    assert!(
        matches!(dns.field_spans["flags"], wrex_core::FieldSpan::None),
        "scattered aggregate: {:?}",
        dns.field_spans["flags"]
    );
    assert!(matches!(
        dns.field_spans["flags.tc"],
        wrex_core::FieldSpan::Bits { .. }
    ));
    let out = patch(
        &reg,
        &p,
        &[Edit::SetField {
            path: "dns.flags.tc".to_string(),
            bytes: Bytes::from_static(&[1]),
        }],
        &Scope::none(),
    )
    .expect("patch");
    // word: 0x8180 (qr+rd+ra) | tc (bit 9, 0x0200) = 0x8380;
    // opcode/rcode untouched.
    assert_eq!(&out[2..4], &[0x83, 0x80]);
    let fresh = dissect(&reg, &out, "dns");
    let dns = fresh.layers.iter().find(|l| l.kind == "dns").unwrap();
    assert_eq!(dns.fields["opcode"], Value::Int(0));
    assert_eq!(dns.fields["rcode"], Value::Int(0));
    let flags = match &dns.fields["flags"] {
        Value::List(names) => names.clone(),
        other => panic!("flags: {other:?}"),
    };
    assert!(flags.contains(&Value::Str("qr".into())));
    assert!(flags.contains(&Value::Str("tc".into())));
}

/// The tranche-11b golden workflow: add a record to a DNS reply with
/// ONE edit set — no spec round-trip. Insert a hand-built A record at
/// the answer-section end + patch `ancount` explicitly (counts are
/// NOT derived targets: the caller decides, scope-all does not
/// conflict), and the fresh dissection stays fully consistent.
#[test]
fn dns_add_a_record_workflow() {
    let reg = registry();
    let frame = dns_reply();
    let p = dissect(&reg, &frame, "dns");
    let dns = p.layers.iter().find(|l| l.kind == "dns").unwrap();
    // Answer-section end = the answer rdata span end.
    let rdata_span = dns
        .field_spans
        .get("an.0.rdata")
        .cloned()
        .expect("rdata span");
    let rdata_end = match rdata_span {
        wrex_core::FieldSpan::Bytes(r) => r.end,
        other => panic!("an.0.rdata span: {other:?}"),
    };
    // A synthetic A record, no pointers: "a.example.com" A IN 300
    // 127.0.0.1 (uncompressed name — self-contained after insert).
    let mut rec = Vec::new();
    rec.extend_from_slice(b"\x01a\x07example\x03com\x00");
    rec.extend_from_slice(&1u16.to_be_bytes());
    rec.extend_from_slice(&1u16.to_be_bytes());
    rec.extend_from_slice(&300u32.to_be_bytes());
    rec.extend_from_slice(&4u16.to_be_bytes());
    rec.extend_from_slice(&[127, 0, 0, 1]);
    let out = patch(
        &reg,
        &p,
        &[
            Edit::Insert {
                at: rdata_end,
                bytes: Bytes::from(rec),
            },
            Edit::SetField {
                path: "dns.ancount".to_string(),
                bytes: Bytes::from_static(&[0x00, 0x02]),
            },
        ],
        &Scope::all(),
    )
    .expect("patch");
    let fresh = dissect(&reg, &out, "dns");
    assert!(fresh.anomalies.is_empty(), "{:?}", fresh.anomalies);
    let dns = fresh.layers.iter().find(|l| l.kind == "dns").unwrap();
    assert_eq!(dns.fields["ancount"], Value::Int(2));
    assert_eq!(dns.fields["an.1.name"], Value::Str("a.example.com".into()));
    assert_eq!(
        dns.fields["an.1.rdata"],
        Value::Ipv4("127.0.0.1".parse().unwrap())
    );
    // the original pointer-compressed answer still resolves.
    assert_eq!(dns.fields["an.0.name"], Value::Str("example.com".into()));
}

/// Tranche 11b-β dhcp: options/hoisted/ReEncode policies on the
/// corpus goldens (DISCOVER/OFFER/… frames).
#[test]
fn dhcp_option_and_hoisted_spans() {
    let reg = registry();
    let mut found = false;
    'outer: for corpus in Corpus::load_all() {
        for frame in &corpus.frames {
            let p = dissect(&reg, &frame.bytes, "auto");
            let Some(l) = p.layers.iter().find(|l| l.kind == "dhcp") else {
                continue;
            };
            if p.anomalies
                .iter()
                .any(|a| a.path.starts_with("dhcp.cookie"))
            {
                continue; // BOOTP legacy frame: no options region
            }
            // msg_type is the hoisted option-53 source: patching it
            // writes the TLV value byte.
            let mt_span = l
                .field_spans
                .get("msg_type")
                .cloned()
                .expect("msg_type span");
            let wrex_core::FieldSpan::Bytes(mt) = mt_span else {
                panic!("msg_type span: {mt_span:?}")
            };
            assert_eq!(mt.len(), 1, "option 53 carries one byte");
            let out = patch(
                &reg,
                &p,
                &[Edit::SetField {
                    path: "dhcp.msg_type".to_string(),
                    bytes: Bytes::from_static(&[8]), // INFORM
                }],
                &Scope::none(),
            )
            .expect("patch");
            let fresh = dissect(&reg, &out, "auto");
            let l2 = fresh.layers.iter().find(|l| l.kind == "dhcp").unwrap();
            assert_eq!(l2.fields["msg_type"], Value::Str("inform".into()));
            // sname/file are ReEncode: recorded, pointed-deferral.
            let err = patch(
                &reg,
                &p,
                &[Edit::SetField {
                    path: "dhcp.sname".to_string(),
                    bytes: Bytes::from_static(&[0x41; 64]),
                }],
                &Scope::none(),
            )
            .unwrap_err();
            assert!(matches!(err, PatchError::UnsupportedPath(_)), "{err}");
            assert!(matches!(
                l.field_spans["sname"],
                wrex_core::FieldSpan::ReEncode(_)
            ));
            // one same-width option value patch: byte-verified.
            let value_span = l
                .field_spans
                .get("opt.0.value")
                .cloned()
                .expect("value span");
            let wrex_core::FieldSpan::Bytes(v) = value_span else {
                panic!("opt.0.value span: {value_span:?}")
            };
            let out2 = patch(
                &reg,
                &p,
                &[Edit::SetField {
                    path: "dhcp.opt.0.value".to_string(),
                    bytes: Bytes::from(vec![0xA5; v.len()]),
                }],
                &Scope::none(),
            )
            .expect("patch");
            assert_eq!(&out2[v.start..v.end], &vec![0xA5; v.len()][..]);
            found = true;
            break 'outer;
        }
    }
    assert!(found, "no dhcp corpus frame with options found");
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
