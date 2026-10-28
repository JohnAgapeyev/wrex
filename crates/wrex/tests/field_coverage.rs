//! HP3-a field-coverage gates (`cargo test -- field_coverage`): the
//! schema as the completion oracle, over the real registry.
//!
//! - **G1** `g1_strategy_completeness`: every settable schema field
//!   appears in its codec's strategy output with a randomized value —
//!   the gate that would have caught the ipv4 mf bug at its first run
//!   (the strategy never sampled `flags`, so every compared frame had
//!   all flag bits zero and a bit-*position* error was invisible).
//! - **G2** `g2_bit_toggle_sweep_feeds_the_differential`: every
//!   FlagSet aggregate, every named bit — a frame with exactly that
//!   bit set must render it, place it where the span map says, and
//!   pass both stack oracles. *Differential coverage = schema
//!   coverage* for the flag surface.
//! - **G6** `g6_differential_key_completeness`: every scalar schema
//!   field of a compared codec appears in at least one oracle map's
//!   attempted-comparison inventory, unless exempted with a recorded
//!   reason — a silently un-compared field is a field whose mapping
//!   bugs are invisible (the mf-bug lesson applied to the maps).
//!
//! Exemptions are recorded in
//! [`wrex_test::gates::STRATEGY_EXEMPT`](wrex_test::gates::STRATEGY_EXEMPT)
//! (with reasons) plus the by-construction sets (`Codec::derived`
//! names, dissect-only record sections); a failure here is a pointed
//! `kind.field` list, never a blanket skip.

use std::collections::BTreeMap;

use wrex_core::FieldSpan;
use wrex_core::encode::{EncodeOpts, encode};
use wrex_core::spec::{LayerSpec, PacketSpec};
use wrex_core::value::Value;
use wrex_test::gates::audit_strategy;
use wrex_test::oracle::{EtherparseOracle, Oracle, TsharkOracle};

fn registry() -> wrex_core::Registry {
    wrex::standard()
}

/// Layer-spec shorthand for the fixtures below.
fn layer(kind: &'static str, fields: &[(&'static str, Value)]) -> LayerSpec {
    let mut map = BTreeMap::new();
    for (k, v) in fields {
        map.insert(k.to_string(), v.clone());
    }
    LayerSpec::with_fields(kind, map)
}

fn int(v: u64) -> Value {
    Value::Int(v as u128)
}

fn spec(layers: Vec<LayerSpec>) -> PacketSpec {
    PacketSpec::new(layers, None)
}

fn encode_af(reg: &wrex_core::Registry, p: &PacketSpec) -> Vec<u8> {
    encode(
        reg,
        p,
        &EncodeOpts {
            autofill: true,
            ..Default::default()
        },
    )
    .expect("encode")
    .bytes
    .to_vec()
}

/// G1: strategy completeness audit, retroactive over every codec with
/// a strategy in the standard registry.
#[test]
fn g1_strategy_completeness() {
    let reg = registry();
    let mut dirty = String::new();
    let mut audited = 0;
    for kind in reg.kinds() {
        // The audit returns None for strategy-less kinds (nothing to
        // audit — none exist in the standard registry today).
        if let Some(audit) = audit_strategy(&reg, kind, 512, 2) {
            audited += 1;
            if !audit.is_clean() {
                dirty.push_str(&audit.message());
            }
        }
    }
    assert!(
        audited >= 19,
        "expected every standard codec audited, got {audited}"
    );
    assert!(dirty.is_empty(), "G1 strategy-completeness audit:\n{dirty}");
}

// ---------------------------------------------------------------------------
// G2 — bit-toggle sweep feeding the differential
// ---------------------------------------------------------------------------

/// One FlagSet sweep fixture: a stack carrying the aggregate's layer,
/// with deterministic field values so the foreign oracles render their
/// conditionally-present fields too.
fn flag_fixture(kind: &str, flag_field: &str) -> PacketSpec {
    match (kind, flag_field) {
        ("tcp", _) => spec(vec![
            layer("eth", &[]),
            layer(
                "ipv4",
                &[("tos", int(0x10)), ("id", int(0x1234)), ("ttl", int(63))],
            ),
            layer(
                "tcp",
                &[
                    ("sport", int(4444)),
                    ("dport", int(80)),
                    ("seq", int(0xdeadbeef)),
                    ("ack", int(0xfeedface)),
                    ("window", int(0x2000)),
                    ("urgent", int(0)),
                ],
            ),
        ]),
        ("ipv4", _) => spec(vec![
            layer("eth", &[]),
            layer(
                "ipv4",
                &[("tos", int(0x10)), ("id", int(0x1234)), ("ttl", int(63))],
            ),
            layer("udp", &[("sport", int(4444)), ("dport", int(53))]),
        ]),
        ("dns", _) => spec(vec![
            layer("eth", &[]),
            layer("ipv4", &[("ttl", int(63))]),
            layer("udp", &[("sport", int(5353)), ("dport", int(53))]),
            layer(
                "dns",
                &[
                    ("id", int(0x4242)),
                    ("opcode", int(0)),
                    ("rcode", int(0)),
                    ("qd.0.name", Value::Str("example.com".into())),
                    ("qd.0.type", Value::Str("A".into())),
                    ("qd.0.class", Value::Str("IN".into())),
                ],
            ),
        ]),
        ("dhcp", _) => spec(vec![
            layer("eth", &[]),
            layer("ipv4", &[("ttl", int(63))]),
            layer("udp", &[("sport", int(68)), ("dport", int(67))]),
            layer(
                "dhcp",
                &[
                    ("op", int(1)),
                    ("htype", int(1)),
                    ("hlen", int(6)),
                    ("hops", int(1)),
                    ("xid", int(0x11223344)),
                    ("secs", int(7)),
                    ("msg_type", Value::Str("discover".into())),
                ],
            ),
        ]),
        ("icmpv6", "ndp.ra_flags") => spec(vec![
            layer("eth", &[]),
            layer("ipv6", &[("hop_limit", int(64))]),
            layer(
                "icmpv6",
                &[
                    ("type", int(134)),
                    ("code", int(0)),
                    ("ndp.cur_hop_limit", int(64)),
                    ("ndp.router_lifetime", int(1800)),
                ],
            ),
        ]),
        ("icmpv6", "ndp.na_flags") => spec(vec![
            layer("eth", &[]),
            layer("ipv6", &[("hop_limit", int(64))]),
            layer(
                "icmpv6",
                &[
                    ("type", int(136)),
                    ("code", int(0)),
                    (
                        "ndp.target",
                        Value::Ipv6("fe80::1".parse::<std::net::Ipv6Addr>().unwrap()),
                    ),
                ],
            ),
        ]),
        ("icmpv6", "mld.flags") => spec(vec![
            layer("eth", &[]),
            layer("ipv6", &[("hop_limit", int(1))]),
            layer(
                "icmpv6",
                &[
                    ("type", int(130)),
                    ("code", int(10)),
                    (
                        "mld.addr",
                        Value::Ipv6("ff02::1".parse::<std::net::Ipv6Addr>().unwrap()),
                    ),
                    ("mld.qrv", int(2)),
                    ("mld.qqic", int(125)),
                ],
            ),
        ]),
        other => unreachable!("no flag fixture for {other:?}"),
    }
}

/// FlagSet aggregates whose span is None-by-policy (no static layout —
/// the conditional MLDv2 body's position depends on the v1/v2 shape
/// discrimination; patching them is the pointed UnsupportedPath, and
/// the wire position is pinned deterministically by the G3 KAV table
/// instead of the span map).
const SPAN_EXEMPT: &[(&str, &str)] = &[("icmpv6", "mld.flags")];

/// Read a `FieldSpan::Bits` window out of the frame (the patch engine's
/// masked-write arithmetic walked in the read direction).
fn read_window(frame: &[u8], span: &FieldSpan) -> Option<u128> {
    let FieldSpan::Bits {
        container,
        shift,
        width,
    } = span
    else {
        return None;
    };
    let c = frame.get(container.start..container.end)?;
    let mut acc = 0u128;
    for b in c {
        acc = (acc << 8) | *b as u128;
    }
    let bits = c.len() * 8;
    Some((acc >> (bits - *shift as usize - *width as usize)) & ((1u128 << *width) - 1))
}

/// G2: for every FlagSet aggregate and named bit in the registry,
/// craft a frame with exactly that bit set, assert (a) the
/// dissection renders exactly that bit name, (b) the span map places
/// the bit where the wire bytes say it is (the window reads the
/// toggle), and (c) both stack oracles agree on the frame — the
/// toggle frames feed the differential, so *differential coverage =
/// schema coverage* for the flag surface.
#[test]
fn g2_bit_toggle_sweep_feeds_the_differential() {
    let reg = registry();
    let ep = EtherparseOracle;
    let ts = TsharkOracle;
    let tshark_live = ts.is_available();
    for (kind, field) in [
        ("tcp", "flags"),
        ("ipv4", "flags"),
        ("dns", "flags"),
        ("dhcp", "flags"),
        ("icmpv6", "ndp.ra_flags"),
        ("icmpv6", "ndp.na_flags"),
        ("icmpv6", "mld.flags"),
    ] {
        let base = flag_fixture(kind, field);
        let schema_field = registry()
            .schema(kind)
            .and_then(|s| s.field(field))
            .expect("flag field");
        for bit in schema_field.bit_names {
            let pos = schema_field.bit_pos(bit).expect("named bit");
            // Toggle ON: the mask carries exactly this bit.
            let mut toggled = base.clone();
            for l in toggled.layers.iter_mut() {
                if l.kind == kind {
                    l.fields.insert(field.to_string(), int(1 << pos));
                }
            }
            let bytes = encode_af(&reg, &toggled);
            let packet = wrex_core::dissect::dissect(&reg, &bytes, "auto");
            assert!(
                packet.anomalies.is_empty(),
                "{kind}.{field}.{bit}: anomalies {:?}",
                packet.anomalies
            );
            let l = packet
                .layers
                .iter()
                .find(|l| l.kind == kind)
                .expect("layer present");
            // (a) the rendered names are exactly [bit].
            let names: Vec<String> = match l.fields.get(field) {
                Some(Value::List(items)) => items
                    .iter()
                    .filter_map(|v| match v {
                        Value::Str(s) => Some(s.to_string()),
                        _ => None,
                    })
                    .collect(),
                other => panic!("{kind}.{field}.{bit}: not a name list: {other:?}"),
            };
            assert_eq!(
                names,
                vec![bit.to_string()],
                "{kind}.{field}.{bit}: rendered {names:?}"
            );
            // (b) the span map places the bit: the aggregate window
            //     (a byte-aligned aggregate, a bit window, or — for
            //     scattered aggregates — the per-bit window) reads
            //     exactly the toggle out of the wire bytes.
            match l.field_spans.get(field) {
                Some(FieldSpan::Bits { .. }) => {
                    let v = read_window(&bytes, &l.field_spans[field]).expect("window in frame");
                    assert_eq!(
                        v,
                        1u128 << pos,
                        "{kind}.{field}.{bit}: aggregate window reads {v:#x}"
                    );
                }
                Some(FieldSpan::Bytes(r)) => {
                    // Byte-aligned aggregate (tcp.flags is the whole
                    // flags byte): the BE value IS the mask.
                    let v = bytes
                        .get(r.start..r.end)
                        .map(|c| c.iter().fold(0u128, |a, b| (a << 8) | *b as u128))
                        .expect("span bytes in frame");
                    assert_eq!(
                        v,
                        1u128 << pos,
                        "{kind}.{field}.{bit}: aggregate bytes read {v:#x}"
                    );
                }
                Some(FieldSpan::None) => {
                    if let Some(sub) = l.field_spans.get(&format!("{field}.{bit}")) {
                        let v = read_window(&bytes, sub).expect("sub window in frame");
                        assert_eq!(v, 1, "{kind}.{field}.{bit}: sub-bit window reads {v}");
                    } else {
                        assert!(
                            SPAN_EXEMPT.contains(&(kind, field)),
                            "{kind}.{field}.{bit}: None-span aggregate without a sub-bit span \
                             and without a recorded exemption"
                        );
                    }
                }
                other => panic!("{kind}.{field}.{bit}: unexpected span {other:?}"),
            }
            // (c) both oracles agree on the toggle frame.
            assert!(
                ep.dissect_diff(&bytes, &packet).is_ok(),
                "{kind}.{field}.{bit}: etherparse disagrees"
            );
            if tshark_live {
                assert!(
                    ts.dissect_diff(&bytes, &packet).is_ok(),
                    "{kind}.{field}.{bit}: tshark disagrees"
                );
            }
            // Toggle OFF (all bits clear) for the two-state sweep: the
            // window reads zero and the oracles still agree.
            let mut cleared = base.clone();
            for l in cleared.layers.iter_mut() {
                if l.kind == kind {
                    l.fields.insert(field.to_string(), int(0));
                }
            }
            let bytes = encode_af(&reg, &cleared);
            let packet = wrex_core::dissect::dissect(&reg, &bytes, "auto");
            assert!(
                ep.dissect_diff(&bytes, &packet).is_ok(),
                "{kind}.{field}.{bit}: etherparse disagrees (clear)"
            );
            if tshark_live {
                assert!(
                    ts.dissect_diff(&bytes, &packet).is_ok(),
                    "{kind}.{field}.{bit}: tshark disagrees (clear)"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// G6 — differential key-completeness audit
// ---------------------------------------------------------------------------

/// Kinds carried by their OWN dedicated oracle differentials, not the
/// stack maps (recorded reasons; the audit skips their scalar fields).
const G6_KIND_EXEMPT: &[(&str, &str)] = &[
    (
        "dns",
        "carried by the dedicated hickory/dig differentials (the T3/T20 design); \
         the stack maps have no dns arm",
    ),
    (
        "dhcp",
        "options carried by the in-process dhcproto oracle (the T7c design); \
         the fixed header IS compared by the tshark map",
    ),
    (
        "dhcp6",
        "options carried by the in-process dhcproto v6 oracle (the T17c design); \
         the fixed header IS compared by the tshark map",
    ),
];

/// Scalar schema fields with NO oracle arm (recorded reasons — a
/// silently un-compared field is a field whose mapping bugs are
/// invisible; these are the consciously-decided holes).
const G6_FIELD_EXEMPT: &[(&str, &str, &str)] = &[
    // raw regions: the foreign oracles render typed trees, not blobs.
    (
        "ipv4",
        "options",
        "raw region — etherparse/tshark render typed option trees; the T22 \
         read-side typing lands the record sections",
    ),
    ("tcp", "options", "raw region — same as ipv4.options (T22)"),
    (
        "icmp",
        "rest",
        "raw 4-byte region — tshark renders the typed per-type body instead",
    ),
    (
        "icmpv6",
        "rest",
        "raw 4-byte region — the generic-type body, no oracle arm",
    ),
    (
        "icmpv6",
        "options",
        "NDP option TLVs — tshark renders the typed option tree (icmpv6.opt \
         keys); the T17b corpus goldens carry them",
    ),
    (
        "icmpv6",
        "mld",
        "the 143 record grammar — rendered by tshark as typed mldv2 records; \
         the T17b corpus goldens carry them",
    ),
    // fixed geometry pinned by the G3 KAV tables (the G1 twins).
    (
        "arp",
        "htype",
        "tshark renders arp.hw.type as a NAME (\"Ethernet (0x0001)\") — no \
         stable numeric key; the G3 KAV table pins the position",
    ),
    (
        "arp",
        "ptype",
        "same rendering caveat as htype (arp.proto.type)",
    ),
    ("arp", "hlen", "descriptive geometry — G3 KAV table"),
    ("arp", "plen", "descriptive geometry — G3 KAV table"),
];

/// NDP/MLD body fields with no etherparse/tshark scalar arms (one
/// blanket reason, listed per field so the audit names each): the
/// icmpv6 conditional bodies are ours alone — the corpus goldens,
/// in-crate units and the G2/G3 sweeps carry them.
const G6_ICMPV6_BODY_EXEMPT: &[&str] = &[
    "ndp.cur_hop_limit",
    "ndp.ra_flags",
    "ndp.router_lifetime",
    "ndp.reachable_time",
    "ndp.retrans_timer",
    "ndp.na_flags",
    "ndp.target",
    "mld.addr",
    "mld.flags",
    "mld.qrv",
    "mld.qqic",
    "mld.nsrcs",
    "mld.sources",
];

/// One maximal-stack audit fixture per compared kind (deterministic
/// nonzero values so conditionally-rendered oracle fields appear).
fn g6_fixtures() -> Vec<(&'static str, PacketSpec)> {
    let eth = || layer("eth", &[]);
    let ip4 = || {
        layer(
            "ipv4",
            &[
                ("tos", int(0x10)),
                ("id", int(0x1234)),
                ("ttl", int(63)),
                ("frag_off", int(0)),
            ],
        )
    };
    let ip6 = || {
        layer(
            "ipv6",
            &[
                ("traffic_class", int(0x20)),
                ("flow_label", int(0x05151)),
                ("hop_limit", int(64)),
            ],
        )
    };
    let udp = |s: u64, d: u64| layer("udp", &[("sport", int(s)), ("dport", int(d))]);
    vec![
        ("eth", spec(vec![eth(), ip4(), udp(4444, 53)])),
        (
            "vlan",
            spec(vec![
                eth(),
                layer(
                    "vlan",
                    &[("pcp", int(3)), ("dei", int(1)), ("vid", int(100))],
                ),
                ip4(),
                udp(4444, 53),
            ]),
        ),
        (
            "arp",
            spec(vec![
                eth(),
                layer(
                    "arp",
                    &[
                        ("oper", int(2)),
                        ("sha", Value::Mac([0xaa, 1, 2, 3, 4, 5])),
                        (
                            "spa",
                            Value::Ipv4("192.0.2.10".parse::<std::net::Ipv4Addr>().unwrap()),
                        ),
                        ("tha", Value::Mac([0xbb, 6, 7, 8, 9, 10])),
                        (
                            "tpa",
                            Value::Ipv4("192.0.2.20".parse::<std::net::Ipv4Addr>().unwrap()),
                        ),
                    ],
                ),
            ]),
        ),
        ("ipv4", spec(vec![eth(), ip4(), udp(4444, 53)])),
        ("ipv6", spec(vec![eth(), ip6(), udp(4444, 53)])),
        (
            "icmp",
            spec(vec![
                eth(),
                ip4(),
                layer(
                    "icmp",
                    &[
                        ("type", int(8)),
                        ("code", int(0)),
                        ("echo.id", int(0x5151)),
                        ("echo.seq", int(7)),
                    ],
                ),
            ]),
        ),
        (
            "icmpv6",
            spec(vec![
                eth(),
                ip6(),
                layer(
                    "icmpv6",
                    &[
                        ("type", int(128)),
                        ("code", int(0)),
                        ("echo.id", int(0x5151)),
                        ("echo.seq", int(7)),
                    ],
                ),
            ]),
        ),
        ("udp", spec(vec![eth(), ip4(), udp(4444, 53)])),
        (
            "tcp",
            spec(vec![
                eth(),
                ip4(),
                layer(
                    "tcp",
                    &[
                        ("sport", int(4444)),
                        ("dport", int(80)),
                        ("seq", int(0xdeadbeef)),
                        ("ack", int(0xfeedface)),
                        ("window", int(0x2000)),
                    ],
                ),
            ]),
        ),
        (
            "hopopts",
            spec(vec![
                eth(),
                ip6(),
                layer(
                    "hopopts",
                    &[(
                        "options",
                        Value::Bytes(bytes::Bytes::from_static(&[1, 4, 0, 0, 0, 0])),
                    )],
                ),
                udp(4444, 53),
            ]),
        ),
        (
            "dstopts",
            spec(vec![
                eth(),
                ip6(),
                layer(
                    "dstopts",
                    &[(
                        "options",
                        Value::Bytes(bytes::Bytes::from_static(&[1, 4, 0, 0, 0, 0])),
                    )],
                ),
                udp(4444, 53),
            ]),
        ),
        (
            "routing",
            spec(vec![
                eth(),
                ip6(),
                layer(
                    "routing",
                    &[
                        ("type", int(0)),
                        ("segs_left", int(1)),
                        (
                            "segments",
                            Value::Bytes(bytes::Bytes::from_static(&[
                                0, 0, 0, 0, 0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                            ])),
                        ),
                    ],
                ),
                udp(4444, 53),
            ]),
        ),
        (
            "frag",
            spec(vec![
                eth(),
                ip6(),
                layer(
                    "frag",
                    &[("offset", int(0)), ("m", int(0)), ("ident", int(0x5151))],
                ),
                udp(4444, 53),
            ]),
        ),
        (
            "ah",
            spec(vec![
                eth(),
                ip6(),
                layer(
                    "ah",
                    &[
                        // RFC 4302 §2.2: header = (len + 2) * 4 bytes —
                        // len 4 → 24: 12 fixed + a 12-byte ICV.
                        ("len", int(4)),
                        ("spi", int(0x1234)),
                        ("seq", int(0x5678)),
                        ("icv", Value::Bytes(bytes::Bytes::from_static(&[9; 12]))),
                    ],
                ),
                udp(4444, 53),
            ]),
        ),
        (
            "dns",
            spec(vec![
                eth(),
                ip4(),
                udp(5353, 53),
                layer(
                    "dns",
                    &[
                        ("id", int(0x4242)),
                        ("opcode", int(0)),
                        ("rcode", int(0)),
                        ("qd.0.name", Value::Str("example.com".into())),
                        ("qd.0.type", Value::Str("A".into())),
                        ("qd.0.class", Value::Str("IN".into())),
                    ],
                ),
            ]),
        ),
        (
            "dhcp",
            spec(vec![
                eth(),
                ip4(),
                udp(68, 67),
                layer(
                    "dhcp",
                    &[
                        ("op", int(1)),
                        ("htype", int(1)),
                        ("hlen", int(6)),
                        ("hops", int(1)),
                        ("xid", int(0x11223344)),
                        ("secs", int(7)),
                        ("msg_type", Value::Str("discover".into())),
                    ],
                ),
            ]),
        ),
        (
            "dhcp6",
            spec(vec![
                eth(),
                ip6(),
                udp(546, 547),
                layer(
                    "dhcp6",
                    &[
                        ("msg_type", Value::Str("solicit".into())),
                        ("trans_id", int(0x424242)),
                    ],
                ),
            ]),
        ),
    ]
}

/// G6: every scalar schema field of every compared codec appears in at
/// least one oracle map's attempted-comparison inventory (the
/// `compared` paths of a `compare()` run over a maximal fixture frame),
/// unless consciously exempted with a recorded reason. The exemption
/// table is itself audited: every entry must name a real schema
/// field, and every fixture frame must pass both oracles cleanly (the
/// audit doubles as the maximal-frame differential sweep).
#[test]
fn g6_differential_key_completeness() {
    let reg = registry();
    let ep = EtherparseOracle;
    let ts = TsharkOracle;
    let tshark_live = ts.is_available();
    let mut missing = String::new();
    let mut stale_exemptions = Vec::new();
    for (kind, spec) in g6_fixtures() {
        let bytes = encode_af(&reg, &spec);
        let packet = wrex_core::dissect::dissect(&reg, &bytes, "auto");
        assert!(
            packet.anomalies.is_empty(),
            "{kind} fixture: anomalies {:?}",
            packet.anomalies
        );
        // The fixture frames pass both oracles (maximal-frame sweep).
        assert!(
            ep.dissect_diff(&bytes, &packet).is_ok(),
            "{kind} fixture: etherparse disagrees"
        );
        let mut compared: Vec<String> = ep.compare(&bytes, &packet).compared;
        if tshark_live {
            assert!(
                ts.dissect_diff(&bytes, &packet).is_ok(),
                "{kind} fixture: tshark disagrees"
            );
            if let Some(report) = ts.compare(&bytes, &packet) {
                compared.extend(report.compared);
            }
        }
        // Key completeness: every scalar schema field of this kind is
        // in the attempted set, exempted per-field, or the kind rides a
        // dedicated oracle.
        let kind_exempt = G6_KIND_EXEMPT.iter().any(|(k, _)| *k == kind);
        for f in reg.schema(kind).expect("fixture kind in registry").fields {
            if matches!(f.kind, wrex_core::schema::FieldKind::FlagSet)
                || f.kind == wrex_core::schema::FieldKind::Bytes
            {
                // FlagSet aggregates ride the G2 sweep; raw Bytes
                // regions are compared-or-exempted below like scalars.
            }
            let path = format!("{kind}.{}", f.name);
            if compared.contains(&path) {
                continue;
            }
            if kind_exempt {
                continue;
            }
            if G6_FIELD_EXEMPT
                .iter()
                .any(|(k, field, _)| *k == kind && *field == f.name)
            {
                continue;
            }
            if kind == "icmpv6" && G6_ICMPV6_BODY_EXEMPT.contains(&f.name) {
                continue;
            }
            missing.push_str(&format!("{path}: never compared by any oracle map\n"));
        }
    }
    // The exemption tables name real fields (stale entries fail).
    for (k, field, _) in G6_FIELD_EXEMPT {
        if reg.schema(k).and_then(|s| s.field(field)).is_none() {
            stale_exemptions.push(format!("{k}.{field}"));
        }
    }
    for field in G6_ICMPV6_BODY_EXEMPT {
        if reg.schema("icmpv6").and_then(|s| s.field(field)).is_none() {
            stale_exemptions.push(format!("icmpv6.{field}"));
        }
    }
    assert!(
        stale_exemptions.is_empty(),
        "stale G6 exemptions (schema field gone): {stale_exemptions:?}"
    );
    assert!(
        missing.is_empty(),
        "G6 differential key-completeness audit:\n{missing}"
    );
}

// ---------------------------------------------------------------------------
// G3 — RFC position vectors (KAV): wire bytes/positions for every bit
// aggregate, asserted against hand-computed RFC-derived tables — never
// the schema's own declarations (they share the bug surface).
// ---------------------------------------------------------------------------

/// Byte-slice assert against the crafted frame.
fn assert_bytes(name: &str, frame: &[u8], at: usize, want: &[u8]) {
    let got = frame
        .get(at..at + want.len())
        .unwrap_or_else(|| panic!("{name}: frame too short for offset {at}"));
    assert_eq!(got, want, "{name}: offset {at}");
}

/// Craft `layers` with autofill and return the frame.
fn craft(layers: Vec<LayerSpec>) -> Vec<u8> {
    let reg = registry();
    encode_af(&reg, &spec(layers))
}

/// The bit-aggregate KAV table. Every row cites the RFC section and
/// pins the EXACT wire bytes at hand-computed absolute offsets (eth is
/// 14 bytes; ipv4 without options 20; ipv6 40; udp 8 — the fixture
/// stacks are option-free so the offsets are deterministic).
#[test]
fn g3_rfc_position_vectors_bit_aggregates() {
    let eth = || layer("eth", &[]);
    let ip4 = || {
        layer(
            "ipv4",
            &[("tos", int(0x10)), ("id", int(0x1234)), ("ttl", int(64))],
        )
    };
    let ip6 = || layer("ipv6", &[("hop_limit", int(64))]);

    // --- ipv4: RFC 791 §3.1 — ver/ihl nibbles (byte 0), tos (byte 1),
    //     flags [res=bit15, df=bit14, mf=bit13] + frag_off (word 3).
    //     The 0x8000 reserved-bit row is the mf-bug's own pin: the
    //     T18a repair wrote mf there until the HP3-a sweep caught it.
    {
        let mut l = ip4();
        l.fields.insert("flags".into(), int(0b100)); // res (bit_names[0] → mask bit 2)
        l.fields.insert("frag_off".into(), int(1));
        let f = craft(vec![
            eth(),
            l,
            layer("udp", &[("sport", int(9)), ("dport", int(9))]),
        ]);
        assert_bytes("ipv4.ver/ihl", &f, 14, &[0x45]);
        assert_bytes("ipv4.tos", &f, 15, &[0x10]);
        assert_bytes("ipv4.flags res + frag_off 1", &f, 20, &[0x80, 0x01]);
    }
    {
        let mut l = ip4();
        l.fields.insert("flags".into(), int(0b011)); // mf|df (mask bits 0,1)
        let f = craft(vec![
            eth(),
            l,
            layer("udp", &[("sport", int(9)), ("dport", int(9))]),
        ]);
        assert_bytes("ipv4.flags mf|df", &f, 20, &[0x60, 0x00]);
    }

    // --- tcp: RFC 9293 §3.1 — data offset (byte 12 nibble), flags
    //     byte 13 [cwr..fin] MSB-first.
    {
        let mut l = layer(
            "tcp",
            &[
                ("sport", int(1234)),
                ("dport", int(80)),
                ("seq", int(1)),
                ("window", int(8192)),
            ],
        );
        l.fields.insert("flags".into(), int(0b00010010)); // syn|ack
        let f = craft(vec![eth(), ip4(), l]);
        assert_bytes("tcp.data_off", &f, 34 + 12, &[0x50]);
        assert_bytes("tcp.flags syn|ack", &f, 34 + 13, &[0x12]);
    }

    // --- vlan: IEEE 802.1Q — TCI = pcp<<13 | dei<<12 | vid (bytes
    //     14-15), ethertype 0x8100 (the craft-side T7a rule).
    {
        let f = craft(vec![
            eth(),
            layer(
                "vlan",
                &[("pcp", int(3)), ("dei", int(1)), ("vid", int(0x064))],
            ),
            ip4(),
            layer("udp", &[("sport", int(9)), ("dport", int(9))]),
        ]);
        assert_bytes("vlan.ethertype", &f, 12, &[0x81, 0x00]);
        assert_bytes("vlan TCI pcp3|dei|vid100", &f, 14, &[0x70, 0x64]);
    }

    // --- ipv6: RFC 8200 §3 — the flow word: ver (4 bits) | traffic
    //     class (8) | flow label (20), bytes 14-17 BE.
    {
        let mut l = ip6();
        l.fields.insert("traffic_class".into(), int(0x20));
        l.fields.insert("flow_label".into(), int(0x05151));
        let f = craft(vec![
            eth(),
            l,
            layer("udp", &[("sport", int(9)), ("dport", int(9))]),
        ]);
        assert_bytes("ipv6 flow word", &f, 14, &[0x62, 0x00, 0x51, 0x51]);
    }

    // --- frag (v6): RFC 8200 §4.5 — the 16-bit field is
    //     offset(13 bits)<<3 | M(bit 0) at frag+2.
    {
        let f = craft(vec![
            eth(),
            ip6(),
            layer(
                "frag",
                &[("offset", int(1)), ("m", int(1)), ("ident", int(1))],
            ),
            layer("udp", &[("sport", int(9)), ("dport", int(9))]),
        ]);
        assert_bytes("frag offset1|M", &f, 54 + 2, &[0x00, 0x09]);
    }

    // --- hopopts: RFC 8200 §4.3 — len counts 8-octet units minus one
    //     (byte 1 of the header).
    {
        let f = craft(vec![
            eth(),
            ip6(),
            layer(
                "hopopts",
                &[(
                    "options",
                    Value::Bytes(bytes::Bytes::from_static(&[1, 4, 0, 0, 0, 0])),
                )],
            ),
            layer("udp", &[("sport", int(9)), ("dport", int(9))]),
        ]);
        assert_bytes("hopopts len (8 octets)", &f, 54 + 1, &[0x00]);
    }

    // --- icmpv6 NDP: RFC 4861 §4.4 — NA flags [r,s,o] = byte 4 bits
    //     7/6/5; §4.2 — RA flags [m,o] = byte 5 bits 7/6.
    {
        let mut l = layer(
            "icmpv6",
            &[
                ("type", int(136)),
                ("code", int(0)),
                ("ndp.target", Value::Ipv6("fe80::1".parse().unwrap())),
            ],
        );
        l.fields.insert("ndp.na_flags".into(), int(0b111)); // r|s|o
        let f = craft(vec![eth(), ip6(), l]);
        assert_bytes("icmpv6.na_flags r|s|o", &f, 54 + 4, &[0xE0]);
    }
    {
        let mut l = layer(
            "icmpv6",
            &[
                ("type", int(134)),
                ("code", int(0)),
                ("ndp.cur_hop_limit", int(64)),
            ],
        );
        l.fields.insert("ndp.ra_flags".into(), int(0b11)); // m|o
        let f = craft(vec![eth(), ip6(), l]);
        assert_bytes("icmpv6.ra_flags m|o", &f, 54 + 5, &[0xC0]);
    }

    // --- icmpv6 MLDv2 query: RFC 3810 §5.1 — after the 16-byte
    //     multicast address, the flags/QRV byte: S = bit 3 (0x08),
    //     QRV = bits 2-0. icmpv6 header (8) + addr (16) → byte 24.
    {
        let mut l = layer(
            "icmpv6",
            &[
                ("type", int(130)),
                ("code", int(10)),
                ("mld.addr", Value::Ipv6("ff02::1".parse().unwrap())),
                ("mld.qrv", int(2)),
            ],
        );
        l.fields.insert("mld.flags".into(), int(0b1)); // s
        let f = craft(vec![eth(), ip6(), l]);
        assert_bytes("icmpv6 mld.flags s + qrv 2", &f, 54 + 24, &[0x0A]);
    }

    // --- dhcp: RFC 2131 §2 — the flags word at header offset 10:
    //     broadcast = bit 15 (0x8000).
    {
        let mut l = layer(
            "dhcp",
            &[
                ("op", int(1)),
                ("htype", int(1)),
                ("hlen", int(6)),
                ("xid", int(1)),
                ("msg_type", Value::Str("discover".into())),
            ],
        );
        l.fields.insert("flags".into(), int(0b1)); // broadcast
        let f = craft(vec![
            eth(),
            ip4(),
            layer("udp", &[("sport", int(68)), ("dport", int(67))]),
            l,
        ]);
        assert_bytes("dhcp.flags broadcast", &f, 42 + 10, &[0x80, 0x00]);
    }

    // --- dns: RFC 1035 §4.1.1 — the flags word at header offset 2:
    //     qr = bit 15, aa 10, tc 9, rd 8, ra 7 (opcode/rcode are the
    //     4-bit windows between them).
    {
        let mut l = layer(
            "dns",
            &[
                ("id", int(0x1234)),
                ("opcode", int(0)),
                ("rcode", int(0)),
                ("qd.0.name", Value::Str("example.com".into())),
                ("qd.0.type", Value::Str("A".into())),
                ("qd.0.class", Value::Str("IN".into())),
            ],
        );
        l.fields.insert("flags".into(), int(0b10010)); // qr|rd (bit_names[qr,aa,tc,rd,ra] → mask bits 4,1)
        let f = craft(vec![
            eth(),
            ip4(),
            layer("udp", &[("sport", int(5353)), ("dport", int(53))]),
            l,
        ]);
        assert_bytes("dns.flags qr|rd", &f, 42 + 2, &[0x81, 0x00]);
    }

    // --- icmp: RFC 792 — echo: type(0) code(1) cksum(2-3) id(4-5)
    //     seq(6-7): the pinned type/code bytes.
    {
        let f = craft(vec![
            eth(),
            ip4(),
            layer(
                "icmp",
                &[
                    ("type", int(8)),
                    ("code", int(3)),
                    ("echo.id", int(0x5151)),
                    ("echo.seq", int(7)),
                ],
            ),
        ]);
        assert_bytes("icmp type|code", &f, 34, &[0x08, 0x03]);
        assert_bytes("icmp echo id|seq", &f, 34 + 4, &[0x51, 0x51, 0x00, 0x07]);
    }
}
