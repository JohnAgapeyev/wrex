//! DNS differential suite (`cargo test -- differential`): random dns
//! specs from the `test-util` strategy → encode → dissect; flat-field
//! roundtrip + the in-process hickory-proto oracle must agree, and the
//! same question built through hickory must produce byte-identical
//! wire bytes (both sides emit uncompressed names).
//!
//! Proptest-based: ignored under Miri (the deterministic dns codec unit
//! tests run there). The subprocess dig differential lives in
//! `dns_dig.rs` (env-gated).
#![cfg_attr(miri, ignore = "proptest; not Miri-safe")]

use proptest::prelude::*;

use wrex_core::Registry;
use wrex_core::encode::{EncodeOpts, encode};
use wrex_core::spec::PacketSpec;
use wrex_core::value::Value;
use wrex_test::dns_oracle::dns_diff;

/// MSB-first dns flag bit names (mirrors the schema).
const DNS_FLAGS: &[&str] = &["qr", "aa", "tc", "rd", "ra"];

fn registry() -> Registry {
    wrex::standard()
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Differential: encode → dissect → roundtrip + hickory agreement.
    #[test]
    fn dns_differential_roundtrip_and_hickory(spec in wrex_proto_dns::strategy::strategy()) {
        let reg = registry();
        let encoded = encode(
            &reg,
            &PacketSpec::new(vec![spec.clone()], None),
            &EncodeOpts { autofill: true, ..Default::default() },
        )
        .expect("encode must not panic");
        let packet = wrex_core::dissect::dissect(&reg, &encoded.bytes, "dns");
        prop_assert!(packet.anomalies.is_empty(), "{:?}", packet.anomalies);
        let dns = &packet.layers[0];
        prop_assert_eq!(dns.kind, "dns");

        // Roundtrip: every explicitly-set whole field reappears typed.
        for (k, v) in &spec.fields {
            match k.as_str() {
                "flags" => {
                    // aggregate mask → dissected sorted name list
                    let Value::Int(mask) = v else { continue };
                    let want: Vec<&str> = DNS_FLAGS
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| mask & (1 << (4 - *i as u128)) != 0)
                        .map(|(_, n)| *n)
                        .collect();
                    let got: Vec<String> = match dns.fields.get("flags") {
                        Some(Value::List(items)) => items
                            .iter()
                            .filter_map(|v| match v {
                                Value::Str(s) => Some(s.clone()),
                                _ => None,
                            })
                            .collect(),
                        _ => Vec::new(),
                    };
                    prop_assert!(
                        got == want.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        "flags: got {got:?} want {want:?}"
                    );
                }
                "flags.rd" | "flags.qr" | "flags.aa" | "flags.tc" | "flags.ra" => {
                    continue; // per-bit subpaths merge into the aggregate
                }
                k if k.starts_with("qd.") => {
                    prop_assert_eq!(
                        dns.fields.get(k),
                        Some(v),
                        "set {} did not roundtrip (got {:?})",
                        k,
                        dns.fields.get(k)
                    );
                }
                _ => {
                    prop_assert_eq!(dns.fields.get(k), Some(v));
                }
            }
        }

        // hickory-proto oracle (in-process, always available).
        if let Err(report) = dns_diff(&encoded.bytes, dns) {
            prop_assert!(
                report.mismatches.is_empty(),
                "hickory diffs {:?}",
                report.mismatches
            );
        }
    }

    /// Craft parity: the same question through hickory `to_vec` must be
    /// byte-identical (both emitters write plain uncompressed names).
    #[test]
    fn dns_differential_craft_parity_with_hickory(
        id in any::<u16>(),
        name in proptest::sample::select(vec![
            "example.com", "a.b.example.com", "localhost", "x.io",
            "sub.domain.example.co.uk",
        ]),
        qtype in proptest::sample::select(vec!["A", "AAAA", "MX", "TXT", "NS", "PTR", "SOA", "SRV", "CNAME"]),
        rd in proptest::bool::ANY,
    ) {
        use std::collections::BTreeMap;
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use hickory_proto::rr::domain::Name;
        use hickory_proto::rr::RecordType;

        let reg = registry();
        let mut fields = BTreeMap::new();
        fields.insert("id".to_string(), Value::Int(id as u128));
        if rd {
            fields.insert("flags.rd".to_string(), Value::Bool(true));
        }
        fields.insert("qd.0.name".to_string(), Value::Str(name.to_string()));
        fields.insert("qd.0.type".to_string(), Value::Str(qtype.to_string()));
        fields.insert("qd.0.class".to_string(), Value::Str("IN".to_string()));
        let spec = wrex_core::LayerSpec::with_fields("dns", fields);
        let encoded = encode(
            &reg,
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts { autofill: true, ..Default::default() },
        )
        .unwrap();

        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = rd;
        message.queries.push(Query::query(
            Name::from_ascii(name).unwrap(),
            RecordType::from(wrex_proto_dns::types::parse_type(qtype).unwrap()),
        ));
        let theirs = message.to_vec().unwrap();

        prop_assert_eq!(&encoded.bytes[..], &theirs[..],
            "craft parity failed for {} {} rd={}\nours:   {}\ntheirs: {}",
            name, qtype, rd, hex::encode(&encoded.bytes), hex::encode(&theirs));
    }
}
