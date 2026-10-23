//! DHCPv6 differential (tranche 17c): our crafted bytes vs the
//! in-process dhcproto::v6 oracle, both directions — wrex → dhcproto
//! (parse our craft) and dhcproto → wrex (dissect their encoding;
//! DhcpOptions is a sorted Vec so dhcproto encodes options sorted by
//! code, the reason craft parity is semantic, not byte-identical).
//! Mirrors tests/dhcp_differential.rs (the tranche-7c pattern).

#![cfg_attr(miri, ignore = "proptest; not Miri-safe")]

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use wrex_core::encode::{EncodeOpts, encode};
use wrex_core::spec::PacketSpec;
use wrex_core::value::Value;
use wrex_proto_dhcp6::strategy::strategy as dhcp6_strategy;
use wrex_test::dhcp_oracle::dhcp6_diff;

fn registry() -> wrex_core::Registry {
    wrex::standard()
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource(
            "proptest-regressions",
        ))),
        cases: 256,
        ..ProptestConfig::default()
    })]

    /// Direction 1 (wrex → dhcproto): encode the strategy spec, dissect
    /// it back from `dhcp6` (no anomalies, terminal, typed roundtrip of
    /// the set fields) and run the in-process oracle against the same
    /// bytes.
    #[test]
    fn dhcp6_craft_roundtrips_and_matches_dhcproto(spec in dhcp6_strategy()) {
        let reg = registry();
        let encoded = encode(
            &reg,
            &PacketSpec::new(vec![spec.clone()], None),
            &EncodeOpts { autofill: true, ..Default::default() },
        )?;
        let packet = wrex_core::dissect::dissect(&reg, &encoded.bytes, "dhcp6");
        prop_assert!(
            packet.anomalies.is_empty(),
            "anomalies on our own layer: {:?}",
            packet.anomalies
        );
        prop_assert_eq!(packet.layers.len(), 1, "dhcp6 is terminal");
        let dhcp6 = &packet.layers[0];
        // typed roundtrip of every explicitly-set whole field
        for (k, v) in &spec.fields {
            if k == "options" {
                continue; // list grammar → raw TLVs, verified by the oracle
            }
            let got = dhcp6.fields.get(k);
            prop_assert!(got.is_some(), "{k} missing after roundtrip");
            match (got, v) {
                (Some(Value::Int(a)), Value::Int(b)) => prop_assert_eq!(a, b),
                (Some(Value::Str(a)), Value::Str(b)) => prop_assert_eq!(a, b),
                (other, _) => panic!("unexpected roundtrip shape for {k}: {other:?}"),
            }
        }
        // in-process dhcproto v6 oracle (always available)
        if let Err(report) = dhcp6_diff(&encoded.bytes, dhcp6) {
            prop_assert!(report.mismatches.is_empty(), "dhcproto disagrees: {report:?}");
        }
    }

    /// Direction 2 (dhcproto → wrex): build a random message through
    /// dhcproto's typed model, encode it, dissect with wrex — the
    /// oracle must agree both ways (their encoder, our parser).
    #[test]
    fn dhcproto_v6_encoding_matches_our_dissection(
        xid in any::<[u8; 3]>(),
        msg in 1u8..=11,
        with_client_id in proptest::bool::ANY,
        with_server_id in proptest::bool::ANY,
        with_iana in proptest::bool::ANY,
        with_iaaddr in proptest::bool::ANY,
        with_oro in proptest::bool::ANY,
        with_elapsed in any::<u16>(),
        with_rapid in proptest::bool::ANY,
        with_dns in proptest::bool::ANY,
        with_domain in proptest::bool::ANY,
        ip in any::<u32>(),
    ) {
        use dhcproto::v6::{
            DhcpOption, IAAddr, IANA, Message, MessageType, OptionCode, ORO,
        };
        use std::net::Ipv6Addr;

        let reg = registry();
        let mut message = Message::new_with_id(
            MessageType::from(msg),
            xid,
        );
        let addr = Ipv6Addr::from(u128::from(u32::from_be(ip)));
        let opts = message.opts_mut();
        if with_client_id {
            opts.insert(DhcpOption::ClientId(vec![0, 1, 2, 3, 4, 5]));
        }
        if with_server_id {
            opts.insert(DhcpOption::ServerId(vec![0, 1, 2, 3, 4, 5]));
        }
        if with_iana {
            let mut iana = IANA {
                id: 7,
                t1: 300,
                t2: 600,
                opts: Default::default(),
            };
            if with_iaaddr {
                iana.opts.insert(DhcpOption::IAAddr(IAAddr {
                    addr,
                    preferred_life: 3600,
                    valid_life: 7200,
                    opts: Default::default(),
                }));
            }
            opts.insert(DhcpOption::IANA(iana));
        }
        if with_oro {
            opts.insert(DhcpOption::ORO(ORO {
                opts: vec![
                    OptionCode::DomainNameServers,
                    OptionCode::DomainSearchList,
                ],
            }));
        }
        if with_elapsed.is_multiple_of(2) {
            opts.insert(DhcpOption::ElapsedTime(with_elapsed));
        }
        if with_rapid {
            opts.insert(DhcpOption::RapidCommit);
        }
        if with_dns {
            opts.insert(DhcpOption::DomainNameServers(vec![
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53),
                addr,
            ]));
        }
        if with_domain {
            // hickory Name::parse wants a domain-local name; the
            // wrex.example fixture is a valid parseable FQDN shape.
            if let Ok(name) = dhcproto::Name::parse("wrex.example.", None) {
                opts.insert(DhcpOption::DomainSearchList(vec![name]));
            }
        }
        let bytes = dhcproto::Encodable::to_vec(&message)?;

        let packet = wrex_core::dissect::dissect(&reg, &bytes, "dhcp6");
        prop_assert!(
            packet.anomalies.is_empty(),
            "anomalies dissecting dhcproto bytes: {:?}",
            packet.anomalies
        );
        prop_assert_eq!(packet.layers.len(), 1);
        let dhcp6 = &packet.layers[0];
        if let Err(report) = dhcp6_diff(&bytes, dhcp6) {
            prop_assert!(report.mismatches.is_empty(), "our dissection disagrees: {report:?}");
        }
    }
}
