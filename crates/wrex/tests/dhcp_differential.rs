//! DHCP differential (tranche 7c): our crafted bytes vs the in-process
//! dhcproto oracle, both directions — wrex → dhcproto (parse our craft)
//! and dhcproto → wrex (dissect their encoding; DhcpOptions is a
//! BTreeMap so dhcproto encodes options sorted by code with an
//! auto-`end`, the reason craft parity is semantic, not byte-identical).
//! Mirrors tests/dns_differential.rs (the hickory-proto pattern).

#![cfg_attr(miri, ignore = "proptest; not Miri-safe")]

use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;
use wrex_core::encode::{EncodeOpts, encode};
use wrex_core::spec::PacketSpec;
use wrex_core::value::Value;
use wrex_proto_dhcp::strategy::strategy as dhcp_strategy;
use wrex_test::dhcp_oracle::dhcp_diff;

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
    /// it back from `dhcp` (no anomalies, typed roundtrip of the set
    /// fields) and run the in-process oracle against the same bytes.
    #[test]
    fn dhcp_craft_roundtrips_and_matches_dhcproto(spec in dhcp_strategy()) {
        let reg = registry();
        let encoded = encode(
            &reg,
            &PacketSpec::new(vec![spec.clone()], None),
            &EncodeOpts { autofill: true, ..Default::default() },
        )?;
        let packet = wrex_core::dissect::dissect(&reg, &encoded.bytes, "dhcp");
        prop_assert!(
            packet.anomalies.is_empty(),
            "anomalies on our own layer: {:?}",
            packet.anomalies
        );
        prop_assert_eq!(packet.layers.len(), 1, "dhcp is terminal");
        let dhcp = &packet.layers[0];
        // typed roundtrip of every explicitly-set whole field
        for (k, v) in &spec.fields {
            if k == "options" {
                continue; // list grammar → raw TLVs, verified by the oracle
            }
            let got = dhcp.fields.get(k);
            prop_assert!(got.is_some(), "{k} missing after roundtrip");
            match (got, v) {
                (Some(Value::Int(a)), Value::Int(b)) => prop_assert_eq!(a, b),
                (Some(Value::Ipv4(a)), Value::Ipv4(b)) => prop_assert_eq!(a, b),
                (Some(Value::Str(a)), Value::Str(b)) => prop_assert_eq!(a, b),
                (other, _) => panic!("unexpected roundtrip shape for {k}: {other:?}"),
            }
        }
        // in-process dhcproto oracle (always available)
        if let Err(report) = dhcp_diff(&encoded.bytes, dhcp) {
            prop_assert!(report.mismatches.is_empty(), "dhcproto disagrees: {report:?}");
        }
    }

    /// Direction 2 (dhcproto → wrex): build a random message through
    /// dhcproto's typed model, encode it, dissect with wrex — the
    /// oracle must agree both ways (their encoder, our parser).
    #[test]
    fn dhcproto_encoding_matches_our_dissection(
        xid in any::<u32>(),
        secs in any::<u16>(),
        ciaddr in any::<u32>(),
        yiaddr in any::<u32>(),
        siaddr in any::<u32>(),
        giaddr in any::<u32>(),
        broadcast in proptest::bool::ANY,
        msg in 1u8..=8,
        with_lease in proptest::bool::ANY,
        with_mask in proptest::bool::ANY,
        with_routers in proptest::bool::ANY,
        with_host in proptest::bool::ANY,
        with_param_req in proptest::bool::ANY,
        with_client_id in proptest::bool::ANY,
    ) {
        use dhcproto::v4::{DhcpOption, Encodable, Flags, HType, MessageType, Message, Opcode, OptionCode};
        use std::net::Ipv4Addr;

        let reg = registry();
        let mut message = Message::new_with_id(
            xid,
            Ipv4Addr::from(ciaddr),
            Ipv4Addr::from(yiaddr),
            Ipv4Addr::from(siaddr),
            Ipv4Addr::from(giaddr),
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
        );
        message.set_opcode(Opcode::BootReply).set_htype(HType::Eth);
        message.set_secs(secs);
        if broadcast {
            message.set_flags(Flags::new(0x8000));
        }
        message.set_sname_str("wrex-server");
        message.set_fname_str("boot.img");
        let opts = message.opts_mut();
        opts.insert(DhcpOption::MessageType(MessageType::from(msg)));
        if with_lease {
            opts.insert(DhcpOption::AddressLeaseTime(3600));
        }
        if with_mask {
            opts.insert(DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)));
        }
        if with_routers {
            opts.insert(DhcpOption::Router(vec![
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
            ]));
        }
        if with_host {
            opts.insert(DhcpOption::Hostname("wrex".to_string()));
        }
        if with_param_req {
            opts.insert(DhcpOption::ParameterRequestList(vec![
                OptionCode::SubnetMask,
                OptionCode::Router,
                OptionCode::DomainNameServer,
            ]));
        }
        if with_client_id {
            opts.insert(DhcpOption::ClientIdentifier(vec![1, 2, 3, 4, 5, 6]));
        }
        let bytes = message.to_vec()?;

        let packet = wrex_core::dissect::dissect(&reg, &bytes, "dhcp");
        prop_assert!(
            packet.anomalies.is_empty(),
            "anomalies dissecting dhcproto bytes: {:?}",
            packet.anomalies
        );
        prop_assert_eq!(packet.layers.len(), 1);
        let dhcp = &packet.layers[0];
        if let Err(report) = dhcp_diff(&bytes, dhcp) {
            prop_assert!(report.mismatches.is_empty(), "our dissection disagrees: {report:?}");
        }
        // sname/file survive dhcproto's NUL padding (bind the values
        // first: MSRV 1.88 doesn't extend match-scrutinee temporaries)
        let want_sname = Value::Str("wrex-server".into());
        let want_file = Value::Str("boot.img".into());
        prop_assert_eq!(dhcp.fields.get("sname"), Some(&want_sname));
        prop_assert_eq!(dhcp.fields.get("file"), Some(&want_file));
    }
}
