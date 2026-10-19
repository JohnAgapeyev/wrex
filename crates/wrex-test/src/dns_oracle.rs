//! In-process hickory-proto differential oracle for DNS messages
//! (tranche 3; the DNS counterpart of [`crate::oracle::EtherparseOracle`]).
//!
//! One module so hickory API drift stays contained. Compares our
//! dissection of a dns-start message against `hickory_proto::op::Message`
//! field by field: header (id, qr/aa/tc/rd/ra, opcode, rcode, counts),
//! every question, and every answer/authority/additional record —
//! name (compression pointers resolved on both sides), type, class, ttl
//! and the typed rdata we model at tranche 3 (A → ipv4,
//! CNAME/NS/PTR → resolved name). The deferred-typed rdata (MX, SOA,
//! SRV, OPT, TXT, AAAA) is covered by hickory's structural parse
//! agreeing on everything else; both-sides-parse convention: when
//! hickory refuses the bytes, there is nothing to compare.

use hickory_proto::op::Message;
use wrex_core::dissect::LayerView;
use wrex_core::value::Value;
use wrex_proto_dns::types::{TYPE_A, TYPE_CNAME, TYPE_NS, TYPE_PTR, parse_type};

use crate::oracle::DiffReport;

/// hickory names carry a trailing dot (FQDN form); ours do not.
fn name_str(hickory: &str) -> String {
    hickory.strip_suffix('.').unwrap_or(hickory).to_string()
}

fn our_str<'v>(layer: &'v LayerView, key: &str) -> Option<&'v String> {
    match layer.fields.get(key) {
        Some(Value::Str(s)) => Some(s),
        _ => None,
    }
}

fn our_int(layer: &LayerView, key: &str) -> Option<u128> {
    match layer.fields.get(key) {
        Some(Value::Int(v)) => Some(*v),
        _ => None,
    }
}

fn our_flag(layer: &LayerView, bit: &str) -> bool {
    match layer.fields.get("flags") {
        Some(Value::List(items)) => items.iter().any(|v| matches!(v, Value::Str(s) if s == bit)),
        _ => false,
    }
}

fn type_num(layer: &LayerView, key: &str) -> Option<u16> {
    our_str(layer, key).and_then(|s| parse_type(s))
}

/// Compare our dns-layer dissection against hickory's parse of the same
/// bytes. `Ok(())` when hickory refuses the message (or agrees).
pub fn dns_diff(input: &[u8], dns: &LayerView) -> Result<(), DiffReport> {
    let Ok(message) = Message::from_vec(input) else {
        return Ok(()); // both-sides-parse convention
    };
    let mut report = DiffReport::default();

    // Header.
    let md = &message.metadata;
    cmp_int(&mut report, "dns.id", our_int(dns, "id"), u128::from(md.id));
    cmp_int(
        &mut report,
        "dns.opcode",
        our_int(dns, "opcode"),
        u128::from(u8::from(md.op_code)),
    );
    cmp_int(
        &mut report,
        "dns.rcode",
        our_int(dns, "rcode"),
        u128::from(u16::from(md.response_code)),
    );
    let flag_pairs = [
        (
            "qr",
            md.message_type == hickory_proto::op::MessageType::Response,
        ),
        ("aa", md.authoritative),
        ("tc", md.truncation),
        ("rd", md.recursion_desired),
        ("ra", md.recursion_available),
    ];
    for (bit, theirs) in flag_pairs {
        let ours = our_flag(dns, bit);
        if ours != theirs {
            report.push(
                &format!("dns.flags.{bit}"),
                format!("{ours}"),
                format!("{theirs}"),
            );
        }
    }

    // Questions (our qd.i.* against hickory's queries).
    cmp_int(
        &mut report,
        "dns.qdcount",
        our_int(dns, "qdcount"),
        message.queries.len() as u128,
    );
    for (i, q) in message.queries.iter().enumerate() {
        let prefix = format!("qd.{i}");
        cmp_str(
            &mut report,
            &format!("dns.{prefix}.name"),
            our_str(dns, &format!("{prefix}.name")),
            name_str(&q.name.to_string()),
        );
        cmp_int(
            &mut report,
            &format!("dns.{prefix}.type"),
            type_num(dns, &format!("{prefix}.type")).map(u128::from),
            u128::from(u16::from(q.query_type)),
        );
        cmp_int(
            &mut report,
            &format!("dns.{prefix}.class"),
            type_class_num(dns, &format!("{prefix}.class")),
            u128::from(u16::from(q.query_class)),
        );
    }

    // Record sections.
    let sections: [(&str, &str, &Vec<hickory_proto::rr::Record>); 3] = [
        ("ancount", "an", &message.answers),
        ("nscount", "ns", &message.authorities),
        ("arcount", "ar", &message.additionals),
    ];
    for (count_key, section, records) in sections {
        cmp_int(
            &mut report,
            &format!("dns.{count_key}"),
            our_int(dns, count_key),
            records.len() as u128,
        );
        for (i, rr) in records.iter().enumerate() {
            let prefix = format!("{section}.{i}");
            cmp_str(
                &mut report,
                &format!("dns.{prefix}.name"),
                our_str(dns, &format!("{prefix}.name")),
                name_str(&rr.name.to_string()),
            );
            cmp_int(
                &mut report,
                &format!("dns.{prefix}.type"),
                type_num(dns, &format!("{prefix}.type")).map(u128::from),
                u128::from(u16::from(rr.record_type())),
            );
            cmp_int(
                &mut report,
                &format!("dns.{prefix}.class"),
                type_class_num(dns, &format!("{prefix}.class")),
                u128::from(u16::from(rr.dns_class)),
            );
            cmp_int(
                &mut report,
                &format!("dns.{prefix}.ttl"),
                our_int(dns, &format!("{prefix}.ttl")),
                u128::from(rr.ttl),
            );
            // Typed rdata per the tranche-3 freeze.
            let rdata_key = format!("{prefix}.rdata");
            let rtype = u16::from(rr.record_type());
            match rtype {
                TYPE_A => match (&rr.data, dns.fields.get(&rdata_key)) {
                    (hickory_proto::rr::RData::A(a), Some(Value::Ipv4(ip))) => {
                        if a.0 != *ip {
                            report.push(
                                &format!("dns.{rdata_key}"),
                                ip.to_string(),
                                a.0.to_string(),
                            );
                        }
                    }
                    (theirs, ours) => report.push(
                        &format!("dns.{rdata_key}"),
                        format!("{ours:?}"),
                        format!("{theirs:?}"),
                    ),
                },
                TYPE_CNAME | TYPE_NS | TYPE_PTR => {
                    let theirs = match &rr.data {
                        hickory_proto::rr::RData::CNAME(c) => name_str(&c.0.to_string()),
                        hickory_proto::rr::RData::NS(n) => name_str(&n.0.to_string()),
                        hickory_proto::rr::RData::PTR(p) => name_str(&p.0.to_string()),
                        other => {
                            report.push(
                                &format!("dns.{rdata_key}"),
                                "unexpected variant".to_string(),
                                format!("{other:?}"),
                            );
                            continue;
                        }
                    };
                    cmp_str(
                        &mut report,
                        &format!("dns.{rdata_key}"),
                        our_str(dns, &rdata_key),
                        theirs,
                    );
                }
                // Deferred-typed rdata: hickory's structural parse
                // agreeing on name/type/class/ttl is the coverage; raw
                // byte parity is asserted by our own encode→dissect
                // roundtrip suites.
                _ => {}
            }
        }
    }

    if report.mismatches.is_empty() {
        Ok(())
    } else {
        Err(report)
    }
}

fn type_class_num(layer: &LayerView, key: &str) -> Option<u128> {
    our_str(layer, key)
        .and_then(|s| wrex_proto_dns::types::parse_class(s))
        .map(u128::from)
}

fn cmp_int(report: &mut DiffReport, path: &str, ours: Option<u128>, theirs: u128) {
    if ours != Some(theirs) {
        report.push(path, format!("{ours:?}"), format!("{theirs}"));
    }
}

fn cmp_str(report: &mut DiffReport, path: &str, ours: Option<&String>, theirs: String) {
    if ours.map(|o| o.as_str()) != Some(theirs.as_str()) {
        report.push(path, format!("{ours:?}"), format!("{theirs:?}"));
    }
}
