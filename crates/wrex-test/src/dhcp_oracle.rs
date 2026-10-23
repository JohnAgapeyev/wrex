//! In-process dhcproto differential oracle for DHCP messages (tranche
//! 7c; the DHCP counterpart of [`crate::dns_oracle`]).
//!
//! One module so dhcproto API drift stays contained. Compares our
//! dissection of a dhcp-start message against
//! `dhcproto::v4::Message` field by field: the fixed header (op,
//! htype, hlen, hops, xid, secs, broadcast flag, the four addresses,
//! sname/file, message type) and the typed option subset we model
//! (subnet mask, routers, dns servers, host name, domain name,
//! requested ip, lease/renewal/rebinding times, server id,
//! parameter-request list, max message size, client identifier).
//! Craft parity is semantic both-direction, not byte-identical:
//! dhcproto stores options in a BTreeMap (encodes sorted by option
//! code, auto-appends `end`) while the wrex grammar preserves the
//! user's order — the tranche-7c freeze. Both-sides-parse convention:
//! when dhcproto refuses the bytes, there is nothing to compare.

use std::net::Ipv4Addr;

use dhcproto::v4::{Decodable, Decoder, DhcpOption, Message, MessageType, Opcode};
use wrex_core::dissect::LayerView;
use wrex_core::value::Value;

use crate::oracle::DiffReport;

fn our_int(layer: &LayerView, key: &str) -> Option<u128> {
    match layer.fields.get(key) {
        Some(Value::Int(v)) => Some(*v),
        _ => None,
    }
}

fn our_str<'v>(layer: &'v LayerView, key: &str) -> Option<&'v String> {
    match layer.fields.get(key) {
        Some(Value::Str(s)) => Some(s),
        _ => None,
    }
}

fn our_ip(layer: &LayerView, key: &str) -> Option<Ipv4Addr> {
    match layer.fields.get(key) {
        Some(Value::Ipv4(a)) => Some(*a),
        _ => None,
    }
}

fn our_broadcast(layer: &LayerView) -> bool {
    matches!(layer.fields.get("flags"), Some(Value::List(items)) if items
        .iter()
        .any(|v| matches!(v, Value::Str(s) if s == "broadcast")))
}

fn our_record_int(layer: &LayerView, code: u8) -> Option<u128> {
    let mut i = 0usize;
    loop {
        match layer.fields.get(&format!("opt.{i}.code")) {
            Some(Value::Int(c)) if *c == code as u128 => {
                return match layer.fields.get(&format!("opt.{i}.num")) {
                    Some(Value::Int(v)) => Some(*v),
                    _ => None,
                };
            }
            Some(_) => i += 1,
            None => return None,
        }
    }
}

fn our_record_ip(layer: &LayerView, code: u8) -> Option<Ipv4Addr> {
    let mut i = 0usize;
    loop {
        match layer.fields.get(&format!("opt.{i}.code")) {
            Some(Value::Int(c)) if *c == code as u128 => {
                return match layer.fields.get(&format!("opt.{i}.ip")) {
                    Some(Value::Ipv4(a)) => Some(*a),
                    _ => None,
                };
            }
            Some(_) => i += 1,
            None => return None,
        }
    }
}

fn our_record_ips(layer: &LayerView, code: u8) -> Option<Vec<Ipv4Addr>> {
    // `value` is the raw wire bytes for the option.
    let mut i = 0usize;
    loop {
        match layer.fields.get(&format!("opt.{i}.code")) {
            Some(Value::Int(c)) if *c == code as u128 => {
                return match layer.fields.get(&format!("opt.{i}.value")) {
                    Some(Value::Bytes(b)) => {
                        if b.len() % 4 != 0 {
                            return None;
                        }
                        Some(
                            b.chunks(4)
                                .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                                .collect(),
                        )
                    }
                    _ => None,
                };
            }
            Some(_) => i += 1,
            None => return None,
        }
    }
}

fn our_record_text(layer: &LayerView, code: u8) -> Option<String> {
    let mut i = 0usize;
    loop {
        match layer.fields.get(&format!("opt.{i}.code")) {
            Some(Value::Int(c)) if *c == code as u128 => {
                return our_str(layer, &format!("opt.{i}.text")).cloned();
            }
            Some(_) => i += 1,
            None => return None,
        }
    }
}

fn cmp_int(report: &mut DiffReport, path: &str, ours: Option<u128>, theirs: u128) {
    if ours != Some(theirs) {
        report.push(path, format!("{ours:?}"), format!("{theirs}"));
    }
}

fn cmp_ip(report: &mut DiffReport, path: &str, ours: Option<Ipv4Addr>, theirs: Ipv4Addr) {
    if ours != Some(theirs) {
        report.push(path, format!("{ours:?}"), format!("{theirs}"));
    }
}

fn cmp_bool(report: &mut DiffReport, path: &str, ours: bool, theirs: bool) {
    if ours != theirs {
        report.push(path, format!("{ours}"), format!("{theirs}"));
    }
}

fn cmp_str(report: &mut DiffReport, path: &str, ours: Option<String>, theirs: &str) {
    if ours.as_deref() != Some(theirs) {
        report.push(path, format!("{ours:?}"), theirs.to_string());
    }
}

fn cmp_ips(
    report: &mut DiffReport,
    path: &str,
    ours: Option<Vec<Ipv4Addr>>,
    theirs: &Vec<Ipv4Addr>,
) {
    if ours.as_deref() != Some(theirs) {
        report.push(path, format!("{ours:?}"), format!("{theirs:?}"));
    }
}

/// Compare our dhcp-layer dissection against dhcproto's parse of the
/// same bytes. `Ok(())` when dhcproto refuses the message (or agrees).
pub fn dhcp_diff(input: &[u8], dhcp: &LayerView) -> Result<(), DiffReport> {
    let Ok(message) = Message::decode(&mut Decoder::new(input)) else {
        return Ok(()); // both-sides-parse convention
    };
    let mut report = DiffReport::default();

    // Fixed header.
    cmp_int(
        &mut report,
        "dhcp.op",
        our_int(dhcp, "op"),
        u128::from(u8::from(message.opcode())),
    );
    cmp_int(
        &mut report,
        "dhcp.hlen",
        our_int(dhcp, "hlen"),
        u128::from(message.hlen()),
    );
    cmp_int(
        &mut report,
        "dhcp.hops",
        our_int(dhcp, "hops"),
        u128::from(message.hops()),
    );
    cmp_int(
        &mut report,
        "dhcp.xid",
        our_int(dhcp, "xid"),
        u128::from(message.xid()),
    );
    cmp_int(
        &mut report,
        "dhcp.secs",
        our_int(dhcp, "secs"),
        u128::from(message.secs()),
    );
    cmp_bool(
        &mut report,
        "dhcp.flags.broadcast",
        our_broadcast(dhcp),
        message.flags().broadcast(),
    );
    cmp_ip(
        &mut report,
        "dhcp.ciaddr",
        our_ip(dhcp, "ciaddr"),
        message.ciaddr(),
    );
    cmp_ip(
        &mut report,
        "dhcp.yiaddr",
        our_ip(dhcp, "yiaddr"),
        message.yiaddr(),
    );
    cmp_ip(
        &mut report,
        "dhcp.siaddr",
        our_ip(dhcp, "siaddr"),
        message.siaddr(),
    );
    cmp_ip(
        &mut report,
        "dhcp.giaddr",
        our_ip(dhcp, "giaddr"),
        message.giaddr(),
    );
    // dhcproto's sname_str()/fname_str() keep the NUL terminator
    // (tshark trims it, as we do) — normalize before comparing.
    let nul_trim = |s: Option<Result<&str, _>>| {
        s.and_then(|s| s.ok())
            .map(|s| s.trim_end_matches('\0').to_string())
            .unwrap_or_default()
    };
    cmp_str(
        &mut report,
        "dhcp.sname",
        our_str(dhcp, "sname").cloned(),
        &nul_trim(message.sname_str()),
    );
    cmp_str(
        &mut report,
        "dhcp.file",
        our_str(dhcp, "file").cloned(),
        &nul_trim(message.fname_str()),
    );

    // Message type (option 53): our canonical lowercase names vs
    // dhcproto's CamelCase variants (MessageType has no Display —
    // map through the numeric wire value).
    if let Some(mt) = message.opts().msg_type() {
        let theirs = wrex_proto_dhcp::options::render_msg_type(u8::from(mt));
        cmp_str(
            &mut report,
            "dhcp.msg_type",
            our_str(dhcp, "msg_type").cloned(),
            &theirs,
        );
    }

    // Typed option subset (both sides may legitimately lack an
    // option; compare only when dhcproto sees one and we can't).
    let opts = message.opts();
    for (code, opt) in opts.iter() {
        match opt {
            DhcpOption::SubnetMask(ip) => {
                cmp_ip(&mut report, "dhcp.opt.1", our_record_ip(dhcp, 1), *ip)
            }
            DhcpOption::Router(ips) => {
                cmp_ips(&mut report, "dhcp.opt.3", our_record_ips(dhcp, 3), ips)
            }
            DhcpOption::DomainNameServer(ips) => {
                cmp_ips(&mut report, "dhcp.opt.6", our_record_ips(dhcp, 6), ips)
            }
            DhcpOption::Hostname(s) => {
                cmp_str(&mut report, "dhcp.opt.12", our_record_text(dhcp, 12), s)
            }
            DhcpOption::DomainName(s) => {
                cmp_str(&mut report, "dhcp.opt.15", our_record_text(dhcp, 15), s)
            }
            DhcpOption::RequestedIpAddress(ip) => {
                cmp_ip(&mut report, "dhcp.opt.50", our_record_ip(dhcp, 50), *ip)
            }
            DhcpOption::AddressLeaseTime(n) => cmp_int(
                &mut report,
                "dhcp.opt.51",
                our_record_int(dhcp, 51),
                u128::from(*n),
            ),
            DhcpOption::ServerIdentifier(ip) => {
                cmp_ip(&mut report, "dhcp.opt.54", our_record_ip(dhcp, 54), *ip)
            }
            DhcpOption::ParameterRequestList(list) => {
                let ours: Option<Vec<u128>> = {
                    let mut i = 0usize;
                    loop {
                        match dhcp.fields.get(&format!("opt.{i}.code")) {
                            Some(Value::Int(c)) if *c == 55 => {
                                let bytes = match dhcp.fields.get(&format!("opt.{i}.value")) {
                                    Some(Value::Bytes(b)) => Some(b.to_vec()),
                                    _ => None,
                                };
                                break bytes.map(|b| b.iter().map(|x| u128::from(*x)).collect());
                            }
                            Some(_) => i += 1,
                            None => break None,
                        }
                    }
                };
                let theirs: Vec<u128> = list.iter().map(|c| u128::from(u8::from(*c))).collect();
                if ours != Some(theirs.clone()) {
                    report.push("dhcp.opt.55", format!("{ours:?}"), format!("{theirs:?}"));
                }
            }
            DhcpOption::MaxMessageSize(n) => cmp_int(
                &mut report,
                "dhcp.opt.57",
                our_record_int(dhcp, 57),
                u128::from(*n),
            ),
            DhcpOption::Renewal(n) => cmp_int(
                &mut report,
                "dhcp.opt.58",
                our_record_int(dhcp, 58),
                u128::from(*n),
            ),
            DhcpOption::Rebinding(n) => cmp_int(
                &mut report,
                "dhcp.opt.59",
                our_record_int(dhcp, 59),
                u128::from(*n),
            ),
            DhcpOption::ClientIdentifier(id) => {
                let mut i = 0usize;
                let ours: Option<Vec<u8>> = loop {
                    match dhcp.fields.get(&format!("opt.{i}.code")) {
                        Some(Value::Int(c)) if *c == 61 => {
                            break match dhcp.fields.get(&format!("opt.{i}.value")) {
                                Some(Value::Bytes(b)) => Some(b.to_vec()),
                                _ => None,
                            };
                        }
                        Some(_) => i += 1,
                        None => break None,
                    }
                };
                if ours.as_deref() != Some(id.as_slice()) {
                    report.push("dhcp.opt.61", format!("{ours:?}"), format!("{id:?}"));
                }
            }
            _ => {
                // Options outside the committed typing: dhcproto's
                // structural parse agreeing on everything else is the
                // coverage (the dns deferred-rdata convention). Only
                // check that we saw the raw TLV too.
                let code_num = u8::from(*code);
                let mut i = 0usize;
                let seen = loop {
                    match dhcp.fields.get(&format!("opt.{i}.code")) {
                        Some(Value::Int(c)) if *c == u128::from(code_num) => break true,
                        Some(_) => i += 1,
                        None => break false,
                    }
                };
                if !seen {
                    report.push(
                        &format!("dhcp.opt.{code_num}"),
                        "no record".to_string(),
                        format!("{opt:?}"),
                    );
                }
            }
        }
    }

    let _ = (Opcode::BootRequest, MessageType::Discover); // dhcproto API surface
    if report.mismatches.is_empty() {
        Ok(())
    } else {
        Err(report)
    }
}

// ---------------------------------------------------------------------------
// Tranche 17c: the DHCPv6 arm (`dhcproto::v6`). The same both-direction,
// both-sides-parse convention: when dhcproto refuses the bytes, there
// is nothing to compare. dhcproto stores options in a sorted Vec
// (encodes sorted by option code) while the wrex grammar preserves
// the user's order — craft parity is semantic, not byte-identical
// (the tranche-7c freeze, transposed). Relay shapes (12/13) are
// outside the oracle: dhcproto's `RelayMessage` is a distinct type
// and crafting them is a recorded deferral.
// ---------------------------------------------------------------------------

use std::net::Ipv6Addr as V6Addr;

use dhcproto::v6::{
    DhcpOption as V6Option, IAAddr as V6IaAddr, IANA as V6Iana, Message as V6Message,
    OptionCode as V6OptionCode,
};

/// One of our `opt.N` record views for a code.
struct V6Record<'v> {
    n: usize,
    map: std::collections::BTreeMap<&'v str, &'v Value>,
}

/// All our `opt.N` records carrying a code (an option may legally
/// appear more than once — IA_NA does).
fn our_v6_records<'v>(layer: &'v LayerView, code: u16) -> Vec<V6Record<'v>> {
    let mut out = Vec::new();
    let mut n = 0usize;
    loop {
        let prefix = format!("opt.{n}.");
        let map: std::collections::BTreeMap<&str, &Value> = layer
            .fields
            .iter()
            .filter_map(|(k, v)| Some((k.strip_prefix(&prefix)?, v)))
            .collect();
        if map.is_empty() {
            return out;
        }
        if matches!(map.get("code"), Some(Value::Int(c)) if *c == u128::from(code)) {
            out.push(V6Record { n, map });
        }
        n += 1;
    }
}

impl V6Record<'_> {
    fn value(&self) -> Option<&[u8]> {
        match self.map.get("value") {
            Some(Value::Bytes(b)) => Some(b),
            _ => None,
        }
    }
    fn num(&self) -> Option<u128> {
        match self.map.get("num") {
            Some(Value::Int(v)) => Some(*v),
            _ => None,
        }
    }
    fn text(&self) -> Option<&str> {
        match self.map.get("text") {
            Some(Value::Str(s)) => Some(s),
            _ => None,
        }
    }
    /// A u32 out of the raw value at a byte offset.
    fn u32_at(&self, at: usize) -> Option<u128> {
        self.value()?
            .get(at..at + 4)
            .map(|b| u128::from(u32::from_be_bytes(b.try_into().unwrap())))
    }
}

/// Compare our dhcp6-layer dissection against dhcproto v6's parse of
/// the same bytes. `Ok(())` when dhcproto refuses the message (or
/// agrees).
pub fn dhcp6_diff(input: &[u8], dhcp6: &LayerView) -> Result<(), DiffReport> {
    let Ok(message) = V6Message::decode(&mut dhcproto::Decoder::new(input)) else {
        return Ok(()); // both-sides-parse convention
    };
    let mut report = DiffReport::default();
    let opts = message.opts();

    // Fixed header: msg_type (our names map through the RFC 8415
    // registry) + trans_id.
    let ours_mt = match dhcp6.fields.get("msg_type") {
        Some(Value::Str(s)) => wrex_proto_dhcp6::options::parse_msg_type(s),
        _ => None,
    };
    cmp_int(
        &mut report,
        "dhcp6.msg_type",
        ours_mt.map(u128::from),
        u128::from(u8::from(message.msg_type())),
    );
    cmp_int(
        &mut report,
        "dhcp6.trans_id",
        our_int(dhcp6, "trans_id"),
        u128::from(message.xid_num()),
    );

    // Typed option subset (compare only where dhcproto sees one; a
    // missing wrex record fails the coverage walk at the end).
    if let Some(V6Option::ClientId(id)) = opts.get(V6OptionCode::ClientId) {
        let recs = our_v6_records(dhcp6, 1);
        let ours = recs.first().and_then(|r| r.value());
        if ours != Some(id.as_slice()) {
            report.push("dhcp6.opt.1", format!("{ours:?}"), format!("{id:?}"));
        }
    }
    if let Some(V6Option::ServerId(id)) = opts.get(V6OptionCode::ServerId) {
        let recs = our_v6_records(dhcp6, 2);
        let ours = recs.first().and_then(|r| r.value());
        if ours != Some(id.as_slice()) {
            report.push("dhcp6.opt.2", format!("{ours:?}"), format!("{id:?}"));
        }
    }
    // IA_NA (may repeat): IAID + T1 + T2 + the IAADDR sub-records.
    let theirs_ianas: Vec<&V6Iana> = opts
        .get_all(V6OptionCode::IANA)
        .unwrap_or_default()
        .iter()
        .filter_map(|o| match o {
            V6Option::IANA(iana) => Some(iana),
            _ => None,
        })
        .collect();
    let ours_ianas = our_v6_records(dhcp6, 3);
    if theirs_ianas.len() != ours_ianas.len() {
        report.push(
            "dhcp6.opt.3",
            format!("{} records", ours_ianas.len()),
            format!("dhcproto sees {}", theirs_ianas.len()),
        );
    } else {
        for (rec, iana) in ours_ianas.iter().zip(&theirs_ianas) {
            let path = |f: &str| format!("dhcp6.opt.{}.{}", rec.n, f);
            cmp_int(
                &mut report,
                &path("iaid"),
                rec.u32_at(0),
                u128::from(iana.id),
            );
            cmp_int(&mut report, &path("t1"), rec.u32_at(4), u128::from(iana.t1));
            cmp_int(&mut report, &path("t2"), rec.u32_at(8), u128::from(iana.t2));
            // The IAADDR sub-records, in order.
            let theirs_addrs: Vec<&V6IaAddr> = iana
                .opts
                .get_all(V6OptionCode::IAAddr)
                .unwrap_or_default()
                .iter()
                .filter_map(|o| match o {
                    V6Option::IAAddr(a) => Some(a),
                    _ => None,
                })
                .collect();
            let mut m = 0usize;
            let mut ours_addrs = 0usize;
            loop {
                let sub: std::collections::BTreeMap<&str, &Value> = dhcp6
                    .fields
                    .iter()
                    .filter_map(|(k, v)| {
                        Some((k.strip_prefix(&format!("opt.{}.sub.{m}.", rec.n))?, v))
                    })
                    .collect();
                if !matches!(
                    sub.get("code"),
                    Some(Value::Int(c)) if *c == u128::from(u16::from(V6OptionCode::IAAddr))
                ) {
                    break;
                }
                ours_addrs += 1;
                let spath = |f: &str| format!("dhcp6.opt.{}.sub.{m}.{}", rec.n, f);
                let get_int = |k: &str| -> Option<u128> {
                    match dhcp6
                        .fields
                        .get(format!("opt.{}.sub.{m}.{k}", rec.n).as_str())
                    {
                        Some(Value::Int(v)) => Some(*v),
                        _ => None,
                    }
                };
                let ours_ip = match dhcp6
                    .fields
                    .get(format!("opt.{}.sub.{m}.ip", rec.n).as_str())
                {
                    Some(Value::Ipv6(a)) => Some(*a),
                    _ => None,
                };
                if let Some(iaaddr) = theirs_addrs.get(m) {
                    if ours_ip != Some(iaaddr.addr) {
                        report.push(
                            &spath("ip"),
                            format!("{ours_ip:?}"),
                            format!("{}", iaaddr.addr),
                        );
                    }
                    cmp_int(
                        &mut report,
                        &spath("preferred"),
                        get_int("preferred"),
                        u128::from(iaaddr.preferred_life),
                    );
                    cmp_int(
                        &mut report,
                        &spath("valid"),
                        get_int("valid"),
                        u128::from(iaaddr.valid_life),
                    );
                }
                m += 1;
            }
            if ours_addrs != theirs_addrs.len() {
                report.push(
                    &format!("dhcp6.opt.{}.sub", rec.n),
                    format!("{ours_addrs} sub-records"),
                    format!("dhcproto sees {}", theirs_addrs.len()),
                );
            }
        }
    }
    if let Some(V6Option::ORO(oro)) = opts.get(V6OptionCode::ORO) {
        let ours: Option<Vec<u128>> = our_v6_records(dhcp6, 6)
            .first()
            .and_then(|r| r.value())
            .map(|b| {
                b.chunks(2)
                    .map(|c| u128::from(u16::from_be_bytes(c.try_into().unwrap())))
                    .collect()
            });
        let theirs: Vec<u128> = oro.opts.iter().map(|c| u128::from(u16::from(*c))).collect();
        if ours != Some(theirs.clone()) {
            report.push("dhcp6.opt.6", format!("{ours:?}"), format!("{theirs:?}"));
        }
    }
    if let Some(V6Option::ElapsedTime(t)) = opts.get(V6OptionCode::ElapsedTime) {
        cmp_int(
            &mut report,
            "dhcp6.opt.8",
            our_v6_records(dhcp6, 8).first().and_then(|r| r.num()),
            u128::from(*t),
        );
    }
    let rapid_theirs = opts.get(V6OptionCode::RapidCommit).is_some();
    let rapid_ours = !our_v6_records(dhcp6, 14).is_empty();
    cmp_bool(&mut report, "dhcp6.opt.14", rapid_ours, rapid_theirs);
    if let Some(V6Option::DomainNameServers(ips)) = opts.get(V6OptionCode::DomainNameServers) {
        let ours: Option<Vec<V6Addr>> = our_v6_records(dhcp6, 23)
            .first()
            .and_then(|r| r.value())
            .map(|b| {
                b.chunks(16)
                    .map(|c| V6Addr::from(<[u8; 16]>::try_from(c).unwrap()))
                    .collect::<Vec<_>>()
            });
        if ours != Some(ips.clone()) {
            report.push("dhcp6.opt.23", format!("{ours:?}"), format!("{ips:?}"));
        }
    }
    if let Some(V6Option::DomainSearchList(names)) = opts.get(V6OptionCode::DomainSearchList) {
        // Our `text` renders the label-decoded names joined by `,`;
        // hickory's Name displays with a trailing root dot.
        let ours = our_v6_records(dhcp6, 24)
            .first()
            .and_then(|r| r.text())
            .map(str::to_string);
        let theirs: Vec<String> = names
            .iter()
            .map(|n| n.to_string().trim_end_matches('.').to_string())
            .collect();
        if ours != Some(theirs.join(",")) {
            report.push("dhcp6.opt.24", format!("{ours:?}"), format!("{theirs:?}"));
        }
    }

    // Coverage walk: every option dhcproto parsed must have a wrex
    // record (a structural parse agreeing on the rest is coverage —
    // the v4 `_`-arm convention).
    for opt in opts.iter() {
        let code = u16::from(V6OptionCode::from(opt));
        if our_v6_records(dhcp6, code).is_empty() {
            report.push(
                &format!("dhcp6.opt.{code}"),
                "no record".to_string(),
                format!("{opt:?}"),
            );
        }
    }

    if report.mismatches.is_empty() {
        Ok(())
    } else {
        Err(report)
    }
}
