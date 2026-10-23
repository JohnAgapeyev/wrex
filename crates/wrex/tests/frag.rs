//! Tranche T18a gate (`cargo test -- frag`): the fragment reassembly
//! engine behind `wrex replay --reassemble`.
//!
//! The engine (`wrex-frag`) is pure; these gates run it against the
//! **real codec registry** — the ADR-3 child-side integration pattern:
//!
//! 1. kind-string pins (the engine's literals vs the codec `KIND`s);
//! 2. v4 reassembly round-trip: a hand-crafted unfragmented packet,
//!    split into wire-honest fragments, reassembles to the original
//!    IP packet byte-for-byte (the fixed-point oracle — the
//!    split/reassemble composition is the identity), and the
//!    reassembled packet re-dissects anomaly-free with the L4 checksum
//!    intact (the T11a preserve contract on the data path);
//! 3. v6 reassembly, direct (`ipv6→frag→udp`) and through a pre-frag
//!    hopopts chain — the unfragmentable part is the fixed header +
//!    the ext headers before `frag` (RFC 8200 §4.5), the byte that
//!    pointed at the frag header rewrites to the terminal protocol;
//! 4. out-of-order completion + incomplete/gap notes (data, exit 0);
//! 5. T11a byte-identity on the fragment frames themselves;
//! 6. the CLI door (`replay --reassemble`) end-to-end over a pcap;
//! 7. a `#[ignore]`d corpus generator (dev-time, the `corpus-import`
//!    pattern): writes the golden `frag` corpus the other gates sweep.
//!
//! Proptest-based parts are ignored under Miri.
#![cfg_attr(miri, ignore = "proptest; not Miri-safe")]

use std::net::{Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use wrex_core::Registry;
use wrex_core::dissect;
use wrex_core::dissect::DissectedPacket;
use wrex_core::encode::{EncodeOpts, encode};
use wrex_core::spec::{LayerSpec, PacketSpec};
use wrex_core::value::Value;
use wrex_frag::{FragInfo, Push, Reassembler, classify};

fn registry() -> Registry {
    wrex::standard()
}

fn encode_bytes(reg: &Registry, spec: PacketSpec) -> Vec<u8> {
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
    .to_vec()
}

/// The kind strings the engine matches on mirror the codec `KIND`s
/// (ADR 3) — pinned here so a rename fails a gate, not a runtime
/// mis-parse.
#[test]
fn kind_strings_pin_the_codecs() {
    assert_eq!(wrex_frag::KIND_IPV4, wrex_proto_ip::KIND);
    assert_eq!(wrex_frag::KIND_IPV6, wrex_proto_ip6::KIND);
    assert_eq!(wrex_frag::KIND_FRAG, wrex_proto_ip6ext::KIND_FRAG);
}

/// A hand-crafted unfragmented eth→ipv4→udp frame (deterministic: the
/// corpus generator reuses it).
fn v4_packet(payload: &[u8]) -> PacketSpec {
    let mut eth = LayerSpec::new("eth");
    eth.fields
        .insert("dst".into(), Value::Mac([0xaa, 1, 2, 3, 4, 5]));
    eth.fields
        .insert("src".into(), Value::Mac([0xbb, 6, 7, 8, 9, 10]));
    let mut ip = LayerSpec::new("ipv4");
    ip.fields
        .insert("src".into(), Value::Ipv4(Ipv4Addr::new(192, 0, 2, 1)));
    ip.fields
        .insert("dst".into(), Value::Ipv4(Ipv4Addr::new(192, 0, 2, 2)));
    ip.fields.insert("id".into(), Value::Int(0x1234));
    ip.fields.insert("ttl".into(), Value::Int(64));
    ip.fields.insert("proto".into(), Value::Int(17));
    let mut udp = LayerSpec::new("udp");
    udp.fields.insert("sport".into(), Value::Int(5353));
    udp.fields.insert("dport".into(), Value::Int(9999));
    PacketSpec::new(
        vec![eth, ip, udp],
        Some(Value::Bytes(bytes::Bytes::copy_from_slice(payload))),
    )
}

/// A hand-crafted unfragmented eth→ipv6→[ext…]→frag→udp frame.
fn v6_packet(hopopts: bool, payload: &[u8]) -> PacketSpec {
    let mut eth = LayerSpec::new("eth");
    eth.fields
        .insert("dst".into(), Value::Mac([0xaa, 1, 2, 3, 4, 5]));
    eth.fields
        .insert("src".into(), Value::Mac([0xbb, 6, 7, 8, 9, 10]));
    let mut ip = LayerSpec::new("ipv6");
    ip.fields
        .insert("src".into(), Value::Ipv6(Ipv6Addr::LOCALHOST));
    ip.fields.insert(
        "dst".into(),
        Value::Ipv6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
    );
    ip.fields.insert("hop_limit".into(), Value::Int(64));
    let mut layers = vec![eth, ip];
    if hopopts {
        let mut hopts = LayerSpec::new("hopopts");
        hopts.fields.insert(
            "options".into(),
            Value::Bytes(vec![0x1d, 0x04, 0, 0, 0, 0].into()), // Router Alert
        );
        layers.push(hopts);
    }
    let mut udp = LayerSpec::new("udp");
    udp.fields.insert("sport".into(), Value::Int(5353));
    udp.fields.insert("dport".into(), Value::Int(9999));
    layers.push(udp);
    PacketSpec::new(
        layers,
        Some(Value::Bytes(bytes::Bytes::copy_from_slice(payload))),
    )
}

/// Split a v4 packet's IP payload into wire-honest fragments: every
/// chunk but the last 8-byte aligned (RFC 791), per-fragment headers
/// patched (`total_len`, `mf`, `frag_off`; the checksum rides the
/// original bytes — per-fragment checksum patching is fragmentation
/// realism we do not need for the engine gate).
fn v4_fragments(frame: &[u8], split: usize) -> Vec<Vec<u8>> {
    let ip_start = 14usize; // eth
    let hdr = 20usize; // fixed ipv4 (no options)
    let payload = &frame[ip_start + hdr..];
    let chunks: &[&[u8]] = &[&payload[..split], &payload[split..]];
    let mut out = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        let mut f = frame[..ip_start + hdr].to_vec();
        let total = (hdr + chunk.len()) as u16;
        f[ip_start + 2] = (total >> 8) as u8;
        f[ip_start + 3] = total as u8;
        let last = i == chunks.len() - 1;
        let word = ((if last { 0u16 } else { 1u16 }) << 15) | ((split * i) / 8) as u16;
        f[ip_start + 6] = (word >> 8) as u8;
        f[ip_start + 7] = word as u8;
        f.extend_from_slice(chunk);
        out.push(f);
    }
    out
}

/// Carve wire-honest v6 fragments out of an UNFRAGMENTED packet (the
/// realistic direction — a real stream's frag0 carries an L4 header
/// whose checksum was folded over the whole original segment):
/// prefix = the unfragmentable part (fixed header + ext headers), each
/// fragment = prefix + a fresh frag header + an 8-aligned data slice,
/// per-fragment `next_header` → 44 and `payload_len` patched.
fn v6_fragments(frame: &[u8], p: &DissectedPacket, split: usize, ident: u32) -> Vec<Vec<u8>> {
    let ip6 = p.layers.iter().find(|l| l.kind == "ipv6").expect("ipv6");
    let l4 = p.layers.iter().find(|l| l.kind == "udp").expect("udp");
    let ip_start = ip6.span.start;
    let prefix = &frame[ip_start..l4.span.start];
    // The byte that points at the L4 layer (fixed header byte 6 when
    // frag rides directly, the last pre-L4 ext header's next_header
    // otherwise) becomes 44: every fragment routes through the frag
    // header.
    let nh_layer = p
        .layers
        .iter()
        .rfind(|l| {
            l.span.start >= ip_start
                && l.span.end <= l4.span.start
                && l.field_spans.contains_key("next_header")
        })
        .expect("a next_header carrier before the L4 layer");
    let nh_rel = match nh_layer.field_spans.get("next_header") {
        Some(wrex_core::dissect::FieldSpan::Bytes(r)) => r.start - ip_start,
        Some(wrex_core::dissect::FieldSpan::Bits { container, .. }) => container.start - ip_start,
        _ => unreachable!("next_header span"),
    };
    let terminal = 17u8; // udp
    let seg = &frame[l4.span.start..];
    let chunks: &[&[u8]] = &[&seg[..split], &seg[split..]];
    let mut out = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        let mut f = frame[..ip_start].to_vec();
        f.extend_from_slice(prefix);
        let plen = (prefix.len() - 40 + 8 + chunk.len()) as u16;
        f[ip_start + 4] = (plen >> 8) as u8;
        f[ip_start + 5] = plen as u8;
        f[ip_start + nh_rel] = 44; // the carrier byte -> frag
        let last = i == chunks.len() - 1;
        let units = (split * i) / 8;
        f.push(terminal);
        f.push(0);
        let word = ((units as u16) << 3) | if last { 0 } else { 1 };
        f.push((word >> 8) as u8);
        f.push(word as u8);
        f.extend_from_slice(&ident.to_be_bytes());
        f.extend_from_slice(chunk);
        out.push(f);
    }
    out
}

/// Feed a fragment stream (dissect → classify → push) in order; panics
/// on any push that is not the expected variant shape.
fn feed(reg: &Registry, frames: &[Vec<u8>], order: &[usize]) -> (Vec<Vec<u8>>, Vec<String>) {
    let mut re = Reassembler::default();
    let mut complete = Vec::new();
    for &i in order {
        let p = dissect(reg, &frames[i], "eth");
        let frag = classify(&p).unwrap_or_else(|| panic!("frame {i} did not classify"));
        match re.push(frag, i as u64) {
            Push::Complete(bytes) => complete.push(bytes),
            Push::Pending => {}
            Push::Overrun => panic!("unexpected overrun"),
        }
    }
    (complete, re.incomplete())
}

#[test]
fn v4_reassembles_to_the_original_packet() {
    let reg = registry();
    let payload: Vec<u8> = (0..24u8).collect();
    let frame = encode_bytes(&reg, v4_packet(&payload));
    let frags = v4_fragments(&frame, 8);
    assert_eq!(frags.len(), 2);
    let (complete, notes) = feed(&reg, &frags, &[0, 1]);
    assert!(notes.is_empty(), "{notes:?}");
    assert_eq!(complete.len(), 1);
    // Fixed-point oracle: split∘reassemble == identity on the IP packet
    // (the eth header never rides a v4 fragment reassembly).
    assert_eq!(complete[0], &frame[14..], "reassembled == original packet");
    // Re-dissection: anomaly-free, L4 checksum intact (the udp bytes
    // were never re-derived).
    let fresh = dissect(&reg, &complete[0], "auto");
    assert!(fresh.anomalies.is_empty(), "{:?}", fresh.anomalies);
    let kinds: Vec<&str> = fresh.layers.iter().map(|l| l.kind).collect();
    assert_eq!(kinds, ["ipv4", "udp"]);
    assert_eq!(&fresh.payload[..], &payload[..]);
}

#[test]
fn v4_out_of_order_and_gap_notes() {
    let reg = registry();
    let payload: Vec<u8> = (0..24u8).collect();
    let frame = encode_bytes(&reg, v4_packet(&payload));
    let frags = v4_fragments(&frame, 8);
    // Terminal fragment first: pending until the offset-0 carrier.
    let (complete, _) = feed(&reg, &frags, &[1, 0]);
    assert_eq!(complete.len(), 1);
    assert_eq!(complete[0], &frame[14..]);
    // Fragments at a coarser split: still complete (a different carve).
    let coarse = v4_fragments(&frame, 16);
    let (complete2, notes2) = feed(&reg, &coarse, &[0, 1]);
    assert_eq!(complete2.len(), 1);
    assert!(notes2.is_empty());
    // A real gap: feed only fragments that leave a hole.
    let mut re = Reassembler::default();
    let p0 = dissect(&reg, &frags[0], "eth");
    let f0: FragInfo = classify(&p0).expect("classify");
    re.push(f0, 0);
    let p1 = dissect(&reg, &coarse[1], "eth");
    let f1: FragInfo = classify(&p1).expect("classify");
    re.push(f1, 1);
    assert_eq!(re.len(), 1);
    let notes = re.incomplete();
    assert!(notes.iter().any(|n| n.contains("incomplete datagram")));
}

#[test]
fn v6_reassembles_direct_and_through_hopopts() {
    let reg = registry();
    let payload: Vec<u8> = (0..40u8).collect();
    for hopopts in [false, true] {
        // The original is UNFRAGMENTED (the realistic carving
        // direction): reassembly must reproduce it exactly.
        let frame = encode_bytes(&reg, v6_packet(hopopts, &payload));
        let p = dissect(&reg, &frame, "eth");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        let frags = v6_fragments(&frame, &p, 16, 0x5151);
        assert_eq!(frags.len(), 2);
        let (complete, notes) = feed(&reg, &frags, &[1, 0]);
        assert!(notes.is_empty(), "{notes:?}");
        assert_eq!(complete.len(), 1, "hopopts={hopopts}");
        // Fixed point: reassemble(carve(original)) == original[14..]
        // (the eth header never rides a v6 reassembly) — the frag header
        // vanishes, the next-header byte that pointed at it restores,
        // payload_len recomputes to the original value.
        assert_eq!(complete[0], &frame[14..], "hopopts={hopopts}");
        // Re-dissection: clean chain, L4 checksum intact.
        let fresh = dissect(&reg, &complete[0], "auto");
        assert!(fresh.anomalies.is_empty(), "{:?}", fresh.anomalies);
        let kinds: Vec<&str> = fresh.layers.iter().map(|l| l.kind).collect();
        if hopopts {
            assert_eq!(kinds, ["ipv6", "hopopts", "udp"]);
        } else {
            assert_eq!(kinds, ["ipv6", "udp"]);
        }
        assert_eq!(&fresh.payload[..], &payload[..]);
    }
}

#[test]
fn fragment_frames_reassemble_byte_identically() {
    // T11a on the fragment path: every wire-honest fragment frame
    // dissects and re-stitches to itself.
    let reg = registry();
    let payload: Vec<u8> = (0..24u8).collect();
    let v4f = v4_fragments(&encode_bytes(&reg, v4_packet(&payload)), 8);
    let v6p = v6_packet(false, &(0..40u8).collect::<Vec<_>>());
    let frame = encode_bytes(&reg, v6p);
    let p = dissect(&reg, &frame, "eth");
    let v6f = v6_fragments(&frame, &p, 16, 0x5151);
    for f in v4f.iter().chain(v6f.iter()) {
        let d = dissect(&reg, f, "eth");
        assert_eq!(&d.reassemble()[..], &f[..]);
    }
}

proptest! {

    /// Never-panic + deterministic completion over random split points
    /// and arrival orders of a real v4 packet.
    #[test]
    fn v4_random_split_order_never_panics(
        unit in 1usize..6,
        order in proptest::collection::vec(any::<bool>(), 0..8),
    ) {
        let split = unit * 8; // frag_off is 8-byte units: aligned splits only
        let reg = registry();
        let payload: Vec<u8> = (0..48u8).collect();
        let frame = encode_bytes(&reg, v4_packet(&payload));
        let frags = v4_fragments(&frame, split);
        let mut idx: Vec<usize> = (0..frags.len()).collect();
        for flip in order {
            if flip && idx.len() > 1 {
                let n = idx.len();
                idx.swap(0, n - 1);
            }
        }
        let (complete, _) = feed(&reg, &frags, &idx);
        prop_assert_eq!(complete.len(), 1);
        prop_assert_eq!(&complete[0], &frame[14..]);
    }
}

// --- CLI door -----------------------------------------------------------------

fn cmd() -> std::process::Command {
    std::process::Command::new(env!("CARGO_BIN_EXE_wrex"))
}

#[test]
fn replay_reassembles_over_pcap() {
    let reg = registry();
    let payload: Vec<u8> = (0..24u8).collect();
    let frame = encode_bytes(&reg, v4_packet(&payload));
    let frags = v4_fragments(&frame, 8);
    let dir = std::env::temp_dir().join(format!("wrex-t18a-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("frags.pcap");
    {
        let file = std::fs::File::create(&path).expect("create");
        let mut w = wrex_pcap::PcapWriter::new(std::io::BufWriter::new(file)).expect("writer");
        for (i, f) in frags.iter().enumerate() {
            let ts = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1000 + i as u64);
            w.write_record(ts, f, 65535).expect("write");
        }
        w.flush().expect("flush");
    }
    // Default replay prints the two fragment dissections.
    let plain = cmd()
        .args(["replay", path.to_str().unwrap(), "--format", "jsonl"])
        .output()
        .expect("spawn wrex");
    assert!(plain.status.success(), "plain replay: {plain:?}");
    let out = String::from_utf8(plain.stdout).expect("utf8");
    assert_eq!(out.lines().count(), 2, "two fragment frames");
    // --reassemble: one reassembled jsonl line, the udp layer present.
    let reassembled = cmd()
        .args([
            "replay",
            path.to_str().unwrap(),
            "--reassemble",
            "--format",
            "jsonl",
        ])
        .output()
        .expect("spawn wrex");
    assert!(reassembled.status.success(), "{reassembled:?}");
    let stdout = String::from_utf8(reassembled.stdout).expect("utf8");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "fragments consumed: {stdout}");
    assert!(
        lines[0].contains("\"udp\""),
        "reassembled udp chain: {}",
        lines[0]
    );
    // -i IFACE is a usage error with --reassemble (exit 2).
    let usage = cmd()
        .args(["replay", path.to_str().unwrap(), "--reassemble", "-i", "lo"])
        .output()
        .expect("spawn wrex");
    assert_eq!(
        usage.status.code(),
        Some(2),
        "--reassemble -i must be usage exit 2"
    );
}

// --- corpus generator (dev-time) ------------------------------------------------

/// Regenerate the golden `frag` corpus (the `corpus-import` pattern,
/// hand-built frames instead of a capture): `cargo test -p wrex --test
/// frag -- --ignored generate_frag_corpus` then commit the outputs.
#[test]
#[ignore = "dev-time corpus generator"]
fn generate_frag_corpus() {
    let reg = registry();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../wrex-test/corpus/frag");
    let frames_dir = root.join("frames");
    std::fs::create_dir_all(&frames_dir).expect("mkdir");
    let v4payload: Vec<u8> = (0..24u8).collect();
    let v4frame = encode_bytes(&reg, v4_packet(&v4payload));
    let v4frags = v4_fragments(&v4frame, 8);
    let v6payload: Vec<u8> = (0..40u8).collect();
    let v6frame = encode_bytes(&reg, v6_packet(true, &v6payload));
    let v6p = dissect(&reg, &v6frame, "eth");
    let v6frags = v6_fragments(&v6frame, &v6p, 16, 0x5151);
    let mut names = Vec::new();
    let mut all: Vec<Vec<u8>> = Vec::new();
    all.extend(v4frags);
    all.extend(v6frags);
    for (i, bytes) in all.iter().enumerate() {
        let name = format!("{:02}", i + 1);
        std::fs::write(frames_dir.join(format!("{name}.bin")), bytes).expect("write bin");
        let packet = dissect(&reg, bytes, "eth");
        let expected = serde_json::to_string_pretty(&wrex_core::render::dissect_to_json(&packet))
            .expect("json");
        std::fs::write(
            frames_dir.join(format!("{name}.expected.json")),
            expected + "\n",
        )
        .expect("write json");
        names.push(name);
    }
    let manifest = format!(
        "source_url = \"handcrafted (wrex tests/frag.rs generator, tranche T18a)\"\nimported = \"2026-10-23\"\nstart = \"auto\"\nframes = {names:?}\n"
    );
    std::fs::write(root.join("manifest.toml"), manifest).expect("write manifest");
}

#[test]
fn capture_pcapng_ns_requires_pcapng() {
    // Tranche T18b: --pcapng-ns without --pcapng is a usage error (2).
    let out = cmd()
        .args(["capture", "-w", "/dev/null", "--pcapng-ns"])
        .output()
        .expect("spawn wrex");
    assert_eq!(out.status.code(), Some(2), "{out:?}");
}
