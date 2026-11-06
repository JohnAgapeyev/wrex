//! The userspace-eBPF-VM differential (tranche 23b/c, the per-commit
//! semantic gate): generated programs vs the reference engines, over
//! the golden corpora — no kernel needed. The filter engine is the
//! spec (Kani-proved comparison core, fuzzed since hardening pass 2),
//! so an agreement here is the "verifier-clean" analog the CI can run
//! everywhere; the live attach is env-gated in the driver suites.
//!
//! Oracles, per the inversion rule (never diff against the thing
//! wrapped): the wrex filter engine for verdicts, the T14 patch engine
//! for translator byte-identity (the incremental RFC 1624 fold vs the
//! full recompute — equal for same-width in-place edits), and the
//! engine's own dissect-side verify for the responder.

use wrex_core::filter::Filter;
use wrex_core::{Edit, Registry, Value, patch};
use wrex_ebpf::{self as ebpf, vm};

fn registry() -> Registry {
    wrex::standard()
}

/// Every golden corpus frame + the foreign fixtures: the differential
/// corpus. Raw reads stay byte-identical through `dissect --start`,
/// so frames pair naturally.
fn corpus_frames() -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    for corpus in wrex_test::corpus::Corpus::load_all() {
        for frame in &corpus.frames {
            frames.push(frame.bytes.clone());
        }
    }
    frames
}

/// Run a compiled filter program against a frame, asserting the
/// compile succeeded.
fn verdict(reg: &Registry, expr: &str, frame: &[u8]) -> vm::Verdict {
    let f = Filter::parse(reg, expr).expect("filter parses");
    let prog = match ebpf::compile_capture_prefilter(reg, &f) {
        Ok(p) => p,
        // Pointed compile errors are PART of the differential: the
        // subset's boundary must stay where the tests pin it.
        Err(e) => {
            panic!("filter `{expr}` must compile: {e}");
        }
    };
    let mut machine = vm::Vm::new_default();
    machine.declare_program_maps(&prog);
    machine.maps.set(ebpf::MAP_IDX_XSK, &0u32.to_le_bytes(), 1);
    machine
        .run(&prog, frame)
        .expect("VM runs a generated program")
}

fn engine_matches(reg: &Registry, expr: &str, frame: &[u8]) -> bool {
    let start = wrex_core::dissect::auto_start(frame);
    let p = wrex_core::dissect::dissect(reg, frame, start);
    Filter::parse(reg, expr).unwrap().matches(&p)
}

/// The verdict differential over every corpus frame: the compiled
/// program's redirect/pass == the filter engine's true/false, for a
/// battery spanning every supported term shape (scalar int ops, CIDR
/// both families, MAC, flag aggregates + bits, hex prefix) and every
/// walk depth (eth / vlan / ipv4 / ipv6 / tcp / udp / icmp).
#[test]
fn filter_verdict_differential_over_corpora() {
    let reg = registry();
    let frames = corpus_frames();
    assert!(frames.len() > 50, "corpora must feed the differential");

    let exprs = [
        // L2
        "eth.type=0x0800",
        "eth.type!=0x0806",
        "eth.dst=ff:ff:ff:ff:ff:ff",
        "eth.src=00:11:22:33:44:55",
        // L3 v4
        "ipv4.ttl=64",
        "ipv4.ttl>32",
        "ipv4.ttl<=64",
        "ipv4.ttl<64",
        "ipv4.ttl>=64",
        "ipv4.proto=17",
        "ipv4.src=127.0.0.1",
        "ipv4.src=10.0.0.0/8",
        "ipv4.src!=10.0.0.0/8",
        "ipv4.src=0.0.0.0/0",
        "ipv4.dst=192.168.0.0/16",
        "ipv4.flags=mf",
        // L3 v6
        "ipv6.hop_limit=1",
        "ipv6.src=::1",
        "ipv6.src=2001:db8::/32",
        "ipv6.src=::/0",
        "ipv6.next_header=17",
        // L4
        "tcp.dport=80",
        "tcp.dport=443",
        "tcp.flags=syn",
        "tcp.flags.syn=true",
        "tcp.flags.syn=false",
        "tcp.flags.ack=true",
        "tcp.window>100",
        "udp.dport=53",
        "udp.sport<1024",
        "udp.length>=8",
        "icmp.type=8",
        // conjunctions across depths
        "eth.type=0x0800 ipv4.proto=6 tcp.flags=syn",
        "ipv4.src=10.0.0.0/8 tcp.dport=80",
        "ipv6.next_header=58",
        // families that never co-occur (the always-fallback shape)
        "ipv4.src=1.2.3.4 ipv6.src=::1",
        "tcp.dport=80 udp.dport=53",
    ];
    let mut compared = 0usize;
    for expr in exprs {
        for frame in &frames {
            let want = engine_matches(&reg, expr, frame);
            let got = matches!(verdict(&reg, expr, frame), vm::Verdict::Redirect);
            assert_eq!(
                got,
                want,
                "filter `{expr}` diverged on a {}-byte frame: {}",
                frame.len(),
                hex::encode(&frame[..frame.len().min(40)]),
            );
            compared += 1;
        }
    }
    assert!(compared > 1000, "the differential must be exercised");
}

/// The empty-frame pin (the live verifier's first lesson): a compiled
/// program on a ZERO-LENGTH packet (data == data_end) must return a
/// clean verdict, never a VM Bounds error — the first live review
/// rejected the `ptr + need - 1` bounds pattern for letting the last
/// read byte sit AT data_end; the VM differential had missed it
/// because no corpus frame puts a read boundary there. The VM is the
/// executor, the verifier proves for ALL frames — this pin closes the
/// gap for the degenerate frame the verifier cares about most.
#[test]
fn empty_packet_yields_clean_verdicts_never_bounds() {
    let reg = registry();
    for expr in [
        "eth.type=0x0800",
        "udp.dport=53",
        "tcp.flags.syn=true",
        "ipv4.src=10.0.0.0/8",
        "ipv6.src=2001:db8::/32",
        "",
    ] {
        let f = Filter::parse(&reg, expr).unwrap();
        let prog = ebpf::compile_capture_prefilter(&reg, &f).unwrap();
        let mut machine = vm::Vm::new_default();
        machine.declare_program_maps(&prog);
        machine.maps.set(ebpf::MAP_IDX_XSK, &0u32.to_le_bytes(), 1);
        let got = machine.run(&prog, b"");
        assert!(
            got.is_ok(),
            "`{expr}` on an empty packet must resolve cleanly (got {got:?})"
        );
    }
}

/// The boundary-length sweep (the systematic form of the live
/// verifier's two lessons): a compiled program must resolve CLEANLY
/// (a verdict, never a VM Bounds error) on frames of EVERY length
/// 0..=60 — both live rejections hid in the corpus gap (no corpus
/// frame is empty, and none ends exactly at the eth/L3 boundary, so
/// the unchecked nibble read and the off-by-one bounds pattern never
/// fired in the differential). The verifier proves for ALL frames;
/// this sweep pins the same class in the per-commit executor.
#[test]
fn boundary_length_sweep_never_bounds() {
    let reg = registry();
    for expr in [
        "eth.type=0x0800",
        "eth.dst=ff:ff:ff:ff:ff:ff",
        "udp.dport=53",
        "udp.sport<1024",
        "tcp.dport=443",
        "tcp.flags.syn=true",
        "tcp.flags=ack",
        "ipv4.ttl=64",
        "ipv4.src=10.0.0.0/8",
        "ipv6.hop_limit=1",
        "ipv6.src=2001:db8::/32",
        "",
    ] {
        let f = Filter::parse(&reg, expr).unwrap();
        let prog = ebpf::compile_capture_prefilter(&reg, &f).unwrap();
        let mut machine = vm::Vm::new_default();
        machine.declare_program_maps(&prog);
        machine.maps.set(ebpf::MAP_IDX_XSK, &0u32.to_le_bytes(), 1);
        for len in 0..=60usize {
            // Pattern families, not one zero-fill: the reads are
            // position-driven but the WALK is value-gated — the zero
            // frame's family nibble is 0, so it never reaches the v4/v6
            // arms and the ext chain was dead code under the first
            // sweep (the verifier's third live lesson hid in exactly
            // that gap). Each family drives one arm:
            for pattern in [
                vec![0u8; len],           // zeros: the L2/eth arm
                vec![0x60; len],          // 0x60-fill: the raw-v6 arm
                b"\x60\x00\x00\x00\x00\x00\x00\x00".to_vec(), // raw v6, next 0 = hopopts → the ext chain
                b"\x45\x00\x00\x00\x00\x00\x00\x00".to_vec(),  // raw v4: the ihl walk
                b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x86\xdd\x60\x00\x00\x00\x00\x00\x00\x00"
                    .to_vec(),            // eth+v6: the eth walk into the v6 arm
                b"\xff\xff\xff\xff\xff\xff\x00\x11\x22\x33\x44\x55\x08\x00\x45\x00\x00\x00\x00\x00\x00\x00"
                    .to_vec(),            // eth+v4: the eth walk into the ihl arm
            ] {
                let mut frame = pattern.clone();
                frame.resize(len, 0);
                let got = machine.run(&prog, &frame);
                assert!(
                    got.is_ok(),
                    "`{expr}` on a {len}-byte {pattern:?} frame must resolve cleanly (got {got:?})"
                );
            }
        }
    }
}

/// The pointed-error boundary: terms the kernel subset cannot express
/// refuse compilation (record sections, Str fields, u64+ ints, layers
/// outside the walk) — never a silent wrong answer. The userspace
/// engine still evaluates them; the capture path falls back.
#[test]
fn pointed_compile_errors_stay_pointed() {
    let reg = registry();
    for expr in [
        "dns.an.0.name=example.com",
        "dns.qd.0.type=1",
        "dhcp6.msg_type=solicit",
        "sll.pkttype=outgoing",
        "dot11.duration=5",
        "ipv4.options=hex:01010100",
        "tcp.opt.0.kind=mss",
    ] {
        let f = Filter::parse(&reg, expr).unwrap_or_else(|e| panic!("{expr}: {e}"));
        let err = ebpf::compile_capture_prefilter(&reg, &f)
            .expect_err("the subset must refuse this term");
        assert!(
            matches!(
                err,
                ebpf::CompileError::UnsupportedField { .. }
                    | ebpf::CompileError::UnsupportedValue { .. }
                    | ebpf::CompileError::UnsupportedLayer { .. }
            ),
            "{expr}: {err}"
        );
    }
}

/// The translator differential: for same-width in-place edits, the
/// incremental RFC 1624 fold (compiled) and the T14 engine's full
/// recompute are byte-identical — `wrex patch --set` semantics,
/// transposed to XDP. Crafted frames across both families.
#[test]
fn translator_byte_identity_vs_patch_engine() {
    let reg = registry();
    let mk = |layers: &[&'static str], payload: &[u8]| -> Vec<u8> {
        let spec_layers: Vec<wrex_core::spec::LayerSpec> = layers
            .iter()
            .map(|l| wrex_core::spec::LayerSpec::new(l))
            .collect();
        let spec = wrex_core::spec::PacketSpec::new(
            spec_layers,
            Some(Value::Bytes(payload.to_vec().into())),
        );
        wrex_core::encode::encode(
            &reg,
            &spec,
            &wrex_core::encode::EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap()
        .bytes
        .to_vec()
    };
    let frames = [
        mk(&["eth", "ipv4", "udp"], &[0xaa, 0xbb, 0xcc]),
        mk(&["eth", "ipv4", "tcp"], &[0x01, 0x02, 0x03, 0x04]),
        mk(&["eth", "ipv4", "icmp"], &[0xde, 0xad]),
        mk(&["eth", "ipv6", "udp"], &[0x11, 0x22]),
        mk(&["eth", "ipv6", "tcp"], &[0x33, 0x44, 0x55]),
    ];
    // (path, wire bytes of the new value).
    let cases: &[(&str, &[u8])] = &[
        ("udp.dport", &[0x35, 0x00]),
        ("tcp.dport", &[0x35, 0x00]),
        ("tcp.window", &[0x05, 0x00]),
        ("ipv4.ttl", &[0x07]),
        ("ipv4.tos", &[0x28]),
        ("ipv6.hop_limit", &[0x09]),
        ("udp.sport", &[0x04, 0xd2]),
    ];
    let checksum_at = |kind: &str| -> Option<usize> {
        reg.get(kind)?
            .layouts()
            .iter()
            .find_map(|(n, l)| match (*n, *l) {
                ("checksum", wrex_core::schema::Layout::Bytes { at, .. }) => Some(at),
                _ => None,
            })
    };
    let mut checked = 0usize;
    for frame in &frames {
        let start = wrex_core::dissect::auto_start(frame);
        let packet = wrex_core::dissect::dissect(&reg, frame, start);
        let present: Vec<&str> = packet.layers.iter().map(|l| l.kind).collect();
        for (path, bytes) in cases {
            let (kind, field) = path.split_once('.').unwrap();
            if !present.contains(&kind) {
                continue;
            }
            // Engine side.
            let edits = [Edit::SetField {
                path: (*path).to_string(),
                bytes: bytes::Bytes::copy_from_slice(bytes),
            }];
            let Ok(engine_out) = patch(&reg, &packet, &edits, &wrex_core::Scope::all()) else {
                continue; // the field is absent/short in this frame
            };
            // Translator side: layer-relative layout offset (compiled
            // artifacts of the schema), checksums per the engine's
            // Scope::all policy for the edited stack.
            let Some((at, width)) = reg.get(kind).and_then(|c| {
                c.layouts()
                    .iter()
                    .find(|(n, _)| *n == field)
                    .map(|(_, l)| match l {
                        wrex_core::schema::Layout::Bytes { at, len } => (*at, *len),
                        _ => (0usize, 0usize),
                    })
            }) else {
                continue;
            };
            if width != bytes.len() {
                continue; // not a same-width case for this layout
            }
            // The checksum policy the engine's Scope::all applies:
            // ipv4.checksum ← ipv4-header edits; the l4 checksums ←
            // own-layer edits + the pseudo-header's src/dst, with the
            // CONTRIBUTION list naming which edits feed each fold
            // (ttl/hop_limit do NOT feed the l4 pseudo-header — the
            // engine leaves the l4 checksum untouched there).
            let mut checksums = Vec::new();
            match kind {
                "ipv4" => checksums.push(ebpf::ChecksumTarget {
                    kind: "ipv4",
                    at: checksum_at("ipv4").expect("ipv4 checksum layout"),
                    contrib: vec![0],
                }),
                "ipv6" | "tcp" | "udp" => {}
                _ => {}
            }
            let l4 = if present.contains(&"tcp") {
                Some("tcp")
            } else if present.contains(&"udp") {
                Some("udp")
            } else {
                None
            };
            let feeds_l4 = match kind {
                "tcp" | "udp" => true,
                "ipv4" | "ipv6" => matches!(field, "src" | "dst"),
                _ => false,
            };
            if feeds_l4 && let Some(l4k) = l4 {
                checksums.push(ebpf::ChecksumTarget {
                    kind: l4k,
                    at: checksum_at(l4k).expect("l4 checksum layout"),
                    contrib: vec![0],
                });
            }
            let prog = ebpf::compile_translate(
                &reg,
                &[ebpf::Edit {
                    kind,
                    at,
                    width,
                    value: bytes.to_vec(),
                }],
                &checksums,
            )
            .unwrap_or_else(|e| panic!("translate {path}: {e}"));
            let mut machine = vm::Vm::new_default();
            let out = machine
                .run_with_packet(&prog, frame)
                .expect("VM runs the translator");
            assert_eq!(
                out,
                engine_out.to_vec(),
                "translator diverged from the engine on {path} ({} bytes)",
                frame.len()
            );
            checked += 1;
        }
    }
    assert!(
        checked >= 10,
        "the translator differential must be exercised"
    );
}

/// The responder: an engine-crafted echo request replies with a
/// checksum-valid echo reply (the engine's own dissect-side verify is
/// the oracle — zero anomalies on the reply).
#[test]
fn responder_reply_dissects_clean() {
    let reg = registry();
    let spec = wrex_core::spec::PacketSpec::new(
        vec![
            wrex_core::spec::LayerSpec::new("eth"),
            wrex_core::spec::LayerSpec::new("ipv4"),
            wrex_core::spec::LayerSpec::new("icmp"),
        ],
        Some(Value::Bytes(vec![0xaa, 0xbb, 0xcc, 0xdd].into())),
    );
    let frame = wrex_core::encode::encode(
        &reg,
        &spec,
        &wrex_core::encode::EncodeOpts {
            autofill: true,
            ..Default::default()
        },
    )
    .unwrap()
    .bytes
    .to_vec();
    let prog = ebpf::compile_responder();
    let mut machine = vm::Vm::new_default();
    let out = machine
        .run_with_packet(&prog, &frame)
        .expect("responder runs");
    // The reply dissects as an echo reply with a VALID checksum (the
    // verify anomaly list is empty).
    let p = wrex_core::dissect::dissect(&reg, &out, "eth");
    let icmp = p.layers.iter().find(|l| l.kind == "icmp").expect("icmp");
    assert_eq!(
        icmp.fields.get("type"),
        Some(&Value::Int(0)),
        "the responder must flip the type to 0"
    );
    assert!(
        p.anomalies.is_empty(),
        "the reply must carry a valid checksum: {:?}",
        p.anomalies
    );
}

/// The ACL shape: match ⇒ DROP, everything else passes — the same
/// verdict differential, complement action.
#[test]
fn acl_drop_verdicts() {
    let reg = registry();
    let frames = corpus_frames();
    let f = Filter::parse(&reg, "tcp.dport=22").unwrap();
    let prog = ebpf::compile_acl(&reg, &f).unwrap();
    let mut machine = vm::Vm::new_default();
    machine.declare_program_maps(&prog);
    for frame in frames.chunks(64).flat_map(|c| c.iter()) {
        let want = engine_matches(&reg, "tcp.dport=22", frame);
        let got = matches!(machine.run(&prog, frame).unwrap(), vm::Verdict::Drop);
        assert_eq!(got, want, "acl diverged on a {}-byte frame", frame.len());
    }
}

/// The flow table: v4 TCP/UDP frames count once per 4-tuple, others
/// pass through uncounted.
#[test]
fn flow_table_counts_four_tuples() {
    let reg = registry();
    let spec = |proto: &'static str, sport: u16, dport: u16| -> Vec<u8> {
        let mut layers = vec![
            wrex_core::spec::LayerSpec::new("eth"),
            wrex_core::spec::LayerSpec::new("ipv4"),
            wrex_core::spec::LayerSpec::new(proto),
        ];
        if let Some(l) = layers.last_mut() {
            l.fields.insert("sport".into(), Value::Int(sport as u128));
            l.fields.insert("dport".into(), Value::Int(dport as u128));
        }
        let ps = wrex_core::spec::PacketSpec::new(layers, None);
        wrex_core::encode::encode(
            &reg,
            &ps,
            &wrex_core::encode::EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap()
        .bytes
        .to_vec()
    };
    let prog = ebpf::compile_flow_table();
    let mut machine = vm::Vm::new_default();
    machine.declare_program_maps(&prog);
    // Two frames of one flow, one of another, one non-flow (icmp).
    for _ in 0..3 {
        machine.run(&prog, &spec("tcp", 1234, 80)).unwrap();
    }
    machine.run(&prog, &spec("tcp", 5555, 443)).unwrap();
    machine.run(&prog, &spec("icmp", 0, 0)).unwrap();
    // The counts live in the VM's map store.
    let mut total = 0u64;
    let mut entries = 0;
    for (k, v) in machine.maps.dump(ebpf::MAP_IDX_FLOW) {
        // tcp keys: proto byte 6 at offset 8.
        if k.get(8) == Some(&6) {
            total += v;
            entries += 1;
        }
    }
    assert_eq!(entries, 2, "two distinct tcp flows counted");
    assert_eq!(total, 4, "3x flow A + 1x flow B");
}
