//! Benchmark tripwires (pass-2): hot paths timed so performance
//! regressions are VISIBLE before release — not a gate (cargo bench
//! runs manually / nightly; the numbers land in the run logs).
//!
//! `cargo bench -p wrex-core` (criterion; dev-only dependency).
//!
//! **Release profile is a precondition**: the bench profile inherits
//! `release` (opt-level 3, debug-assertions/overflow-checks off) plus
//! the workspace `debug = 1`, so `perf` symbols resolve for free. A
//! dev-profile run (`cargo run --bench hotpaths`, `cargo test
//! --benches`) is *silently wrong*: debug-assertions and overflow
//! checks skew allocation-heavy paths worst — [`assert_release_profile`]
//! makes it fail loudly instead.

use std::hint::black_box;

use criterion::{Criterion, criterion_group};
use wrex_core::encode::{EncodeOpts, encode};
use wrex_core::patch::{Edit, Scope, patch};
use wrex_core::render::{dissect_to_jsonl, dissect_to_text};
use wrex_core::spec::{LayerSpec, PacketSpec};
use wrex_core::value::Value;
use wrex_core::{Filter, Registry, dissect};

/// Release-profile guard: dev-profile bench numbers are meaningless
/// (debug-assertions/overflow-checks stay on and skew allocation-heavy
/// paths worst), so refuse to run rather than emit misleading numbers.
/// A *runtime* panic — `cargo clippy/check --all-targets` compiles this
/// target under the dev profile and must keep passing.
fn assert_release_profile() {
    if cfg!(debug_assertions) {
        panic!(
            "hotpaths benches must run optimized: use `cargo bench -p wrex-core` \
             (bench profile inherits release). This binary was built with \
             debug-assertions on — its numbers are meaningless."
        );
    }
}

fn udp_frame_spec(payload_len: usize) -> PacketSpec {
    let mut eth = std::collections::BTreeMap::new();
    eth.insert("dst".into(), Value::Mac([0xff; 6]));
    eth.insert("src".into(), Value::Mac([0x11; 6]));
    let mut ip = std::collections::BTreeMap::new();
    ip.insert("src".into(), Value::Ipv4("127.0.0.1".parse().unwrap()));
    ip.insert("dst".into(), Value::Ipv4("127.0.0.1".parse().unwrap()));
    ip.insert("proto".into(), Value::Int(17));
    let mut udp = std::collections::BTreeMap::new();
    udp.insert("sport".into(), Value::Int(4444));
    udp.insert("dport".into(), Value::Int(53));
    PacketSpec::new(
        vec![
            LayerSpec::with_fields("eth", eth),
            LayerSpec::with_fields("ipv4", ip),
            LayerSpec::with_fields("udp", udp),
        ],
        Some(Value::Bytes(vec![0x42u8; payload_len].into())),
    )
}

fn corpus_frames(reg: &Registry) -> Vec<Vec<u8>> {
    // The committed corpus: the dissect-side workload (wrex replay on
    // captures; the differential suite's per-frame cost).
    let mut frames = Vec::new();
    // Only use wrex-test corpus if available at bench time (it is:
    // same workspace).
    for corpus in wrex_test::corpus::Corpus::load_all() {
        for f in &corpus.frames {
            frames.push(f.bytes.clone());
        }
    }
    // Fall back to a crafted frame if the corpus is missing.
    if frames.is_empty() {
        let enc = encode(
            reg,
            &udp_frame_spec(64),
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .expect("bench fixture encodes");
        frames.push(enc.bytes.to_vec());
    }
    frames
}

fn bench_encode(c: &mut Criterion) {
    let reg = wrex::standard();
    let spec = udp_frame_spec(512);
    let opts = EncodeOpts {
        autofill: true,
        ..Default::default()
    };
    c.bench_function("encode/eth-ipv4-udp+512", |b| {
        b.iter(|| {
            let _ = black_box(encode(black_box(&reg), black_box(&spec), black_box(&opts)));
        })
    });
}

fn bench_dissect(c: &mut Criterion) {
    let reg = wrex::standard();
    let enc = encode(
        &reg,
        &udp_frame_spec(512),
        &EncodeOpts {
            autofill: true,
            ..Default::default()
        },
    )
    .expect("bench fixture encodes");
    let frame = enc.bytes.to_vec();
    c.bench_function("dissect/eth-ipv4-udp+512", |b| {
        b.iter(|| {
            let _ = black_box(dissect(
                black_box(&reg),
                black_box(&frame),
                black_box("eth"),
            ));
        })
    });
}

fn bench_corpus_dissect(c: &mut Criterion) {
    let reg = wrex::standard();
    let frames = corpus_frames(&reg);
    let mut group = c.benchmark_group("dissect/corpus");
    group.throughput(criterion::Throughput::Bytes(
        frames.iter().map(|f| f.len() as u64).sum(),
    ));
    group.bench_function("all-frames", |b| {
        b.iter(|| {
            for f in black_box(&frames) {
                let _ = dissect(black_box(&reg), black_box(f), black_box("eth"));
            }
        })
    });
    group.finish();
}

fn bench_pcap_read(c: &mut Criterion) {
    // Classic + pcapng reader round trips over the corpus bytes.
    let frames = corpus_frames(&wrex::standard());
    let mut classic = Vec::new();
    {
        let mut w = wrex_pcap::PcapWriter::new(&mut classic).unwrap();
        for f in &frames {
            w.write_record(std::time::SystemTime::now(), f, 65535)
                .unwrap();
        }
    }
    let mut ng = Vec::new();
    {
        let mut w = wrex_pcap::PcapngWriter::new(&mut ng).unwrap();
        for f in &frames {
            w.write_record(std::time::SystemTime::now(), f, 65535)
                .unwrap();
        }
    }
    c.bench_function("pcap-read/classic-corpus", |b| {
        b.iter(|| {
            let _ = black_box(wrex_pcap::read(black_box(&classic)));
        })
    });
    c.bench_function("pcap-read/pcapng-corpus", |b| {
        b.iter(|| {
            let _ = black_box(wrex_pcap::read(black_box(&ng)));
        })
    });
}

fn bench_schema_walk(c: &mut Criterion) {
    // Tripwire (const-eval pass): the per-field schema walk every
    // dissect/encode drives — LayerSchema::field resolving a name over
    // the static (const-evaluated) field tables. The LazyLock form
    // paid a lazy-init branch + heap Vec per access.
    let reg = wrex::standard();
    let tcp = reg.get("tcp").expect("tcp registered").schema();
    let udp = reg.get("udp").expect("udp registered").schema();
    let ip = reg.get("ipv4").expect("ipv4 registered").schema();
    c.bench_function("schema/field-lookup", |b| {
        b.iter(|| {
            let mut hits = 0u64;
            for _ in 0..100 {
                if black_box(tcp.field(black_box("dport"))).is_some() {
                    hits += 1;
                }
                if black_box(udp.field(black_box("checksum"))).is_some() {
                    hits += 1;
                }
                if black_box(ip.field(black_box("ttl"))).is_some() {
                    hits += 1;
                }
            }
            black_box(hits);
        })
    });
    c.bench_function("schema/field-names-unique", |b| {
        // The const fn behind the per-codec uniqueness proof, over the
        // same static tables the tests assert.
        b.iter(|| {
            let mut ok = true;
            for s in black_box(&[tcp, udp, ip]) {
                for r in s.records.iter() {
                    ok &= wrex_core::schema::field_names_unique(r.fields);
                }
            }
            black_box(ok)
        })
    });
}

fn bench_checksum(c: &mut Criterion) {
    // Tripwire (const-eval pass): the RFC 1071 fold — now const (the
    // add_bytes index-loop rewrite vs the old as_chunks iterator form
    // is the codegen difference worth watching) and running per frame
    // on every proto write path.
    use wrex_core::ChecksumAccumulator;
    let frame = [0x45u8; 64];
    let header = [
        0x45u8, 0, 0, 0x40, 0, 0, 0, 0, 0x40, 17, 0, 0, 192, 168, 0, 1, 192, 168, 0, 2,
    ];
    c.bench_function("checksum/add-bytes-64", |b| {
        b.iter(|| {
            let mut acc = ChecksumAccumulator::new();
            acc.add_bytes(black_box(&frame));
            black_box(acc.value());
        })
    });
    c.bench_function("checksum/fold-header", |b| {
        b.iter(|| {
            let mut acc = ChecksumAccumulator::new();
            acc.add_bytes(black_box(&header));
            black_box(acc.value());
        })
    });
}

fn bench_render(c: &mut Criterion) {
    // The output side of the recv/replay hot loop: the renderers alone
    // over pre-dissected corpus packets. This isolates the field-string
    // materialization cost (JSON map keys, name formatting) from the
    // dissection cost, so the two budget halves can be compared.
    let reg = wrex::standard();
    let frames = corpus_frames(&reg);
    let packets: Vec<_> = frames
        .iter()
        .map(|f| dissect(black_box(&reg), black_box(f), black_box("eth")))
        .collect();
    let total: u64 = frames.iter().map(|f| f.len() as u64).sum();
    let mut g = c.benchmark_group("render");
    g.throughput(criterion::Throughput::Bytes(total));
    g.bench_function("jsonl-corpus", |b| {
        b.iter(|| {
            let mut n = 0usize;
            for p in black_box(&packets) {
                n += black_box(dissect_to_jsonl(black_box(p))).len();
            }
            black_box(n)
        })
    });
    g.bench_function("text-corpus", |b| {
        b.iter(|| {
            let mut n = 0usize;
            for p in black_box(&packets) {
                n += black_box(dissect_to_text(black_box(p))).len();
            }
            black_box(n)
        })
    });
    g.finish();
}

fn bench_recv(c: &mut Criterion) {
    // The end-to-end per-packet budget of `recv`/`replay` (jsonl default):
    // dissect + render in one iteration, mirroring the verbs loop.
    let reg = wrex::standard();
    let frames = corpus_frames(&reg);
    let total: u64 = frames.iter().map(|f| f.len() as u64).sum();
    let mut g = c.benchmark_group("recv");
    g.throughput(criterion::Throughput::Bytes(total));
    g.bench_function("jsonl-corpus", |b| {
        b.iter(|| {
            let mut n = 0usize;
            for f in black_box(&frames) {
                let p = dissect(black_box(&reg), black_box(f), black_box("eth"));
                n += black_box(dissect_to_jsonl(black_box(&p))).len();
            }
            black_box(n)
        })
    });
    g.finish();
}

fn bench_filter(c: &mut Criterion) {
    // Filter evaluation over pre-dissected corpus packets: the
    // `BTreeMap<String, _>` lookup path (`--filter` on `replay`/`recv`).
    // The filter parses once, outside the loop — parse cost is
    // per-invocation, not per-packet.
    let reg = wrex::standard();
    let filter = Filter::parse(
        black_box(&reg),
        black_box("ipv4.proto=17 udp.dport=53 ipv4.ttl>0"),
    )
    .expect("bench filter parses against the standard registry");
    let frames = corpus_frames(&reg);
    let packets: Vec<_> = frames
        .iter()
        .map(|f| dissect(black_box(&reg), black_box(f), black_box("eth")))
        .collect();
    let mut g = c.benchmark_group("filter");
    g.throughput(criterion::Throughput::Elements(packets.len() as u64));
    g.bench_function("matches-corpus", |b| {
        b.iter(|| {
            let mut hits = 0usize;
            for p in black_box(&packets) {
                if black_box(filter.matches(black_box(p))) {
                    hits += 1;
                }
            }
            black_box(hits)
        })
    });
    g.finish();
}

fn bench_patch(c: &mut Criterion) {
    // Tripwire (doctrine: verification.md "patch-engine ops — one bench
    // each"): one NAT-style `SetField` + `Scope::all` recompute walk per
    // packet. The engine itself (op resolution, scope selection,
    // reassemble) — the dissect half is benched separately above.
    let reg = wrex::standard();
    let frames = corpus_frames(&reg);
    let packets: Vec<_> = frames
        .iter()
        .map(|f| dissect(black_box(&reg), black_box(f), black_box("eth")))
        .collect();
    let edits = vec![
        Edit::SetField {
            path: "ipv4.ttl".to_string(),
            bytes: bytes::Bytes::from_static(&[64]),
        },
        Edit::SetField {
            path: "ipv4.src".to_string(),
            bytes: bytes::Bytes::from_static(&[127, 0, 0, 1]),
        },
    ];
    let mut g = c.benchmark_group("patch");
    g.throughput(criterion::Throughput::Elements(packets.len() as u64));
    g.bench_function("setfield+scope-all-corpus", |b| {
        b.iter(|| {
            let mut n = 0usize;
            for p in black_box(&packets) {
                if let Ok(out) = patch(
                    black_box(&reg),
                    black_box(p),
                    black_box(&edits),
                    black_box(&Scope::all()),
                ) {
                    n += black_box(out.len());
                }
            }
            black_box(n)
        })
    });
    g.finish();
}

fn bench_frame_retention(c: &mut Criterion) {
    // Tripwire: the byte-fidelity frame retention
    // (`Bytes::copy_from_slice` ×2 per packet: full frame + payload
    // region) at MTU scale. Retention only needs ownership — callers
    // hold a `Bytes` already — so this copy is a zero-copy-API
    // candidate; the bench marks its share of the unknown-layer
    // dissect cost as frames scale.
    let reg = wrex::standard();
    let frame_1500 = black_box(vec![0x42u8; 1500]);
    c.bench_function("retention/unknown-1500B", |b| {
        b.iter(|| {
            let mut n = 0usize;
            for _ in 0..100 {
                let p = dissect(
                    black_box(&reg),
                    black_box(&frame_1500),
                    black_box("unknown"),
                );
                n += black_box(p.frame.len());
            }
            black_box(n)
        })
    });
    let frame_9000 = black_box(vec![0x42u8; 9000]);
    c.bench_function("retention/unknown-9000B-jumbo", |b| {
        b.iter(|| {
            let mut n = 0usize;
            for _ in 0..100 {
                let p = dissect(
                    black_box(&reg),
                    black_box(&frame_9000),
                    black_box("unknown"),
                );
                n += black_box(p.frame.len());
            }
            black_box(n)
        })
    });
}

criterion_group!(
    benches,
    bench_encode,
    bench_dissect,
    bench_corpus_dissect,
    bench_render,
    bench_recv,
    bench_filter,
    bench_patch,
    bench_frame_retention,
    bench_pcap_read,
    bench_schema_walk,
    bench_checksum
);

fn main() {
    assert_release_profile();
    benches();
}
