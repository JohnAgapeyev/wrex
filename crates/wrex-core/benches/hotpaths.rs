//! Benchmark tripwires (pass-2): hot paths timed so performance
//! regressions are VISIBLE before release — not a gate (cargo bench
//! runs manually / nightly; the numbers land in the run logs).
//!
//! `cargo bench -p wrex-core` (criterion; dev-only dependency).

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use wrex_core::encode::{EncodeOpts, encode};
use wrex_core::spec::{LayerSpec, PacketSpec};
use wrex_core::value::Value;
use wrex_core::{Registry, dissect};

fn udp_frame_spec(payload_len: usize) -> PacketSpec {
    let mut eth = std::collections::BTreeMap::new();
    eth.insert("dst".to_string(), Value::Mac([0xff; 6]));
    eth.insert("src".to_string(), Value::Mac([0x11; 6]));
    let mut ip = std::collections::BTreeMap::new();
    ip.insert("src".to_string(), Value::Ipv4("127.0.0.1".parse().unwrap()));
    ip.insert("dst".to_string(), Value::Ipv4("127.0.0.1".parse().unwrap()));
    ip.insert("proto".to_string(), Value::Int(17));
    let mut udp = std::collections::BTreeMap::new();
    udp.insert("sport".to_string(), Value::Int(4444));
    udp.insert("dport".to_string(), Value::Int(53));
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

criterion_group!(
    benches,
    bench_encode,
    bench_dissect,
    bench_corpus_dissect,
    bench_pcap_read
);
criterion_main!(benches);
