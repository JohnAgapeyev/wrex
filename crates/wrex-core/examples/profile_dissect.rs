//! TEMPORARY profiling fixture (removed after perf run): the corpus
//! dissect workload in a plain loop, for `perf record -e cycles:u`.
use std::hint::black_box;
use wrex_core::{Registry, dissect};

fn main() {
    let reg: Registry = wrex::standard();
    let mut frames = Vec::new();
    for corpus in wrex_test::corpus::Corpus::load_all() {
        for f in &corpus.frames {
            frames.push(f.bytes.clone());
        }
    }
    assert!(!frames.is_empty(), "corpus frames loaded");
    let mut n = 0usize;
    for _ in 0..2000 {
        for f in black_box(&frames) {
            let p = dissect(black_box(&reg), black_box(f), black_box("eth"));
            n += black_box(p.layers.len());
        }
    }
    eprintln!("dissected layers total: {n}");
}
