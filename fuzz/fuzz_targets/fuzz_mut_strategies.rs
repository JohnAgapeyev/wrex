#![no_main]
//! libFuzzer target: arbitrary bytes + strategy picks drive the
//! mutation engine. Invariants: no panics, a mutant is always
//! produced (never empty), and the stream stays deterministic per
//! (seed, strategy) pair.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wrex::standard;
use wrex_mut::{Mutator, Strategy};

/// A strategy index into the concrete pick set (field/len/flip/splice/
/// raw/all — splice degrades to a flip on single seeds).
#[derive(Arbitrary, Debug)]
struct FuzzMutate {
    seeds: Vec<Vec<u8>>,
    strategy_idx: u8,
    seed: u64,
    rounds: u8,
}

const STRATEGIES: [Strategy; 6] = [
    Strategy::Field,
    Strategy::Len,
    Strategy::Flip,
    Strategy::Splice,
    Strategy::Raw,
    Strategy::All,
];

fuzz_target!(|input: FuzzMutate| {
    // Empty seeds are a construction error (the CLI's usage path);
    // empty-vec seeds are legal mutants of nothing — skip both noise
    // shapes but keep zero-length seed BYTES in play.
    let seeds: Vec<Vec<u8>> = input
        .seeds
        .iter()
        .map(|s| if s.is_empty() { vec![0u8] } else { s.clone() })
        .collect();
    if seeds.is_empty() {
        return;
    }
    let registry = standard();
    let strategy = STRATEGIES[(input.strategy_idx as usize) % STRATEGIES.len()];
    let mut a = Mutator::new(&registry, seeds.clone(), strategy, input.seed)
        .expect("non-empty seeds");
    let mut b = Mutator::new(&registry, seeds, strategy, input.seed).expect("twin");

    let rounds = 1 + (input.rounds as usize).min(32);
    for _ in 0..rounds {
        let m = a.next_mutant();
        assert!(!m.is_empty(), "mutants are never empty");
        // Determinism: a same-seeded twin produces the same stream.
        assert_eq!(m, b.next_mutant(), "mutant streams must match per seed");
    }
});