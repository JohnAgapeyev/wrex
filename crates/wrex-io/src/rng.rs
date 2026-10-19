//! Seeded jitter source: in-house SplitMix64 (from the SplitMix paper).
//!
//! No `rand` dependency — the workspace stays RNG-free and probe/query
//! identities and schedules are bit-reproducible under a pinned seed.
//! Tranche 3 moves it here from wrex-scan: it is sans-IO IO vocabulary
//! now that two tranches need it (scan identities, DNS query ids).

use std::time::Duration;

/// SplitMix64 state. Deterministic per seed; not cryptographically
/// secure (it does not need to be — the seed is user-controlled).
#[derive(Clone, Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// New generator from a seed.
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Next raw 64-bit value (SplitMix64 mix).
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform-ish `f64` in `[0, 1)` (top 53 bits).
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    /// Uniform value in `lo..=hi` (empty range → `lo`).
    pub fn range_u16(&mut self, lo: u16, hi: u16) -> u16 {
        if hi <= lo {
            return lo;
        }
        lo + (self.next_u64() % (hi - lo + 1) as u64) as u16
    }

    /// Signed jitter offset in seconds, uniform in `[-jitter, +jitter]`.
    pub fn jitter_secs(&mut self, jitter: Duration) -> f64 {
        if jitter.is_zero() {
            return 0.0;
        }
        (self.next_f64() * 2.0 - 1.0) * jitter.as_secs_f64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_per_seed() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        let mut c = Rng::new(43);
        assert_ne!(a.next_u64(), c.next_u64());
    }

    #[test]
    fn f64_in_unit_range() {
        let mut r = Rng::new(7);
        for _ in 0..1000 {
            let v = r.next_f64();
            assert!((0.0..1.0).contains(&v), "{v}");
        }
    }

    #[test]
    fn jitter_bounds() {
        let mut r = Rng::new(11);
        for _ in 0..1000 {
            let off = r.jitter_secs(Duration::from_millis(500));
            assert!((-0.5..=0.5).contains(&off), "{off}");
        }
        assert_eq!(r.jitter_secs(Duration::ZERO), 0.0);
    }
}
