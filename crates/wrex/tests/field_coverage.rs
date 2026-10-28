//! HP3-a field-coverage gates (`cargo test -- field_coverage`): the
//! schema as the completion oracle, over the real registry.
//!
//! - **G1** `g1_strategy_completeness`: every settable schema field
//!   appears in its codec's strategy output with a randomized value —
//!   the gate that would have caught the ipv4 mf bug at its first run
//!   (the strategy never sampled `flags`, so every compared frame had
//!   all flag bits zero and a bit-*position* error was invisible).
//!
//! Exemptions are recorded in
//! [`wrex_test::gates::STRATEGY_EXEMPT`](wrex_test::gates::STRATEGY_EXEMPT)
//! (with reasons) plus the by-construction sets (`Codec::derived`
//! names, dissect-only record sections); a failure here is a pointed
//! `kind.field: never randomized` list, never a blanket skip.

use wrex_test::gates::audit_strategy;

fn registry() -> wrex_core::Registry {
    wrex::standard()
}

/// G1: strategy completeness audit, retroactive over every codec with
/// a strategy in the standard registry.
#[test]
fn g1_strategy_completeness() {
    let reg = registry();
    let mut dirty = String::new();
    let mut audited = 0;
    for kind in reg.kinds() {
        // The audit returns None for strategy-less kinds (nothing to
        // audit — none exist in the standard registry today).
        if let Some(audit) = audit_strategy(&reg, kind, 512, 2) {
            audited += 1;
            if !audit.is_clean() {
                dirty.push_str(&audit.message());
            }
        }
    }
    assert!(
        audited >= 19,
        "expected every standard codec audited, got {audited}"
    );
    assert!(dirty.is_empty(), "G1 strategy-completeness audit:\n{dirty}");
}
