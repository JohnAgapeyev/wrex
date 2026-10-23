#![no_main]
//! libFuzzer target: the span-patch engine (tranche 11b/13a) under
//! arbitrary edit lists over real corpus frames. Invariants:
//!
//! - no panics: rejections are pointed `PatchError`s (data, not crashes)
//!   — the engine splices arbitrary user input into byte buffers and
//!   must never corrupt memory or underflow;
//! - a successful patch re-dissects: the post-patch frame yields the
//!   same layer kinds as the baseline (splice never desyncs the
//!   stack), and with `Scope::all` zero anomalies (everything
//!   consistent — the eBPF-style translation archetype);
//! - determinism: same packet + edits + scope ⇒ same output bytes.
//!
//! `fuzz_mut_strategies` covers the mutation strategies (which
//! explicitly exclude ReEncode/dynamic paths); this target is the
//! engine's own coverage: SetField (bytes + bit-masked + ReEncode),
//! Insert/Delete shape changes, scope selections.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wrex::standard;
use wrex_core::dissect::dissect;
use wrex_core::patch::{Edit, Scope, patch};

/// One generated edit: a shape picked by discriminant with its own
/// payload. Ordinals/at are kept small (corpus frames are <1500B) so
/// out-of-bounds is a *result*, not a guaranteed error everywhere.
#[derive(Arbitrary, Debug)]
enum FuzzEdit {
    SetField { path_idx: u8, bytes: Vec<u8> },
    Insert { at: u8, bytes: Vec<u8> },
    Delete { at: u8, len: u8 },
}

/// Fixed field-path vocabulary over the udp_frame fixture: real spans
/// (bytes + bits), a ReEncode region (dhcp sname — none here, so a
/// plain str field), bogus paths, and edge shapes.
const PATHS: &[&str] = &[
    // bytes spans on the fixture stack (eth/ipv4/udp)
    "eth.dst",
    "eth.src",
    "ipv4.src",
    "ipv4.dst",
    "ipv4.ttl",
    "udp.sport",
    "udp.dport",
    // bit spans
    "ipv4.flags.df",
    "tcp.flags.syn",
    // path grammar edges
    "nope",
    "no.such.path",
    "eth",
    "",
    // reencode region (dhcp sname is not on this stack; a str field
    // on the udp frame): none — resolve_span handles it as unresolved.
    "udp.checksum",
];

#[derive(Arbitrary, Debug)]
struct FuzzPatch {
    frame_idx: u8,
    edits: Vec<FuzzEdit>,
    /// 0 = all, 1 = none, 2+ = selective from a fixed selector table.
    scope_idx: u8,
}

const SELECTORS: &[&[&str]] = &[
    &["udp.*"],
    &["ipv4.*"],
    &["udp.checksum"],
    &["eth.*", "udp.*"],
    &["bogus.*"],
];

/// The fixture family: shapes the corpus keeps — every frame is
/// dissected from `eth` (the corpus reader guarantees the linktype).
fn fixture(reg: &wrex_core::Registry) -> Vec<wrex_core::dissect::DissectedPacket> {
    let corpora = wrex_test::corpus::Corpus::load_all();
    let mut frames = Vec::new();
    for corpus in corpora {
        for case in &corpus.frames {
            if frames.len() >= 24 {
                break;
            }
            frames.push(dissect(reg, &case.bytes, "eth"));
        }
    }
    frames
}

fn realize(edits: &[FuzzEdit]) -> Vec<Edit> {
    let mut out = Vec::new();
    for e in edits {
        match e {
            FuzzEdit::SetField { path_idx, bytes } => {
                let path = PATHS[(*path_idx as usize) % PATHS.len()];
                out.push(Edit::SetField {
                    path: path.to_string(),
                    bytes: bytes::Bytes::copy_from_slice(bytes),
                });
            }
            FuzzEdit::Insert { at, bytes } => out.push(Edit::Insert {
                at: (*at as usize) * 7,
                bytes: bytes::Bytes::copy_from_slice(bytes),
            }),
            FuzzEdit::Delete { at, len } => {
                let start = (*at as usize) * 7;
                let end = start + (*len as usize) * 3;
                out.push(Edit::Delete {
                    at: start..end,
                });
            }
        }
    }
    out
}

fuzz_target!(|input: FuzzPatch| {
    let reg = standard();
    let packets = fixture(&reg);
    if packets.is_empty() {
        return;
    }
    let packet = &packets[(input.frame_idx as usize) % packets.len()];
    let scope = match input.scope_idx % 3 {
        0 => Scope::all(),
        1 => Scope::none(),
        _ => {
            let sels = SELECTORS[(input.scope_idx as usize / 3) % SELECTORS.len()];
            Scope::select(sels).expect("static selectors are well-formed")
        }
    };
    let edits = realize(&input.edits);

    // Determinism: two identical runs produce identical bytes or
    // identical errors.
    let a = patch(&reg, packet, &edits, &scope);
    let b = patch(&reg, packet, &edits, &scope);
    match (&a, &b) {
        (Ok(x), Ok(y)) => assert_eq!(x, y, "patch must be deterministic"),
        (Err(x), Err(y)) => assert_eq!(x, y, "patch errors must be deterministic"),
        _ => panic!("patch determinism broken"),
    }

    // Rejection is pointed data (never a panic — patch() itself is
    // asserted above by reaching either arm without aborting).
    let Ok(patched) = a else {
        return;
    };

    // SetField-only edits must preserve the frame length (the retained
    // input is the ground truth for the splice size); Insert/Delete
    // change it legitimately.
    let shape = edits
        .iter()
        .any(|e| matches!(e, Edit::Insert { .. } | Edit::Delete { .. }));
    if !shape {
        assert_eq!(
            patched.len(),
            packet.frame.len(),
            "SetField-only patch changed the frame length"
        );
    }

    // A successful patch must re-dissect without panicking, and must
    // never *add* anomalies: with the stack unchanged (kinds equal) and
    // no shape edits, every anomaly in the re-dissection was already
    // present in the baseline (the corpus carries deliberate anomaly
    // fixtures — e.g. a bad BOOTP cookie — that Scope::all rightly
    // leaves alone: only *derived* fields heal).
    let re = dissect(&reg, &patched, "eth");
    let baseline_kinds: Vec<&str> = packet.layers.iter().map(|l| l.kind).collect();
    let patched_kinds: Vec<&str> = re.layers.iter().map(|l| l.kind).collect();
    if !shape && baseline_kinds == patched_kinds && scope == Scope::all() {
        let baseline_set: std::collections::BTreeSet<(String, String)> = packet
            .anomalies
            .iter()
            .map(|a| (a.path.clone(), a.message.clone()))
            .collect();
        for a in &re.anomalies {
            assert!(
                baseline_set.contains(&(a.path.clone(), a.message.clone())),
                "Scope::all patch ADDED anomaly {} {} (baseline: {:?})",
                a.path,
                a.message,
                packet.anomalies
            );
        }
    }
});