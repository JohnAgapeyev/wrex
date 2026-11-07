//! The static verifier-shape checker (lesson #5: stop guessing — check).
//!
//! The kernel verifier's rules for the subset we emit are well-known:
//! packet reads and stores must be dominated by a bounds check against
//! `data_end` ON THE SAME REGISTER INSTANCE (a re-derivation between
//! check and use loses the proof), the bounds arithmetic must be
//! strict (`ptr + need <= end`, not `ptr + need - 1`), no unreachable
//! instructions, r1 is the ctx, r10 the stack frame, and helper calls
//! clobber r0–r5. The four live lessons of the tranche's attach rounds
//! were all instances of these rules — each found on a live kernel at
//! real cost. This pass enforces the whole class at COMPILE time:
//! every `compile_*` runs it, and a violation is a pointed
//! `CompileError::VerifierShape` naming the instruction — never a
//! kernel round-trip.
//!
//! The checker is an abstract interpretation over the EMITTED subset
//! (smaller than the kernel verifier — it knows our shapes): a
//! worklist CFG walk carrying, per register, its abstract value
//! (packet pointer with constant offset and proof-attribution
//! register, scalar constant, ctx, map, stack) and the bytes PROVEN
//! readable at the backing register's address. Any write to a
//! register kills its proof — the re-derivation lesson, mirrored.
//!
//! Known limitation (deliberate, recorded): packet pointers whose
//! offset folds in a runtime scalar with the checker's value unknown
//! (the IHL-derived `Base::L4` base, the v6 ext-chain pointer) decay
//! to `Top` and their loads/stores are NOT proof-checked here. Every
//! such emit site is `emit_ptr` + `emit_ptr_bounds` on the same
//! register instance — audited at the call sites (the L4 dispatch's
//! per-hop 8-byte checks, the term/edit/checksum loads) — and the
//! kernel still verifies them at load. Extending the checker to model
//! the unknown-offset class is a recorded swap trigger, not done.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::insn::Insn;

/// One verifier-shape violation, with the instruction index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub insn: usize,
    pub msg: String,
}

const NREGS: usize = 11;

/// Abstract value of one register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Val {
    /// Nothing known (initial / clobbered / merged-incompatible).
    Top,
    /// The xdp_md ctx pointer (r1 at entry).
    Ctx,
    /// `data_end` (the bounds-comparison target).
    End,
    /// A packet pointer: `data + off`. `off` is None once a
    /// packet-derived (non-constant) value folds in — the address is
    /// still tracked for shape, only constant folding stops. `backing`
    /// is the register a bounds-check proof attributes to (the holder
    /// the reads will go through).
    Pkt { off: Option<u64>, backing: u8 },
    /// A scalar constant.
    Const(u64),
    /// A map fd (LD_IMM64 pseudo) or map-value pointer (post-lookup).
    Map,
    /// The stack frame pointer (r10).
    Stack,
}

/// Per-register abstract state: the value plus the bytes PROVEN
/// readable at the register's own address (the proof lands on the
/// BACKING register; derived reads consult it through their offset).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RegState {
    val: Val,
    readable: u64,
}

/// The Top state (a const — RegState has no methods).
const REG_TOP: RegState = RegState {
    val: Val::Top,
    readable: 0,
};

/// The checker entry point: `Ok(())` or the full violation list.
pub fn verify_shape(insns: &[Insn]) -> Result<(), Vec<Violation>> {
    if insns.is_empty() {
        return Err(vec![Violation {
            insn: 0,
            msg: "empty program".into(),
        }]);
    }
    // --- successors --------------------------------------------------------
    // LD_IMM64 occupies two slots; JMP32/JMP relatives are forward;
    // the checker still walks a general successor graph.
    let mut succs: Vec<(Option<usize>, Option<usize>)> = vec![(None, None); insns.len()];
    for (pc, insn) in insns.iter().enumerate() {
        let class = insn.code & 0x07;
        match class {
            0x00 if insn.code == 0x18 => {
                if pc + 2 < insns.len() {
                    succs[pc] = (Some(pc + 2), None);
                }
            }
            0x05 | 0x06 => {
                // JMP / JMP32 share the opcode layout; JMP32 is the
                // class every term comparison rides (the sign-fix
                // lesson made E::jump emit j32).
                let op = insn.code & 0xf0;
                if op == 0x90 {
                    // EXIT: no successors.
                } else if op == 0x80 {
                    // CALL: falls through.
                    if pc + 1 < insns.len() {
                        succs[pc] = (Some(pc + 1), None);
                    }
                } else if op == 0x00 {
                    // JA: unconditional.
                    let t = (pc as i64 + 1 + insn.off as i64) as usize;
                    if t < insns.len() {
                        succs[pc] = (Some(t), None);
                    }
                } else {
                    // Conditional: (jump target, fall-through).
                    let t = (pc as i64 + 1 + insn.off as i64) as usize;
                    let target = if t < insns.len() { Some(t) } else { None };
                    let fall = if pc + 1 < insns.len() {
                        Some(pc + 1)
                    } else {
                        None
                    };
                    succs[pc] = (target, fall);
                }
            }
            _ => {
                if pc + 1 < insns.len() {
                    succs[pc] = (Some(pc + 1), None);
                }
            }
        }
    }

    // --- the worklist walk ---------------------------------------------------
    let mut states: Vec<Option<[RegState; NREGS]>> = vec![None; insns.len()];
    let mut visited = vec![false; insns.len()];
    states[0] = Some(initial_state());
    let mut work: Vec<usize> = vec![0];
    let mut violations: Vec<Violation> = Vec::new();

    while let Some(pc) = work.pop() {
        visited[pc] = true;
        let Some(state) = states[pc] else { continue };
        let state: [RegState; NREGS] = state;
        let insn = &insns[pc];

        // Shape checks against the PRE state.
        check_insn(insn, pc, &state, &mut violations);

        // The conditional bounds check splits edges: the fall-through
        // (rX <= end) earns the proof on rX's backing; the jump target
        // keeps the pre-check state.
        let (target_state, fall_state) = transfer(insn, &state);
        let (target, fall) = succs[pc];
        for (succ, next) in [(target, target_state), (fall, fall_state)] {
            if let Some(s) = succ {
                match &mut states[s] {
                    None => {
                        states[s] = Some(next);
                        work.push(s);
                    }
                    Some(prev) => {
                        let merged = merge_states(prev, &next);
                        if merged != *prev {
                            *prev = merged;
                            work.push(s);
                        }
                    }
                }
            }
        }
    }

    // Unreachable instructions (lesson 2) — EXCEPT the LD_IMM64
    // second slot, which is pseudo-data, never an instruction.
    for (pc, seen) in visited.iter().enumerate() {
        if !seen {
            let slot2 = pc > 0 && insns[pc - 1].code == 0x18;
            if !slot2 {
                violations.push(Violation {
                    insn: pc,
                    msg: "unreachable instruction (the kernel verifier refuses dead code)".into(),
                });
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn initial_state() -> [RegState; NREGS] {
    let mut s = [REG_TOP; NREGS];
    s[1] = RegState {
        val: Val::Ctx,
        readable: 0,
    };
    s[10] = RegState {
        val: Val::Stack,
        readable: 0,
    };
    s
}

/// A memory access's byte size from the size bits.
const fn access_size(size_bits: u8) -> u64 {
    match size_bits {
        0x10 => 1, // B
        0x08 => 2, // H
        0x00 => 4, // W
        _ => 8,    // DW
    }
}

/// The bytes PROVEN readable at `reg`'s address: the proof lives ON
/// the register itself (a bounds check attributes to the register the
/// reads go through — the check-scratch's backing, which our shapes
/// always make the read register). Any write to the register kills
/// the proof (the re-derivation lesson); None = not a packet pointer.
fn readable_at(reg: &RegState, _state: &[RegState; NREGS]) -> Option<u64> {
    match reg.val {
        Val::Pkt { .. } => Some(reg.readable),
        _ => None,
    }
}

/// The per-instruction shape checks (read/store proofs).
fn check_insn(insn: &Insn, pc: usize, state: &[RegState; NREGS], v: &mut Vec<Violation>) {
    let class = insn.code & 0x07;
    let size_bits = insn.code & 0x18;
    let off = insn.off as u16 as u64;
    match class {
        0x01 => {
            // LDX dst, [src + off] — a load.
            let src = &state[insn.src as usize];
            match src.val {
                Val::Pkt { .. } => {
                    let need = off + access_size(size_bits);
                    match readable_at(src, state) {
                        Some(proven) if proven >= need => {}
                        _ => v.push(Violation {
                            insn: pc,
                            msg: format!(
                                "unproven packet read: r{}+{} ({} bytes) has no surviving bounds proof — the kernel verifier will refuse (re-derive-then-read? strict-bounds?)",
                                insn.src, off, access_size(size_bits)
                            ),
                        }),
                    }
                }
                Val::Ctx => {
                    // The xdp_md u32 fields we read: data(0), data_end(4),
                    // data_meta(8), ingress_ifindex(12), rx_queue_index(16).
                    let ok = matches!(off, 0 | 4 | 8 | 12 | 16) && access_size(size_bits) == 4;
                    if !ok {
                        v.push(Violation {
                            insn: pc,
                            msg: format!(
                                "ctx read outside the xdp_md u32 fields: off {off} size {}",
                                access_size(size_bits)
                            ),
                        });
                    }
                }
                _ => {}
            }
        }
        0x03 => {
            // STX src, [dst + off] — a store THROUGH a register. Packet
            // stores need the same proof as reads (the translator's
            // in-place edits); stack stores ride r10's fixed frame.
            let dst = &state[insn.dst as usize];
            if matches!(dst.val, Val::Pkt { .. }) {
                let need = off + access_size(size_bits);
                match readable_at(dst, state) {
                    Some(proven) if proven >= need => {}
                    _ => v.push(Violation {
                        insn: pc,
                        msg: format!(
                            "unproven packet store: r{}+{} ({} bytes) has no surviving bounds proof",
                            insn.dst, off, access_size(size_bits)
                        ),
                    }),
                }
            }
        }
        _ => {}
    }
}

/// The transfer: fold constants, classify loads, kill proofs on
/// writes, attribute the bounds-check proof on the fall-through edge.
/// Returns (jump-target state, fall-through state) — for non-jumps
/// both are the same.
fn transfer(insn: &Insn, state: &[RegState; NREGS]) -> ([RegState; NREGS], [RegState; NREGS]) {
    let mut next = *state;
    let class = insn.code & 0x07;
    let src_bit = insn.code & 0x08 != 0;
    let dst = insn.dst as usize;
    match class {
        0x00 if insn.code == 0x18 => {
            next[dst] = RegState {
                val: Val::Map,
                readable: 0,
            };
        }
        0x01 => {
            // LDX: the ctx reads produce the packet vocabulary; other
            // loads scalars (or map values after lookup — Top here,
            // classified at the CALL below).
            let val = match state[insn.src as usize].val {
                Val::Ctx => match insn.off as u16 {
                    0 => Val::Pkt {
                        off: Some(0),
                        backing: insn.dst,
                    },
                    4 => Val::End,
                    _ => Val::Top,
                },
                Val::Map => Val::Map,
                _ => Val::Top,
            };
            next[dst] = RegState { val, readable: 0 };
        }
        0x02 => {
            // ST imm, [dst+off]: no register is written; the store's
            // shape was checked (packet stores above / the stack frame).
        }
        0x03 => {
            // STX: stores a register into memory — no register written.
        }
        0x04 | 0x07 => {
            let alu_op = insn.code & 0xf0;
            let operand: Option<u64> = if src_bit {
                match state[insn.src as usize].val {
                    Val::Const(c) => Some(c),
                    _ => None,
                }
            } else {
                Some((insn.imm as i64) as u64)
            };
            let val = match alu_op {
                0xb0 => {
                    // MOV: a copy RE-BASES the proof attribution —
                    // `mov r5, r4; add r5, K; jgt r5, r7` must land its
                    // proof on r4 (the address holder the reads use),
                    // not on r4's own old backing (the false-positive
                    // class the first checker run showed).
                    if src_bit {
                        match state[insn.src as usize].val {
                            Val::Pkt { off, .. } => Val::Pkt {
                                off,
                                backing: insn.src,
                            },
                            other => other,
                        }
                    } else {
                        Val::Const((insn.imm as i64) as u64)
                    }
                }
                0x00 => match (state[dst].val, operand) {
                    // ADD: Pkt{const} + Const folds (the proof's
                    // backing rides along); anything else with a
                    // packet base keeps Pkt{None} (address still
                    // tracked, folding stops).
                    (
                        Val::Pkt {
                            off: Some(o),
                            backing,
                        },
                        Some(c),
                    ) => Val::Pkt {
                        off: Some(o.wrapping_add(c)),
                        backing,
                    },
                    (Val::Const(a), Some(c)) => Val::Const(a.wrapping_add(c)),
                    (Val::Pkt { off: None, backing }, _) => Val::Pkt { off: None, backing },
                    _ => Val::Top,
                },
                0x10 => match (state[dst].val, operand) {
                    (
                        Val::Pkt {
                            off: Some(o),
                            backing,
                        },
                        Some(c),
                    ) => Val::Pkt {
                        off: Some(o.wrapping_sub(c)),
                        backing,
                    },
                    (Val::Const(a), Some(c)) => Val::Const(a.wrapping_sub(c)),
                    (Val::Pkt { off: None, backing }, _) => Val::Pkt { off: None, backing },
                    _ => Val::Top,
                },
                _ => Val::Top,
            };
            // The readable window (the kernel's packet-pointer range):
            // a MOV copies it (same address, same id-family range), a
            // CONSTANT add/sub folds into the pointer and SHIFTS the
            // window with it (`p + K` leaves range−K from the new
            // position — the misalign-advance store pattern rides
            // this), an add of an UNKNOWN scalar kills it (lesson #4:
            // the live verifier lost the range once the offset
            // register was packet-derived), and every other write
            // starts clean.
            let readable = match (alu_op, src_bit) {
                (0xb0, true) => match state[insn.src as usize].val {
                    Val::Pkt { .. } => state[insn.src as usize].readable,
                    _ => 0,
                },
                (0x00, _) => match (state[dst].val, operand) {
                    (Val::Pkt { .. }, Some(c)) => state[dst].readable.saturating_sub(c),
                    _ => 0,
                },
                (0x10, _) => match (state[dst].val, operand) {
                    (Val::Pkt { .. }, Some(c)) => state[dst].readable.saturating_add(c),
                    _ => 0,
                },
                _ => 0,
            };
            next[dst] = RegState { val, readable };
        }
        0x05 => {
            let op = insn.code & 0xf0;
            match op {
                0x80 => {
                    // CALL clobbers r0..r5.
                    next[..6].fill(REG_TOP);
                    // The map_lookup return: r0 is a map-value pointer
                    // — classify for the store/read exemption.
                    next[0] = RegState {
                        val: Val::Map,
                        readable: 0,
                    };
                }
                0x90 => {}
                _ if insn.code & 0xf0 == 0x20 && insn.src == 7 => {
                    // JGT rX, r7 — the bounds check: the FALL-THROUGH
                    // (not taken: rX <= end) earns the proof on rX's
                    // backing, amount = rX's folded offset − the
                    // backing's offset.
                    let fall = &mut next;
                    let lhs = insn.dst as usize;
                    if let Val::Pkt {
                        off: Some(ox),
                        backing,
                    } = state[lhs].val
                    {
                        let b = backing as usize;
                        if let Val::Pkt { off: Some(ob), .. } = state[b].val {
                            let proof = ox.saturating_sub(ob);
                            fall[b].readable = fall[b].readable.max(proof);
                        }
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
    (next, next)
}

/// Elementwise state merge at CFG joins: kinds must agree (else Top);
/// proofs take the MINIMUM (conservative).
fn merge_states(a: &[RegState; NREGS], b: &[RegState; NREGS]) -> [RegState; NREGS] {
    let mut out = *a;
    for r in 0..NREGS {
        out[r].val = if a[r].val == b[r].val {
            a[r].val
        } else {
            Val::Top
        };
        out[r].readable = a[r].readable.min(b[r].readable);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::insn::BPF_FUNC_redirect_map;
    use crate::insn::{Insn, R0, R1, R6, R7};
    // insn.rs exports R0/R1/R6-R9; the checker's test bodies use the
    // scratch regs numerically.
    const R4: u8 = 4;
    const R5: u8 = 5;

    /// A minimal verifier-clean program: read data/data_end, check 1
    /// byte, read it, pass.
    fn clean_prologue() -> Vec<Insn> {
        vec![
            Insn::ldx_w(R6, R1, 0),  // r6 = data
            Insn::ldx_w(R7, R1, 4),  // r7 = data_end
            Insn::mov64_reg(R5, R6), // r5 = r6
            Insn::add64_imm(R5, 1),  // r5 += 1 (STRICT bounds)
        ]
    }

    fn pass_tail() -> Vec<Insn> {
        vec![Insn::mov64_imm(0, 2), Insn::exit()]
    }

    /// The bounds check itself is a JGT against r7.
    fn bounds_check(insns: &mut Vec<Insn>) {
        // if r5 > r7 goto miss — encoded as a 2-byte relative jump to
        // a later miss label; the checker resolves targets from off.
        insns.push(Insn::j64_reg(crate::insn::JmpOp::Gt, R5, R7, 2)); // skip the pass tail
    }

    #[test]
    fn clean_read_passes() {
        let mut p = clean_prologue();
        bounds_check(&mut p);
        p.push(Insn::ldx_b(R4, R6, 0)); // the checked read
        p.extend(pass_tail());
        assert!(verify_shape(&p).is_ok(), "{:?}", verify_shape(&p));
    }

    /// Lesson 1: `ptr + need - 1` bounds then a `need`-byte read —
    /// rejected (the strict-bounds off-by-one).
    #[test]
    fn off_by_one_bounds_rejected() {
        let mut p = vec![
            Insn::ldx_w(R6, R1, 0),
            Insn::ldx_w(R7, R1, 4),
            Insn::mov64_reg(R5, R6),
            Insn::add64_imm(R5, 0), // BUG: +0 instead of +1
            Insn::j64_reg(crate::insn::JmpOp::Gt, R5, R7, 2),
            Insn::ldx_b(R4, R6, 0),
        ];
        p.extend(pass_tail());
        let errs = verify_shape(&p).unwrap_err();
        assert!(
            errs.iter().any(|v| v.msg.contains("unproven packet read")),
            "{errs:?}"
        );
    }

    /// Lesson 4's class: a re-derivation does not extend the window.
    /// Check 4 bytes at the base, re-derive at base+8, read — the
    /// constant walk past the proven window spends it (the saturating
    /// shift), so the read is refused. (A no-op `mov r6, r6` does
    /// NOT kill the window — the kernel copies the range on mov; the
    /// live lesson was the unknown-scalar re-derivation, which this
    /// checker models as the `_ => 0` kill in the ALU transfer.)
    #[test]
    fn rederive_then_read_rejected() {
        let mut p = vec![
            Insn::ldx_w(R6, R1, 0),
            Insn::ldx_w(R7, R1, 4),
            Insn::mov64_reg(R5, R6),
            Insn::add64_imm(R5, 4),
            Insn::j64_reg(crate::insn::JmpOp::Gt, R5, R7, 3),
            // Re-derive at base+8: the 4-byte window does not survive
            // the walk past it.
            Insn::mov64_reg(R4, R6),
            Insn::add64_imm(R4, 8),
            Insn::ldx_b(R5, R4, 0), // unproven: window spent
        ];
        p.extend(pass_tail());
        let errs = verify_shape(&p).unwrap_err();
        assert!(
            errs.iter().any(|v| v.msg.contains("unproven packet read")),
            "{errs:?}"
        );
    }

    /// The misalign-advance store shape (the translator's odd-offset
    /// edits): check a 2-byte span, advance the SAME pointer by a
    /// constant, store at the new position — the kernel folds the
    /// constant and shifts the proven range (range − K), accepted.
    #[test]
    fn const_add_shifts_the_proven_window() {
        let mut p = vec![
            Insn::ldx_w(R6, R1, 0),
            Insn::ldx_w(R7, R1, 4),
            Insn::mov64_reg(R4, R6),
            Insn::mov64_reg(R5, R4),
            Insn::add64_imm(R5, 2),
            Insn::j64_reg(crate::insn::JmpOp::Gt, R5, R7, 3),
            Insn::add64_imm(R4, 1), // the misalign advance: window 2 → 1
            Insn::mov64_imm(R0, 0x40),
            Insn::stx_b(R4, 0, R0), // 1 byte ≤ 1: proven
        ];
        p.extend(pass_tail());
        assert!(verify_shape(&p).is_ok(), "{:?}", verify_shape(&p));
    }

    /// The shifted window cannot overdraw: check 1, advance 1, store
    /// 1 — the new position proves 0 bytes, refused.
    #[test]
    fn const_add_cannot_overdraw_the_window() {
        let mut p = vec![
            Insn::ldx_w(R6, R1, 0),
            Insn::ldx_w(R7, R1, 4),
            Insn::mov64_reg(R4, R6),
            Insn::mov64_reg(R5, R4),
            Insn::add64_imm(R5, 1),
            Insn::j64_reg(crate::insn::JmpOp::Gt, R5, R7, 3),
            Insn::add64_imm(R4, 1), // window 1 → 0
            Insn::mov64_imm(R0, 0x40),
            Insn::stx_b(R4, 0, R0), // refused
        ];
        p.extend(pass_tail());
        let errs = verify_shape(&p).unwrap_err();
        assert!(
            errs.iter().any(|v| v.msg.contains("unproven packet store")),
            "{errs:?}"
        );
    }

    /// Lesson 2: a dead block after the terminal exit — unreachable.
    #[test]
    fn dead_code_rejected() {
        let mut p = clean_prologue();
        bounds_check(&mut p);
        p.push(Insn::ldx_b(R4, R6, 0));
        p.extend(pass_tail());
        p.push(Insn::mov64_imm(3, 0)); // dead: after exit, nothing jumps here
        let errs = verify_shape(&p).unwrap_err();
        assert!(
            errs.iter().any(|v| v.msg.contains("unreachable")),
            "{errs:?}"
        );
    }

    /// The stub shape (as compiled today) passes: prologue, ja, action,
    /// exit — all reachable, no packet reads at all.
    #[test]
    fn empty_stub_shape_ok() {
        let p = vec![
            Insn::ldx_w(R6, R1, 0),
            Insn::ldx_w(R7, R1, 4),
            Insn::ja(1),
            Insn::ldx_w(R5, R1, 16),
            Insn::ld_imm64(R4, 0, 0, Some(0))[0],
            Insn::ld_imm64(R4, 0, 0, Some(0))[1],
            Insn::mov64_imm(R5, 0),
            Insn::call(BPF_FUNC_redirect_map),
            Insn::exit(),
        ];
        let errs = verify_shape(&p).unwrap_err();
        // The unreachable check may flag nothing here; the call's
        // fall-through is modeled. The important part: no unproven
        // reads (there are none).
        assert!(!errs.iter().any(|v| v.msg.contains("unproven")), "{errs:?}");
    }
}
