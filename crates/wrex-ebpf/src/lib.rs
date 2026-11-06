//! wrex-ebpf (tranche 23b/c): the eBPF instruction model, the
//! schema→codegen family (filter predicates, packet rewrites with
//! incremental checksums, counters), and the userspace VM that executes
//! them — the per-commit semantic gate. Programs are **compiled
//! artifacts of the schema, never hand-written** (the standing T29
//! rule): every field offset in a generated program comes from the
//! codecs' own layout tables, so a protocol becomes kernel-filterable
//! by landing layouts, not by writing BPF.
//!
//! The crate is `no_std` (alloc only): the same code emits for the
//! kernel and runs in the in-process differential.

#![no_std]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod insn;
pub mod verify;
pub mod vm;

mod codegen;
pub use codegen::{
    Action, ChecksumTarget, CompileError, Edit, MAP_IDX_FLOW, MAP_IDX_XSK, MapDecl, MapKind,
    Program, compile_acl, compile_capture_prefilter, compile_filter, compile_flow_table,
    compile_responder, compile_translate,
};

#[cfg(test)]
mod tests {
    use crate::codegen::{MAP_IDX_XSK, MapDecl, MapKind, Program};
    use crate::insn::Insn;
    use crate::vm::Vm;

    // Smoke: the wiring below carries the real suites (the differential
    // lives in wrex/tests so it can use the full standard registry).
    #[test]
    fn module_shape() {
        // A trivial always-pass program assembles and runs.
        let prog = Program {
            name: alloc::string::String::new(),
            maps: alloc::vec::Vec::new(),
            insns: alloc::vec![Insn::mov64_imm(0, 2) /* XDP_PASS */, Insn::exit(),],
        };
        let mut vm = Vm::new_default();
        let verdict = vm.run(&prog, &[0x45u8, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(verdict, crate::vm::Verdict::Pass);
        // Redirect plumbing (the XSK map) feeds the same path.
        let redirect = Program {
            name: alloc::string::String::new(),
            maps: alloc::vec![MapDecl {
                idx: MAP_IDX_XSK,
                kind: MapKind::XskMap,
                key_size: 4,
                value_size: 4,
                max_entries: 1,
            }],
            insns: alloc::vec![
                Insn::ldx_w(2, 1, crate::insn::XDP_MD_RX_QUEUE),
                Insn::ld_imm64(1, MAP_IDX_XSK, 0, Some(0))[0],
                Insn::ld_imm64(1, MAP_IDX_XSK, 0, Some(0))[1],
                Insn::mov64_imm(3, 0),
                Insn::call(crate::insn::BPF_FUNC_redirect_map),
                Insn::exit(),
            ],
        };
        let mut vm = Vm::new_default();
        vm.declare_program_maps(&redirect);
        assert_eq!(
            vm.run(&redirect, &[0; 32]).unwrap(),
            crate::vm::Verdict::Pass
        );
        vm.maps.set(MAP_IDX_XSK, &0u32.to_le_bytes(), 1);
        assert_eq!(
            vm.run(&redirect, &[0; 32]).unwrap(),
            crate::vm::Verdict::Redirect
        );
    }
}
