#![no_main]
//! libfuzzer target: raw 64-bit words → the userspace eBPF VM. Any
//! instruction stream must resolve to a verdict or a POINTED VmError
//! (bounds/budget/unsupported) — never a panic. Generated programs
//! are straight-line; this target pins the VM's own soundness against
//! arbitrary streams (the codegen differential pins the semantics).

use libfuzzer_sys::fuzz_target;
use wrex_ebpf::codegen::Program;
use wrex_ebpf::vm::Vm;

fuzz_target!(|words: &[[u8; 8]]| {
    let insns: Vec<wrex_ebpf::insn::Insn> = words
        .iter()
        .map(|w| wrex_ebpf::insn::Insn::from_bits(u64::from_le_bytes(*w)))
        .collect();
    let prog = Program {
        name: String::new(),
        maps: Vec::new(),
        insns,
    };
    let mut vm = Vm::new_default();
    // Any outcome is fine; a panic is not.
    let _ = vm.run(&prog, b"\x45\x00\x00\x00\x00\x00\x00\x00");
});
