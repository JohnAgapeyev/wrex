#![no_main]
//! libfuzzer target: raw bytes → the userspace eBPF VM, eight
//! little-endian bytes per instruction word (`chunks_exact` drops a
//! trailing partial word — a stream the VM sees truncated must not
//! panic either). Any instruction stream must resolve to a verdict or
//! a POINTED VmError (bounds/budget/unsupported) — never a panic.
//! Generated programs are straight-line; this target pins the VM's own
//! soundness against arbitrary streams (the codegen differential pins
//! the semantics).

use libfuzzer_sys::fuzz_target;
use wrex_ebpf::insn::Insn;
use wrex_ebpf::vm::Vm;
use wrex_ebpf::Program;

fuzz_target!(|data: &[u8]| {
    let insns: Vec<Insn> = data
        .chunks_exact(8)
        .map(|w| {
            let mut word = [0u8; 8];
            word.copy_from_slice(w);
            Insn::from_bits(u64::from_le_bytes(word))
        })
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
