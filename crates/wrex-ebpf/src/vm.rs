//! The userspace eBPF VM: executes generated programs against a packet
//! (the per-commit semantic gate — verdict differential vs the filter
//! engine over the golden corpora, no kernel needed). Faithful to the
//! subset the codegen emits: 64/32-bit ALU, unsigned jumps, byte loads,
//! ctx/packet pointers, the stack, and the map/redirect/csum helpers.
//! Bounds discipline mirrors the verifier: a packet load outside
//! `[data, data_end)` is a pointed `VmError::Bounds` — the codegen
//! guards every load, so one firing is a compiler bug, not packet data.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::insn::*;

/// An XDP action the program returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Aborted,
    Drop,
    Pass,
    Tx,
    Redirect,
}

impl Verdict {
    /// From the raw `r0` at `exit`.
    pub fn from_action(v: u64) -> Self {
        match v {
            0 => Self::Aborted,
            1 => Self::Drop,
            2 => Self::Pass,
            3 => Self::Tx,
            4 => Self::Redirect,
            _ => Self::Aborted,
        }
    }
}

/// The VM-side map store. Values live in POINTER-BACKED CELLS (the
/// kernel hands `map_lookup_elem` a pointer INTO the map's value —
/// `*ptr += 1` persists in-kernel, so the VM's cells must be an
/// addressable region, not a by-value lookup).
#[derive(Default)]
pub struct VmMaps {
    maps: BTreeMap<u32, (usize, BTreeMap<Vec<u8>, usize>)>,
    /// Value cells; cell i lives at MAP_CELLS_BASE + i*8.
    cells: Vec<u64>,
}

impl VmMaps {
    /// Declare a map (the codegen's map tables materialize here).
    pub fn declare(&mut self, idx: u32, key_size: u32) {
        self.maps
            .entry(idx)
            .or_insert((key_size as usize, BTreeMap::new()));
    }
    /// Insert an entry (e.g. queue 0 → socket value for the XSKMAP).
    pub fn set(&mut self, idx: u32, key: &[u8], value: u64) {
        let cell = self.cells.len();
        self.cells.push(value);
        self.maps
            .entry(idx)
            .or_insert((key.len(), BTreeMap::new()))
            .1
            .insert(key.to_vec(), cell);
    }
    /// Dump a map (the flow-table reader: keys + counter values).
    pub fn dump(&self, idx: u32) -> Vec<(Vec<u8>, u64)> {
        self.maps
            .get(&idx)
            .map(|(_, m)| m.iter().map(|(k, c)| (k.clone(), self.cells[*c])).collect())
            .unwrap_or_default()
    }
    fn key_size(&self, idx: u32) -> usize {
        self.maps.get(&idx).map_or(4, |(k, _)| *k)
    }
    fn lookup_cell(&self, idx: u32, key: &[u8]) -> Option<usize> {
        self.maps.get(&idx)?.1.get(key).copied()
    }
    /// The pointer a successful lookup hands the program.
    fn cell_ptr(cell: usize) -> u64 {
        MAP_CELLS_BASE + cell as u64 * 8
    }
    /// Read a cell through its pointer (the lookup-returned pointer).
    fn read_cell(&self, addr: u64, size: u8) -> Option<u64> {
        if addr < MAP_CELLS_BASE {
            return None;
        }
        let cell = ((addr - MAP_CELLS_BASE) / 8) as usize;
        let v = *self.cells.get(cell)?;
        Some(match size {
            4 => v & 0xffff_ffff,
            2 => v & 0xffff,
            1 => v & 0xff,
            _ => v,
        })
    }
    /// Write a cell through its pointer.
    fn write_cell(&mut self, addr: u64, size: u8, value: u64) -> Option<()> {
        if addr < MAP_CELLS_BASE {
            return None;
        }
        let cell = ((addr - MAP_CELLS_BASE) / 8) as usize;
        let slot = self.cells.get_mut(cell)?;
        match size {
            4 => *slot = (*slot & 0xffff_ffff_0000_0000) | (value & 0xffff_ffff),
            2 => *slot = (*slot & !0xffff) | (value & 0xffff),
            1 => *slot = (*slot & !0xff) | (value & 0xff),
            _ => *slot = value,
        }
        Some(())
    }
}

/// The execution context: the packet bytes plus the xdp_md fields the
/// programs read (rx queue for the redirect key, ifindex for stats).
#[derive(Clone, Debug)]
pub struct VmCtx {
    pub data: Vec<u8>,
    pub ingress_ifindex: u32,
    pub rx_queue: u32,
}

const PACKET_ADDR: u64 = 0x1000;
/// The stack region base (r10).
const STACK_ADDR: u64 = 0x10000;

/// A runtime VM error: either a program bug (bounds, division) or a
/// malformed instruction stream — never packet data.
#[derive(Debug, PartialEq, Eq)]
pub enum VmError {
    /// A packet load outside `[data, data_end)` — a codegen bug (every
    /// generated load is guarded).
    Bounds,
    /// An instruction outside the emitted subset.
    Unsupported(u8),
    /// The instruction budget ran out (loops are never emitted).
    Budget,
    /// Unknown map index.
    NoMap(u32),
    /// Helper unimplemented in the VM.
    Helper(i32),
}

/// The interpreter.
pub struct Vm {
    regs: [u64; 11],
    stack: [u8; 512],
    pub maps: VmMaps,
    ctx: VmCtx,
    data_end: u64,
}

impl Vm {
    /// A VM with no maps declared (pure-predicate programs).
    pub fn new_default() -> Self {
        Self::with_ctx(VmCtx {
            data: vec![],
            ingress_ifindex: 0,
            rx_queue: 0,
        })
    }

    pub fn with_ctx(ctx: VmCtx) -> Self {
        let mut vm = Self {
            regs: [0; 11],
            stack: [0; 512],
            maps: VmMaps::default(),
            ctx,
            data_end: 0,
        };
        let len = vm.ctx.data.len() as u64;
        vm.data_end = PACKET_ADDR.saturating_add(len);
        vm
    }

    /// Declare every map of a program (with its key size — the flow
    /// hash keys are wider than the XSKMAP queue keys).
    pub fn declare_program_maps(&mut self, prog: &crate::codegen::Program) {
        for m in &prog.maps {
            self.maps.declare(m.idx, m.key_size);
        }
    }

    /// Run a program against `ctx.data`, returning the XDP verdict.
    pub fn run(
        &mut self,
        prog: &crate::codegen::Program,
        packet: &[u8],
    ) -> Result<Verdict, VmError> {
        self.ctx.data = packet.to_vec();
        let len = packet.len() as u64;
        self.data_end = PACKET_ADDR.saturating_add(len);
        self.regs = [0; 11];
        // r1 = the ctx pointer; r10 = the stack frame pointer.
        self.regs[1] = CTX_BASE;
        self.regs[10] = STACK_ADDR + 512;
        self.execute(prog)
    }

    /// Run a program against `packet` and return the (possibly edited)
    /// packet bytes — the translator/responder shape (the writes land
    /// in the packet copy).
    pub fn run_with_packet(
        &mut self,
        prog: &crate::codegen::Program,
        packet: &[u8],
    ) -> Result<Vec<u8>, VmError> {
        let verdict = self.run(prog, packet)?;
        if matches!(verdict, Verdict::Aborted) {
            return Err(VmError::Helper(0xdead));
        }
        Ok(self.ctx.data.clone())
    }

    fn read_mem(&self, addr: u64, size: u8) -> Result<u64, VmError> {
        // Map value cells: pointer-backed (lookup hands a pointer INTO
        // the map's value — reads/writes persist, kernel contract).
        if (MAP_CELLS_BASE..STACK_ADDR).contains(&addr)
            && let Some(v) = self.maps.read_cell(addr, size)
        {
            return Ok(v);
        }
        // Crafted streams reach the VM with ATTACKER-arbitrary addresses
        // (any register value): the end-of-span add must be
        // OVERFLOW-PROOF — a wrapping `addr + size` would sail past the
        // region checks and index out of bounds (checked_add → the
        // pointed Bounds refusal instead).
        let end = addr.checked_add(size as u64);
        let in_pkt = end.is_some_and(|e| addr >= PACKET_ADDR && e <= self.data_end);
        let in_stack = end.is_some_and(|e| addr >= STACK_ADDR && e <= STACK_ADDR + 512);
        #[cfg(all(debug_assertions, feature = "std"))]
        if !(in_pkt || in_stack) {
            // Differential debugging aid: name the faulting read.
            std::eprintln!(
                "vm read_mem OOB: addr={addr:#x} size={size} end={:#x}",
                self.data_end
            );
        }
        if in_pkt {
            let off = (addr - PACKET_ADDR) as usize;
            let mut v = 0u64;
            for i in (0..size as usize).rev() {
                v = (v << 8) | self.ctx.data[off + i] as u64;
            }
            return Ok(v);
        }
        if in_stack {
            let off = (addr - STACK_ADDR) as usize;
            let mut v = 0u64;
            for i in (0..size as usize).rev() {
                v = (v << 8) | self.stack[off + i] as u64;
            }
            return Ok(v);
        }
        Err(VmError::Bounds)
    }

    fn write_mem(&mut self, addr: u64, size: u8, value: u64) -> Result<(), VmError> {
        if (MAP_CELLS_BASE..STACK_ADDR).contains(&addr) {
            // A lookup-returned map cell (or any cell-region write):
            // only ALLOCATED cells are writable (the bounds discipline).
            return self
                .maps
                .write_cell(addr, size, value)
                .ok_or(VmError::Bounds)
                .map(|_| ());
        }
        // Same overflow-proof span math as read_mem.
        let end = addr.checked_add(size as u64);
        if end.is_some_and(|e| addr >= PACKET_ADDR && e <= self.data_end) {
            let off = (addr - PACKET_ADDR) as usize;
            for i in 0..size as usize {
                self.ctx.data[off + i] = ((value >> (8 * i)) & 0xff) as u8;
            }
            return Ok(());
        }
        if end.is_some_and(|e| addr >= STACK_ADDR && e <= STACK_ADDR + 512) {
            let off = (addr - STACK_ADDR) as usize;
            for i in 0..size as usize {
                self.stack[off + i] = ((value >> (8 * i)) & 0xff) as u8;
            }
            return Ok(());
        }
        Err(VmError::Bounds)
    }

    fn ctx_field(&self, off: i16) -> u64 {
        match off {
            XDP_MD_DATA => PACKET_ADDR,
            XDP_MD_DATA_END => self.data_end,
            12 => self.ctx.ingress_ifindex as u64,
            XDP_MD_RX_QUEUE => self.ctx.rx_queue as u64,
            _ => 0,
        }
    }

    fn execute(&mut self, prog: &crate::codegen::Program) -> Result<Verdict, VmError> {
        const BUDGET: u64 = 1_000_000;
        let insns = &prog.insns;
        let mut pc: usize = 0;
        let mut spent: u64 = 0;
        loop {
            spent += 1;
            if spent > BUDGET {
                return Err(VmError::Budget);
            }
            let Some(insn) = insns.get(pc) else {
                return Err(VmError::Unsupported(0xff));
            };
            #[cfg(all(debug_assertions, feature = "std"))]
            if std::env::var_os("WREX_VM_TRACE").is_some() {
                std::eprintln!(
                    "pc={pc:3} code={:02x} dst={} src={} off={:4} imm={:6} r3={:x} r5={:x} r9={:x}",
                    insn.code,
                    insn.dst,
                    insn.src,
                    insn.off,
                    insn.imm,
                    self.regs[3],
                    self.regs[5],
                    self.regs[9]
                );
            }
            let code = insn.code;
            let class = code & 0x07;
            let size = code & 0x18;
            let src_bit = code & 0x08 != 0 && matches!(class, 0x04..=0x07);
            let (dst, src) = (insn.dst as usize, insn.src as usize);
            // Register fields are 4-bit on the wire; the kernel verifier
            // rejects r11..r15 outright ("invalid register") — the VM
            // answers the same way, pointedly. (The fuzz target found the
            // raw-index panic this guard closes: a crafted stream's
            // dst=0xf on a MOV reached regs[15] out of bounds.) Every
            // executed class rides this one guard; the LD_IMM64 slot-2
            // pseudo-data never reaches here (it is skipped, not
            // executed).
            if dst > 10 || src > 10 {
                return Err(VmError::Unsupported(code));
            }
            let next = pc + 1;
            match class {
                0x00 if code == BPF_LD_IMM64_CODE => {
                    // Two-slot immediate (pseudo map fd or plain 64-bit).
                    let lo = insn.imm as u32 as u64;
                    let hi = insns
                        .get(next)
                        .map(|i| i.imm as u32 as u64)
                        .ok_or(VmError::Bounds)?;
                    if insn.src == BPF_PSEUDO_MAP_FD {
                        // The map POINTER: the VM address space reserves
                        // MAP_IDX_BASE + idx.
                        self.regs[dst] = MAP_BASE.wrapping_add(insn.imm as u64);
                    } else {
                        self.regs[dst] = lo | (hi << 32);
                    }
                    pc = next + 1;
                    continue;
                }
                0x01 => {
                    // LDX: dst = *(size*)(src + off).
                    let addr = self.regs[src]
                        .checked_add_signed(insn.off as i64)
                        .ok_or(VmError::Bounds)?;
                    let v = if (CTX_BASE..PACKET_ADDR).contains(&addr) {
                        self.ctx_field(insn.off)
                    } else {
                        let n = match size {
                            0x00 => 4,
                            0x08 => 2,
                            0x10 => 1,
                            _ => return Err(VmError::Unsupported(code)),
                        };
                        self.read_mem(addr, n)?
                    };
                    self.regs[dst] = v;
                }
                0x02 => {
                    // ST: *(size*)(dst + off) = imm.
                    let addr = self.regs[dst]
                        .checked_add_signed(insn.off as i64)
                        .ok_or(VmError::Bounds)?;
                    let n = match size {
                        0x00 => 4,
                        0x08 => 2,
                        0x10 => 1,
                        _ => return Err(VmError::Unsupported(code)),
                    };
                    self.write_mem(addr, n, insn.imm as u32 as u64)?;
                }
                0x03 => {
                    // STX: *(size*)(dst + off) = src.
                    let addr = self.regs[dst]
                        .checked_add_signed(insn.off as i64)
                        .ok_or(VmError::Bounds)?;
                    let n = match size {
                        0x00 => 4,
                        0x08 => 2,
                        0x10 => 1,
                        _ => return Err(VmError::Unsupported(code)),
                    };
                    self.write_mem(addr, n, self.regs[src])?;
                }
                0x04 | 0x07 => {
                    let is64 = class == 0x07;
                    let op = code & 0xf0;
                    // Kernel ABI: 64-bit ALU immediates SIGN-extend;
                    // 32-bit ops zero-extend (the upper bits clear).
                    let operand = if src_bit {
                        self.regs[src]
                    } else if is64 {
                        (insn.imm as i64) as u64
                    } else {
                        insn.imm as u32 as u64
                    };
                    let cur = self.regs[dst];
                    let out = match op {
                        0x00 => cur.wrapping_add(operand), // ADD
                        0x10 => cur.wrapping_sub(operand), // SUB
                        0x40 => cur | operand,             // OR
                        0x50 => cur & operand,             // AND
                        0xa0 => cur ^ operand,             // XOR
                        0x60 => {
                            let s = (operand & 63) as u32;
                            cur.checked_shl(s).ok_or(VmError::Bounds)? // LSH
                        }
                        0x70 => {
                            let s = (operand & 63) as u32;
                            cur.checked_shr(s).ok_or(VmError::Bounds)? // RSH
                        }
                        0xb0 => operand, // MOV
                        _ => return Err(VmError::Unsupported(code)),
                    };
                    self.regs[dst] = if is64 { out } else { out & 0xffff_ffff };
                }
                0x05 | 0x06 => {
                    if code == 0x95 {
                        return Ok(Verdict::from_action(self.regs[0]));
                    }
                    if code == 0x85 {
                        self.call_helper(prog, insn.imm)?;
                        pc = next;
                        continue;
                    }
                    let op = code & 0xf0;
                    if op == 0x00 {
                        // JA
                        pc = (next as i64 + insn.off as i64) as usize;
                        continue;
                    }
                    let a = self.regs[dst];
                    let b = if src_bit {
                        self.regs[src]
                    } else if class == 0x05 {
                        // 64-bit jump immediates sign-extend (JMP32
                        // below zero-extends like every 32-bit op).
                        (insn.imm as i64) as u64
                    } else {
                        insn.imm as u32 as u64
                    };
                    let (a, b) = if class == 0x06 {
                        (a & 0xffff_ffff, b)
                    } else {
                        (a, b)
                    };
                    let taken = match op {
                        0x10 => a == b,
                        0x20 => a > b,
                        0x30 => a >= b,
                        0x40 => a & b != 0,
                        0x50 => a != b,
                        0xb0 => a < b,
                        0xc0 => a <= b,
                        _ => return Err(VmError::Unsupported(code)),
                    };
                    if taken {
                        pc = (next as i64 + insn.off as i64) as usize;
                        continue;
                    }
                }
                _ => return Err(VmError::Unsupported(code)),
            }
            pc = next;
        }
    }

    /// Resolve a map "pointer" (MAP_BASE + idx) to its index.
    fn map_idx(ptr: u64) -> Result<u32, VmError> {
        ptr.checked_sub(MAP_BASE)
            .filter(|v| *v <= u32::MAX as u64)
            .map(|v| v as u32)
            .ok_or(VmError::NoMap(u32::MAX))
    }

    fn call_helper(&mut self, prog: &crate::codegen::Program, id: i32) -> Result<(), VmError> {
        #[allow(non_upper_case_globals)]
        match id {
            BPF_FUNC_redirect_map => {
                let map = Self::map_idx(self.regs[1])?;
                let key = self.reg_bytes(self.regs[2], self.maps.key_size(map))?;
                if self.maps.lookup_cell(map, &key).is_some() {
                    self.regs[0] = XDP_REDIRECT as u64;
                } else {
                    self.regs[0] = XDP_PASS as u64;
                }
            }
            BPF_FUNC_map_lookup_elem => {
                let map = Self::map_idx(self.regs[1])?;
                let key = self.read_key(self.regs[2], self.maps.key_size(map))?;
                // The kernel contract: a pointer INTO the map's value
                // (writes persist). Absent keys hand NULL.
                match self.maps.lookup_cell(map, &key) {
                    Some(cell) => self.regs[0] = VmMaps::cell_ptr(cell),
                    None => self.regs[0] = 0,
                }
            }
            BPF_FUNC_map_update_elem => {
                let map = Self::map_idx(self.regs[1])?;
                let key = self.read_key(self.regs[2], self.maps.key_size(map))?;
                let val = if self.regs[3] >= STACK_ADDR {
                    let off = (self.regs[3] - STACK_ADDR) as usize;
                    // Overflow-proof range end (the raw register is
                    // attacker-arbitrary): `off + 8` would panic on
                    // wrap in debug and wrap past the slice in release.
                    let end = off.checked_add(8).ok_or(VmError::Bounds)?;
                    u64::from_le_bytes(
                        self.stack
                            .get(off..end)
                            .and_then(|s| s.try_into().ok())
                            .ok_or(VmError::Bounds)?,
                    )
                } else if self.regs[3] >= MAP_CELLS_BASE {
                    self.maps
                        .read_cell(self.regs[3], 8)
                        .ok_or(VmError::Bounds)?
                } else {
                    self.regs[3]
                };
                if self.maps.maps.contains_key(&map) {
                    self.maps.set(map, &key, val);
                    self.regs[0] = 0;
                } else {
                    return Err(VmError::NoMap(map));
                }
            }
            BPF_FUNC_csum_diff => {
                // csum_diff(from, from_size, to, to_size, seed): the
                // incremental RFC 1624 fold — seed + Σ(to words) −
                // Σ(from words) in ONE'S-COMPLEMENT arithmetic: the
                // subtraction rides the complement (a + ~b) and the
                // end-around carry, never a plain wrap (a wrapping
                // borrow is off by one mod 0xFFFF — the classic gotcha
                // the tcp.window differential caught).
                let seed = self.regs[5];
                let mut acc = seed;
                for (base, len, negate) in [
                    (self.regs[1], self.regs[2] as usize, true),
                    (self.regs[3], self.regs[4] as usize, false),
                ] {
                    let mut off = 0usize;
                    while off + 1 < len {
                        // Overflow-proof address math (base is a raw
                        // register value — attacker-arbitrary).
                        let a = base.checked_add(off as u64).ok_or(VmError::Bounds)?;
                        let b2 = a.checked_add(1).ok_or(VmError::Bounds)?;
                        let hi = self.read_mem(a, 1)?;
                        let lo = self.read_mem(b2, 1)?;
                        let w = (hi << 8) | lo;
                        acc += if negate { 0xffff - w } else { w };
                        off += 2;
                    }
                    if len % 2 == 1 {
                        let b =
                            self.read_mem(base.checked_add(off as u64).ok_or(VmError::Bounds)?, 1)?;
                        let w = b << 8;
                        acc += if negate { 0xffff - w } else { w };
                    }
                    // End-around carry (bounded: ≤ 3 rounds for any
                    // u64 seed the codegen produces).
                    while acc > 0xffff {
                        acc = (acc & 0xffff) + (acc >> 16);
                    }
                }
                self.regs[0] = acc;
            }
            _ => {
                let _ = prog;
                return Err(VmError::Helper(id));
            }
        }
        Ok(())
    }

    /// The raw-value key (redirect_map takes the index VALUE, not a
    /// pointer): the register's own bytes. Keys wider than a register
    /// are outside the emitted subset (the XSKMAP key is u32) — the
    /// pointed refusal, never a slice panic on `[..n]`.
    fn reg_bytes(&self, r: u64, n: usize) -> Result<Vec<u8>, VmError> {
        if n > 8 {
            return Err(VmError::Bounds);
        }
        Ok(r.to_le_bytes()[..n].to_vec())
    }

    /// Read a map KEY from a pointer (map_lookup_elem/update_elem take
    /// pointers — unlike redirect_map, which takes the index value).
    fn read_key(&self, ptr: u64, n: usize) -> Result<Vec<u8>, VmError> {
        let mut key = Vec::with_capacity(n);
        for i in 0..n {
            key.push(self.read_mem(ptr.saturating_add(i as u64), 1)? as u8);
        }
        Ok(key)
    }
}

const BPF_LD_IMM64_CODE: u8 = 0x18;
/// The flat address of the xdp_md ctx.
const CTX_BASE: u64 = 0x80;
/// Map "pointers" (LD_IMM64 pseudo-fd) live here + idx.
const MAP_BASE: u64 = 0x2000;
/// The map value cells (pointer-backed lookup results live here).
const MAP_CELLS_BASE: u64 = 0x4000;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codegen::{MAP_IDX_XSK, Program};
    use alloc::vec;

    fn prog(insns: Vec<Insn>) -> Program {
        Program {
            name: alloc::string::String::new(),
            maps: vec![],
            insns,
        }
    }

    /// The packet-bound discipline: a load past data_end is the pointed
    /// Bounds error (codegen guards make it unreachable in generated
    /// programs — this pins the VM's own soundness).
    #[test]
    fn oob_load_is_bounds() {
        // r6 = ctx.data; r9 = *(u8*)(r6+1000) on a 4-byte packet.
        let p = prog(vec![
            Insn::ldx_w(6, 1, XDP_MD_DATA),
            Insn::ldx_b(9, 6, 1000),
            Insn::mov64_imm(0, 2),
            Insn::exit(),
        ]);
        let mut vm = Vm::new_default();
        assert_eq!(vm.run(&p, &[0; 4]).unwrap_err(), VmError::Bounds);
    }

    /// The fuzz target's first find (crash-9daa47ef): a crafted
    /// stream's dst=0xf — register fields are 4-bit on the wire, the
    /// kernel verifier rejects r11..r15 outright, and the VM answers
    /// the same way instead of indexing regs out of bounds.
    #[test]
    fn invalid_register_is_pointed() {
        // 0xffff_ff6a_ffff_fcb7: MOV imm with dst=0xf, src=0xc.
        let p = prog(vec![
            Insn::from_bits(0xffff_ff6a_ffff_fcb7),
            Insn::mov64_imm(0, 2),
            Insn::exit(),
        ]);
        let mut vm = Vm::new_default();
        assert_eq!(vm.run(&p, &[0; 4]).unwrap_err(), VmError::Unsupported(0xb7));
    }

    /// The same fuzz round's sibling hazard, pinned: an address whose
    /// span end WRAPS (u64::MAX + 1) must be the pointed Bounds — a
    /// raw `addr + size` sails past the region check and indexes out
    /// of bounds.
    #[test]
    fn wrapping_span_is_bounds() {
        let p = prog(vec![
            Insn::mov64_imm(9, -1), // r9 = u64::MAX (MOV imm sign-extends)
            Insn::stx_b(9, 0, 0),   // *(u8*)(r9+0) = r0 → the span end wraps
            Insn::mov64_imm(0, 2),
            Insn::exit(),
        ]);
        let mut vm = Vm::new_default();
        assert_eq!(vm.run(&p, &[0; 4]).unwrap_err(), VmError::Bounds);
    }

    /// Byte-wise BE u16 build (the codegen's own idiom) reads the right
    /// number: 0x1234 at offset 0 — through the generated JEQ shape.
    #[test]
    fn be16_build_reads_network_order() {
        let p = prog(vec![
            Insn::ldx_w(6, 1, XDP_MD_DATA),
            Insn::ldx_b(9, 6, 0),
            Insn::lsh64_imm(9, 8),
            Insn::ldx_b(3, 6, 1),
            Insn::or64_reg(9, 3),
            Insn::mov64_imm(0, 2),
            Insn::j64_imm(JmpOp::Eq, 9, 0x1234, 1),
            Insn::mov64_imm(0, 1), // miss → DROP
            Insn::exit(),
        ]);
        let mut vm = Vm::new_default();
        assert_eq!(vm.run(&p, &[0x12, 0x34, 0, 0]).unwrap(), Verdict::Pass);
        assert_eq!(vm.run(&p, &[0x12, 0x35, 0, 0]).unwrap(), Verdict::Drop);
    }

    /// The redirect helper: an XSKMAP entry at the queue key redirects,
    /// a miss passes (the sound-fallback contract, executable).
    #[test]
    fn redirect_map_verdicts() {
        let p = Program {
            name: alloc::string::String::new(),
            maps: vec![crate::codegen::MapDecl {
                idx: MAP_IDX_XSK,
                kind: crate::codegen::MapKind::XskMap,
                key_size: 4,
                value_size: 4,
                max_entries: 1,
            }],
            insns: vec![
                Insn::ldx_w(2, 1, XDP_MD_RX_QUEUE),
                Insn::ld_imm64(1, MAP_IDX_XSK, 0, Some(0))[0],
                Insn::ld_imm64(1, MAP_IDX_XSK, 0, Some(0))[1],
                Insn::mov64_imm(3, 0),
                Insn::call(BPF_FUNC_redirect_map),
                Insn::exit(),
            ],
        };
        let mut vm = Vm::with_ctx(VmCtx {
            data: vec![0; 20],
            ingress_ifindex: 1,
            rx_queue: 0,
        });
        vm.declare_program_maps(&p);
        // No socket in the map → PASS (the fallback).
        assert_eq!(vm.run(&p, &[0; 20]).unwrap(), Verdict::Pass);
        // Queue 0 present → REDIRECT.
        vm.maps.set(MAP_IDX_XSK, &0u32.to_le_bytes(), 1);
        assert_eq!(vm.run(&p, &[0; 20]).unwrap(), Verdict::Redirect);
    }

    /// The csum_diff helper folds old/new bytes into the seed (the
    /// incremental-checksum translator rides it; pinned against the
    /// RFC 1624 identity: a no-op diff returns the seed).
    #[test]
    fn csum_diff_identity() {
        // from = packet+0 len 4, to = packet+0 len 4 (same bytes).
        let p = prog(vec![
            Insn::ldx_w(6, 1, XDP_MD_DATA),
            Insn::mov64_reg(1, 6),
            Insn::mov64_imm(2, 4),
            Insn::mov64_reg(3, 6),
            Insn::mov64_imm(4, 4),
            Insn::mov64_imm(5, 0x1234),
            Insn::call(BPF_FUNC_csum_diff),
            Insn::exit(),
        ]);
        let mut vm = Vm::new_default();
        vm.run(&p, &[0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
        // from == to → the two folds cancel; seed carried (mod the
        // one's-complement carry fold — 0x1234 stays 0x1234).
        assert_eq!(vm.regs[0], 0x1234);
    }
}
