//! The eBPF instruction model: one 64-bit `struct bpf_insn` (the kernel
//! ABI), opcode constants for the subset the codegen emits, and the
//! helpers our programs call. Encoding follows `linux/bpf.h` verbatim:
//! `code | dst:4 | src:4 | off:16 | imm:32`.

/// One eBPF instruction (the raw kernel `bpf_insn`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u8,
    pub dst: u8,
    pub src: u8,
    pub off: i16,
    pub imm: i32,
}

/// Register aliases (the kernel ABI's own).
pub const R0: u8 = 0;
pub const R1: u8 = 1;
pub const R2: u8 = 2;
pub const R3: u8 = 3;
pub const R6: u8 = 6;
pub const R7: u8 = 7;
pub const R8: u8 = 8;
pub const R9: u8 = 9;

// --- opcode classes -------------------------------------------------------
// The full kernel ABI classes/sizes are named even where the codegen
// subset does not emit them (LD/ST/DW/JMP32): the model mirrors
// `linux/bpf.h` verbatim, and the VM accepts what the verifier would.
#[allow(dead_code)] // ABI model completeness (the VM accepts the class)
const BPF_LD: u8 = 0x00;
const BPF_LDX: u8 = 0x01;
#[allow(dead_code)] // ABI model completeness (the VM accepts the class)
const BPF_ST: u8 = 0x02;
const BPF_STX: u8 = 0x03;
const BPF_ALU: u8 = 0x04;
const BPF_JMP: u8 = 0x05;
#[allow(dead_code)] // ABI model completeness (the VM handles the class)
const BPF_JMP32: u8 = 0x06;
const BPF_ALU64: u8 = 0x07;
// sizes
const BPF_W: u8 = 0x00; // 32-bit
const BPF_H: u8 = 0x08; // 16-bit
const BPF_B: u8 = 0x10; // 8-bit
#[allow(dead_code)] // ABI model completeness
const BPF_DW: u8 = 0x18; // 64-bit
// sources
const BPF_K: u8 = 0x00;
const BPF_X: u8 = 0x08;
// mode (eBPF memory accesses carry BPF_MEM; classic-BPF ABS/IND are
// not part of the subset)
const BPF_MEM: u8 = 0x60;
// ALU ops
const BPF_ADD: u8 = 0x00;
const BPF_SUB: u8 = 0x10;
const BPF_AND: u8 = 0x50;
const BPF_LSH: u8 = 0x60;
const BPF_RSH: u8 = 0x70;
const BPF_OR: u8 = 0x40;
const BPF_XOR: u8 = 0xa0;
const BPF_MOV: u8 = 0xb0;
// JMP ops
const BPF_JA: u8 = 0x00;
const BPF_JEQ: u8 = 0x10;
const BPF_JGT: u8 = 0x20;
const BPF_JGE: u8 = 0x30;
const BPF_JNE: u8 = 0x50;
const BPF_JLT: u8 = 0xb0;
const BPF_JLE: u8 = 0xc0;
const BPF_CALL: u8 = 0x80;
const BPF_EXIT: u8 = 0x90;
// LD_IMM64 (pseudo map fd when src == BPF_PSEUDO_MAP_FD)
const BPF_LD_IMM64: u8 = 0x18;
/// `src_reg` value marking an LD_IMM64 as a map-fd reference.
pub const BPF_PSEUDO_MAP_FD: u8 = 1;

// --- helpers (linux/bpf.h `enum bpf_func_id`) ------------------------------
// Named exactly as the kernel header spells them.
#[allow(non_upper_case_globals)]
pub const BPF_FUNC_map_lookup_elem: i32 = 1;
#[allow(non_upper_case_globals)]
pub const BPF_FUNC_map_update_elem: i32 = 2;
#[allow(non_upper_case_globals)]
pub const BPF_FUNC_csum_diff: i32 = 28;
#[allow(non_upper_case_globals)]
pub const BPF_FUNC_redirect_map: i32 = 51;

// --- XDP action codes ------------------------------------------------------
/// `XDP_ABORTED`.
pub const XDP_ABORTED: i32 = 0;
/// `XDP_DROP`.
pub const XDP_DROP: i32 = 1;
/// `XDP_PASS`.
pub const XDP_PASS: i32 = 2;
/// `XDP_TX`.
pub const XDP_TX: i32 = 3;
/// `XDP_REDIRECT`.
pub const XDP_REDIRECT: i32 = 4;

/// The xdp_md context: data(0), data_end(4), data_meta(8),
/// ingress_ifindex(12), rx_queue_index(16) — the `struct xdp_md` field
/// order (the VM mirrors it; only the first and last are used).
pub const XDP_MD_DATA: i16 = 0;
pub const XDP_MD_DATA_END: i16 = 4;
pub const XDP_MD_RX_QUEUE: i16 = 16;

impl Insn {
    pub const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            dst,
            src,
            off,
            imm,
        }
    }

    /// `r{dst} = imm` (64-bit).
    pub const fn mov64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)
    }
    /// `r{dst} = r{src}` (64-bit).
    pub const fn mov64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0)
    }
    /// `r{dst} = imm` (32-bit, zero-extends).
    pub const fn mov32_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU | BPF_MOV | BPF_K, dst, 0, 0, imm)
    }
    /// `r{dst} += imm` (64-bit).
    pub const fn add64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_ADD | BPF_K, dst, 0, 0, imm)
    }
    /// `r{dst} += r{src}` (64-bit).
    pub const fn add64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | BPF_ADD | BPF_X, dst, src, 0, 0)
    }
    /// `r{dst} |= r{src}` (64-bit).
    pub const fn or64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | BPF_OR | BPF_X, dst, src, 0, 0)
    }
    /// `r{dst} &= r{src}` (64-bit).
    pub const fn and64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | BPF_AND | BPF_X, dst, src, 0, 0)
    }
    /// `r{dst} ^= imm` (64-bit).
    pub const fn xor64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_XOR | BPF_K, dst, 0, 0, imm)
    }
    /// `r{dst} &= imm` (64-bit).
    pub const fn and64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_AND | BPF_K, dst, 0, 0, imm)
    }
    /// `r{dst} |= imm` (64-bit).
    pub const fn or64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_OR | BPF_K, dst, 0, 0, imm)
    }
    /// `r{dst} <<= imm` (64-bit).
    pub const fn lsh64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_LSH | BPF_K, dst, 0, 0, imm)
    }
    /// `r{dst} >>= imm` (64-bit, logical).
    pub const fn rsh64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_RSH | BPF_K, dst, 0, 0, imm)
    }
    /// `r{dst} -= imm` (64-bit).
    pub const fn sub64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_SUB | BPF_K, dst, 0, 0, imm)
    }

    /// Jump-if `r{dst} OP imm` (64-bit unsigned), `off` relative to the
    /// NEXT instruction.
    pub const fn j64_imm(op: JmpOp, dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | op.to_raw() | BPF_K, dst, 0, off, imm)
    }
    /// Jump-if `r{dst} OP imm` comparing the low 32 BITS (the imm
    /// zero-extends — this is the class for u32 values whose high bit
    /// is set, where a 64-bit JEQ's sign-extended imm would never hit).
    pub const fn j32_imm(op: JmpOp, dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP32 | op.to_raw() | BPF_K, dst, 0, off, imm)
    }
    /// Jump-if `r{dst} OP r{src}` (64-bit unsigned).
    pub const fn j64_reg(op: JmpOp, dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_JMP | op.to_raw() | BPF_X, dst, src, off, 0)
    }
    /// Unconditional relative jump.
    pub const fn ja(off: i16) -> Self {
        Self::new(BPF_JMP | BPF_JA, 0, 0, off, 0)
    }

    /// `r{dst} = *(u8*)(r{src} + off)`.
    pub const fn ldx_b(dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_LDX | BPF_MEM | BPF_B, dst, src, off, 0)
    }
    /// `r{dst} = *(u16*)(r{src} + off)` (little-endian).
    pub const fn ldx_h(dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_LDX | BPF_MEM | BPF_H, dst, src, off, 0)
    }
    /// `r{dst} = *(u32*)(r{src} + off)` (little-endian).
    pub const fn ldx_w(dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_LDX | BPF_MEM | BPF_W, dst, src, off, 0)
    }
    /// `*(u8*)(r{dst} + off) = imm`.
    #[allow(dead_code)] // ABI model completeness (the codegen stores via
    // registers, but the ST-imm form is valid eBPF)
    pub const fn st_b(dst: u8, off: i16, imm: i32) -> Self {
        Self::new(BPF_ST | BPF_MEM | BPF_B, dst, 0, off, imm)
    }
    /// `*(u8*)(r{dst} + off) = r{src}`.
    pub const fn stx_b(dst: u8, off: i16, src: u8) -> Self {
        Self::new(BPF_STX | BPF_MEM | BPF_B, dst, src, off, 0)
    }
    /// `*(u16*)(r{dst} + off) = r{src}`.
    pub const fn stx_h(dst: u8, off: i16, src: u8) -> Self {
        Self::new(BPF_STX | BPF_MEM | BPF_H, dst, src, off, 0)
    }
    /// `*(u32*)(r{dst} + off) = r{src}`.
    pub const fn stx_w(dst: u8, off: i16, src: u8) -> Self {
        Self::new(BPF_STX | BPF_MEM | BPF_W, dst, src, off, 0)
    }

    /// The LD_IMM64 pair: `r{dst} = imm64` (two slots). With `map =
    /// Some(idx)` the first word carries the pseudo-map-fd marker and
    /// the imm is the map's index within the program (the loader
    /// rewrites it to the real fd; the VM resolves it locally).
    pub const fn ld_imm64(dst: u8, lo: u32, hi: u32, map: Option<u8>) -> [Self; 2] {
        let src = match map {
            Some(_) => BPF_PSEUDO_MAP_FD,
            None => 0,
        };
        [
            Self::new(BPF_LD_IMM64, dst, src, 0, lo as i32),
            Self::new(0, 0, 0, 0, hi as i32),
        ]
    }

    /// `call imm` (helper id).
    pub const fn call(imm: i32) -> Self {
        Self::new(BPF_JMP | BPF_CALL, 0, 0, 0, imm)
    }

    /// `exit`.
    pub const fn exit() -> Self {
        Self::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
    }

    /// The raw 64-bit encoding (the kernel ABI).
    pub const fn to_bits(self) -> u64 {
        (self.code as u64)
            | ((self.dst as u64 & 0xf) << 8)
            | ((self.src as u64 & 0xf) << 12)
            | ((self.off as u16 as u64) << 16)
            | ((self.imm as u32 as u64) << 32)
    }

    /// Decode the raw 64-bit encoding.
    pub const fn from_bits(bits: u64) -> Self {
        Self {
            code: (bits & 0xff) as u8,
            dst: ((bits >> 8) & 0xf) as u8,
            src: ((bits >> 12) & 0xf) as u8,
            off: ((bits >> 16) & 0xffff) as u16 as i16,
            imm: ((bits >> 32) & 0xffff_ffff) as u32 as i32,
        }
    }
}

/// The unsigned comparison ops the codegen uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JmpOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
}

impl JmpOp {
    const fn to_raw(self) -> u8 {
        match self {
            Self::Eq => BPF_JEQ,
            Self::Ne => BPF_JNE,
            Self::Gt => BPF_JGT,
            Self::Ge => BPF_JGE,
            Self::Lt => BPF_JLT,
            Self::Le => BPF_JLE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The known-answer encoding: `add r1, 2` is `0x0200000000000107`
    /// (the canonical eBPF disassembly example, byte-for-byte).
    #[test]
    fn encoding_known_answers() {
        let add = Insn::add64_imm(1, 2);
        assert_eq!(add.to_bits(), 0x0000_0002_0000_0107);
        assert_eq!(Insn::from_bits(add.to_bits()), add);
        // mov64 r0, 2: 0xb7 dst=0 imm=2 → 0x02000000000000b7
        assert_eq!(Insn::mov64_imm(0, 2).to_bits(), 0x0000_0002_0000_00b7);
        // exit: 0x95
        assert_eq!(Insn::exit().to_bits(), 0x0000_0000_0000_0095);
        // call 51: 0x85 imm=51
        assert_eq!(Insn::call(51).to_bits(), 0x0000_0033_0000_0085);
        // ldxb r9, [r6+12]: code 0x71, src 6 (<<12), dst 9 (<<8),
        // off 12 (<<16) → 0x000c690000000071.
        let ldx = Insn::ldx_b(9, 6, 12);
        assert_eq!(ldx.code, 0x71);
        assert_eq!((ldx.dst, ldx.src, ldx.off), (9, 6, 12));
        assert_eq!(ldx.to_bits(), 0x0000_0000_000c_6971);
        // ld_imm64 pseudo map fd: src_reg 1, imm lo.
        let [a, _] = Insn::ld_imm64(1, 7, 0, Some(0));
        assert_eq!(a.code, 0x18);
        assert_eq!(a.src, BPF_PSEUDO_MAP_FD);
        assert_eq!(a.imm, 7);
    }
}
