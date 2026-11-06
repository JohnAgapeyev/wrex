//! The schema→eBPF codegen (tranche 23b/c): every field offset in a
//! generated program comes from the codecs' own layout tables — a
//! protocol becomes kernel-filterable by landing layouts, not by writing
//! BPF (the standing T29 rule). Programs are compiled artifacts:
//!
//! - [`compile_capture_prefilter`]: the filter AST → an XDP program
//!   that redirects matching frames into the XSK map and passes the
//!   rest (the default capture datapath; the sound-fallback contract:
//!   anything unwalkable is `XDP_PASS`, never dropped).
//! - [`compile_acl`]: the filter AST → match ⇒ `XDP_DROP` (ACL/drop
//!   lists from wrex filters).
//! - [`compile_translate`]: fixed-offset field rewrites with RFC 1624
//!   incremental checksums (the T14 engine's same-width subset,
//!   transposed — byte-identity is the oracle).
//! - [`compile_responder`]: an ICMPv4-echo XDP_TX responder (the T33
//!   `listen` fast path).
//! - [`compile_flow_table`]: a per-4-tuple BPF hash-map counter feed
//!   (the live `wrex stats` substrate).
//!
//! Walk discipline (the verifier-safety rules, mirrored by the VM):
//! every packet load is preceded by an explicit `ptr + need <=
//! data_end` check jumping to the fallback; variable headers (IPv4
//! options, VLAN stacking) are handled by bounded unrolled walks; no
//! loops are ever emitted. Unsupported terms (record sections, Str
//! fields, dynamic regions) are POINTED compile errors — the caller
//! decides the fallback (the userspace filter), never a silent wrong
//! answer.
//!
//! Register file plan (fixed roles across the walk and the terms):
//! `r1` ctx, `r6` data, `r7` data_end, `r8` L3 start offset,
//! `r9` L4 start offset, `r3/r4/r5` scratch, `r0` the verdict.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use wrex_core::Registry;
use wrex_core::filter::{Filter, Op as FilterOp, Term, TermValue as FilterTermValue};
use wrex_core::schema::{FieldKind, Layout, ResolvedField};

use crate::insn::*;

/// Scratch/role register aliases inside the codegen (the insn module
/// names r0/r1/…; these carry the walk's roles).
const R2: u8 = 2;
const R3: u8 = 3;
const R4: u8 = 4;
const R5: u8 = 5;
const P_DATA: u8 = R6;
const P_END: u8 = R7;
const P_L3: u8 = R8;
const P_L4: u8 = R9;

/// XDP map index 0 is the capture socket map (an XSKMAP).
pub const MAP_IDX_XSK: u32 = 0;
/// Map index 1 is the flow-table hash (a `BPF_MAP_TYPE_HASH`).
pub const MAP_IDX_FLOW: u32 = 1;

/// A declared map the program references (LD_IMM64 pseudo-fd; `idx` is
/// the position in [`Program::maps`], which the loader rewrites to the
/// real fd and the VM resolves locally).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MapDecl {
    pub idx: u32,
    pub kind: MapKind,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapKind {
    XskMap,
    Hash,
}

impl MapKind {
    /// The `enum bpf_map_type` value — counted from
    /// /usr/include/linux/bpf.h (UNSPEC=0 .. CPUMAP=16, XSKMAP=17).
    /// The tranche's live runs caught a hand-marshaled 42 here: an
    /// unregistered map type on every kernel, EINVAL at create — the
    /// constant comes from the header, never memory.
    pub const fn kernel_id(self) -> u32 {
        match self {
            Self::XskMap => 17,
            Self::Hash => 1,
        }
    }
}

/// A compiled eBPF program: instructions, referenced maps, a name (the
/// load-time diagnostics surface) and the license (GPL — the helpers
/// the codegen calls require it).
#[derive(Clone, Debug)]
pub struct Program {
    pub name: String,
    pub maps: Vec<MapDecl>,
    pub insns: Vec<Insn>,
}

impl Program {
    /// Raw `bpf_insn` stream as u64 words, the exact bytes
    /// `BPF_PROG_LOAD` takes.
    pub fn to_bits(&self) -> Vec<u64> {
        self.insns.iter().map(|i| i.to_bits()).collect()
    }
}

/// What a matching frame does (non-matching frames always pass — the
/// sound fallback, even for the ACL shape).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Redirect into the XSK map (the capture datapath).
    Redirect,
    /// Drop (ACL/drop lists).
    Drop,
}

/// A pointed compile error: the term (or edit) the kernel subset cannot
/// express, named — never a silent wrong answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    /// A term addressing an unsupported layer (not eth/vlan/ipv4/ipv6/
    /// icmp/udp/tcp — the cooked/802.11 roots never reach XDP).
    UnsupportedLayer { term: String },
    /// A term whose field is not a fixed-offset layout (records, Str
    /// fields, dynamic regions, containers > 4 bytes).
    UnsupportedField { term: String, why: String },
    /// A term whose operand the kernel subset cannot compile (u64/u128
    /// ints, Str values, ordering ops on non-integers).
    UnsupportedValue { term: String, why: String },
    /// A rewrite at a layer/path the translator subset does not cover.
    UnsupportedEdit { edit: String, why: String },
}

impl core::fmt::Display for CompileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedLayer { term } => {
                write!(f, "term `{term}`: layer not walkable by the eBPF subset")
            }
            Self::UnsupportedField { term, why } => write!(f, "term `{term}`: {why}"),
            Self::UnsupportedValue { term, why } => write!(f, "term `{term}`: {why}"),
            Self::UnsupportedEdit { edit, why } => write!(f, "edit `{edit}`: {why}"),
        }
    }
}

fn term_str(t: &Term) -> String {
    format!("{}.{}", t.layer, t.field)
}

/// Walk planning: which layers the term set needs.
#[derive(Default)]
struct Plan {
    l2_eth: bool,
    vlan: bool,
    v4: bool,
    v6: bool,
    l4_tcp: bool,
    l4_udp: bool,
    l4_icmp: bool,
    l4_icmpv6: bool,
}

impl Plan {
    fn needs_l3(&self) -> bool {
        self.v4 || self.v6 || self.needs_l4()
    }
    fn needs_l4(&self) -> bool {
        self.l4_tcp || self.l4_udp || self.l4_icmp || self.l4_icmpv6
    }
    /// A conjunction mixing mutually-exclusive layer terms can never
    /// hold (the engine agrees: every frame misses one side's layer).
    fn contradictory(&self) -> bool {
        (self.v4 && self.v6)
            || (self.l4_tcp && self.l4_udp)
            || (self.l4_tcp && self.l4_icmp)
            || (self.l4_udp && self.l4_icmp)
            || (self.l4_icmp && self.l4_icmpv6)
    }
}

fn plan_terms(terms: &[Term]) -> Result<Plan, CompileError> {
    let mut p = Plan::default();
    for t in terms {
        match t.layer {
            "eth" => p.l2_eth = true,
            "vlan" => {
                p.l2_eth = true;
                p.vlan = true;
            }
            "ipv4" => p.v4 = true,
            "ipv6" => p.v6 = true,
            "tcp" => p.l4_tcp = true,
            "udp" => p.l4_udp = true,
            "icmp" => p.l4_icmp = true,
            "icmpv6" => p.l4_icmpv6 = true,
            other => {
                return Err(CompileError::UnsupportedLayer {
                    term: format!("{other}.{}", t.field),
                });
            }
        }
    }
    Ok(p)
}

// --- the emitter ------------------------------------------------------------

/// Label-backpatching assembler.
struct E {
    insns: Vec<Insn>,
    patches: Vec<(usize, u32)>,
    labels: BTreeMap<u32, usize>,
    next_label: u32,
}

impl E {
    fn new() -> Self {
        Self {
            insns: Vec::new(),
            patches: Vec::new(),
            labels: BTreeMap::new(),
            next_label: 0,
        }
    }

    fn label(&mut self) -> u32 {
        let l = self.next_label;
        self.next_label += 1;
        l
    }

    fn place(&mut self, l: u32) {
        self.labels.insert(l, self.insns.len());
    }

    /// Jump (conditional or unconditional) to `l`; the offset is
    /// patched at [`E::finish`]. Conditional compares are JMP32 (low
    /// 32 bits, imm zero-extended): every operand the codegen emits is
    /// a u32-domain value, and the 64-bit JEQ sign-extends its imm —
    /// an addr like 192.168.0.0 would never compare equal there.
    fn jump(&mut self, op: Option<(JmpOp, u8, i32)>, l: u32) {
        self.patches.push((self.insns.len(), l));
        match op {
            Some((jop, reg, imm)) => self.insns.push(Insn::j32_imm(jop, reg, imm, 0)),
            None => self.insns.push(Insn::ja(0)),
        }
    }

    /// Conditional jump against another REGISTER.
    fn jump_reg(&mut self, op: JmpOp, dst: u8, src: u8, l: u32) {
        self.patches.push((self.insns.len(), l));
        self.insns.push(Insn::j64_reg(op, dst, src, 0));
    }

    fn raw(&mut self, i: Insn) {
        self.insns.push(i);
    }

    fn finish(mut self) -> Vec<Insn> {
        for (at, l) in &self.patches {
            let target = self.labels[l];
            let diff = target as i64 - (*at as i64 + 1);
            self.insns[*at].off = diff as i16;
        }
        self.insns
    }
}

/// The prologue: `r6 = data`, `r7 = data_end` (r1 keeps the ctx).
fn emit_prologue(e: &mut E) {
    e.raw(Insn::ldx_w(P_DATA, 1, XDP_MD_DATA));
    e.raw(Insn::ldx_w(P_END, 1, XDP_MD_DATA_END));
}

fn emit_action(e: &mut E, action: Action, maps: &mut Vec<MapDecl>) {
    match action {
        Action::Redirect => {
            // bpf_redirect_map(xskmap, rx_queue_index, 0): match ⇒ the
            // capture socket; the helper's own return IS the verdict.
            maps.push(MapDecl {
                idx: MAP_IDX_XSK,
                kind: MapKind::XskMap,
                key_size: 4,
                value_size: 4,
                max_entries: 64,
            });
            e.raw(Insn::ldx_w(2, 1, XDP_MD_RX_QUEUE));
            let [a, b] = Insn::ld_imm64(1, MAP_IDX_XSK, 0, Some(0));
            e.raw(a);
            e.raw(b);
            e.raw(Insn::mov64_imm(3, 0));
            e.raw(Insn::call(BPF_FUNC_redirect_map));
            e.raw(Insn::exit());
        }
        Action::Drop => {
            e.raw(Insn::mov64_imm(0, XDP_DROP));
            e.raw(Insn::exit());
        }
    }
}

// --- the walk ---------------------------------------------------------------

/// Bounds-check a POINTER in `ptr` (need bytes readable), miss on
/// overrun. `ptr` must be a packet address (r6-relative); the check is
/// `ptr + need - 1 <= data_end`.
fn emit_ptr_bounds(e: &mut E, ptr: u8, need: usize, miss: u32) {
    e.raw(Insn::mov64_reg(R5, ptr));
    e.raw(Insn::add64_imm(R5, need.saturating_sub(1) as i32));
    e.jump_reg(JmpOp::Gt, R5, P_END, miss);
}

/// r{dst} = the layer-relative pointer `r6 + base + rel` where the base
/// may be static or the runtime L3/L4 offset register.
#[derive(Clone, Copy)]
enum Base {
    /// Static offset from data (eth fields: 0).
    Abs(i32),
    /// The L3 runtime offset register (r8).
    L3,
    /// The L4 runtime offset register (r9).
    L4,
}

impl Base {
    fn emit_ptr(self, e: &mut E, dst: u8, rel: i32) {
        match self {
            Self::Abs(off) => {
                e.raw(Insn::mov64_reg(dst, P_DATA));
                e.raw(Insn::add64_imm(dst, off + rel));
            }
            Self::L3 => {
                e.raw(Insn::mov64_reg(dst, P_DATA));
                e.raw(Insn::add64_reg(dst, P_L3));
                e.raw(Insn::add64_imm(dst, rel));
            }
            Self::L4 => {
                e.raw(Insn::mov64_reg(dst, P_DATA));
                e.raw(Insn::add64_reg(dst, P_L4));
                e.raw(Insn::add64_imm(dst, rel));
            }
        }
    }
}

/// The L2-only raw gate (the auto_start mirror): first nibble 4/6 ⇒ a
/// RAW ip frame — the eth/vlan layers are absent, so their terms are
/// false (miss). Non-raw frames fall through to the eth walk.
fn emit_raw_gate(e: &mut E, miss: u32) {
    let raw = e.label();
    let ethish = e.label();
    // A zero-length frame is `unknown` start (no layers at all).
    emit_ptr_bounds(e, P_DATA, 1, miss);
    e.raw(Insn::ldx_b(R5, P_DATA, 0));
    e.raw(Insn::rsh64_imm(R5, 4));
    e.raw(Insn::and64_imm(R5, 0xf));
    e.jump(Some((JmpOp::Eq, R5, 4)), raw);
    e.jump(Some((JmpOp::Eq, R5, 6)), raw);
    e.jump(None, ethish);
    e.place(raw);
    e.jump(None, miss);
    e.place(ethish);
}

/// The L3 walk: `r8` = the L3 start offset — eth bounds, then up to 4
/// unrolled VLAN hops (eth.type 0x8100/0x88a8 ⇒ +4, the QinQ rule),
/// each hop bounds-checked. When a vlan term is planned, the walk
/// additionally requires at least one tag (an untagged frame misses).
fn emit_l3_walk(e: &mut E, miss: u32) {
    emit_ptr_bounds(e, P_DATA, 14, miss);
    e.raw(Insn::mov64_imm(P_L3, 14));
    let done = e.label();

    for _ in 0..4 {
        // The ethertype sits at (r8 - 2): eth.type at 12 for the first
        // hop, the tag's own type at 14+4k-2 = 16+4k for later hops.
        e.raw(Insn::mov64_reg(R4, P_DATA));
        e.raw(Insn::add64_reg(R4, P_L3));
        e.raw(Insn::sub64_imm(R4, 2));
        emit_ptr_bounds(e, R4, 2, miss);
        // BE u16 → r5.
        e.raw(Insn::ldx_b(R5, R4, 0));
        e.raw(Insn::lsh64_imm(R5, 8));
        e.raw(Insn::ldx_b(R3, R4, 1));
        e.raw(Insn::or64_reg(R5, R3));
        let tag = e.label();
        e.jump(Some((JmpOp::Eq, R5, 0x8100)), tag);
        e.jump(Some((JmpOp::Eq, R5, 0x88a8)), tag);
        e.jump(None, done);
        e.place(tag);
        // The tag adds 4 bytes; the next ethertype (r8+2) must read.
        e.raw(Insn::mov64_reg(R4, P_DATA));
        e.raw(Insn::add64_reg(R4, P_L3));
        e.raw(Insn::add64_imm(R4, 4 + 1));
        e.jump_reg(JmpOp::Gt, R4, P_END, miss);
        e.raw(Insn::add64_imm(P_L3, 4));
    }
    e.place(done);
}

// --- term compilation -------------------------------------------------------

/// Compile the filter to an XDP program: matching frames take `action`
/// (plus the XSK redirect), everything else passes (sound fallback).
pub fn compile_filter(
    registry: &Registry,
    filter: &Filter,
    name: &str,
    action: Action,
) -> Result<Program, CompileError> {
    let terms = filter.terms();
    let plan = plan_terms(terms)?;
    let mut maps = Vec::new();
    let mut e = E::new();
    emit_prologue(&mut e);
    let miss = e.label();
    let matched = e.label();

    if terms.is_empty() {
        // The filterless capture tap: every frame matches (the stub).
        e.jump(None, matched);
    } else if plan.contradictory() {
        // Mixed exclusive-layer conjunctions never hold (the engine
        // agrees: every frame misses one side's layer). Honest fallback.
        e.jump(None, miss);
    } else {
        if !plan.needs_l3() {
            // L2-only: the auto_start mirror first — a raw v4/v6 frame
            // (first nibble 4/6) has NO eth layer, so eth/vlan terms are
            // false on it (the engine agrees). An empty term set (the
            // filterless capture tap) matches everything.
            if plan.l2_eth || plan.vlan {
                emit_raw_gate(&mut e, miss);
            }
            emit_ptr_bounds(&mut e, P_DATA, 14, miss);
            emit_term_chain(
                &mut e,
                registry,
                terms.iter().filter(|t| t.layer == "eth"),
                Base::Abs(0),
                miss,
            )?;
            if plan.vlan {
                // The tag walk, then the vlan fields.
                emit_l3_walk(&mut e, miss);
                emit_term_chain(
                    &mut e,
                    registry,
                    terms.iter().filter(|t| t.layer == "vlan"),
                    Base::Abs(14),
                    miss,
                )?;
            }
            e.jump(None, matched);
        } else {
            // The full walk mirrors auto_start: the first nibble 4/6 is
            // a RAW ip frame — no eth layer (its terms are false) and
            // P_L3 = 0; anything else walks eth (+ tags) and then the
            // family nibble at r8.
            let v4 = e.label();
            let v6 = e.label();
            let raw_v4 = e.label();
            let raw_v6 = e.label();
            let ethish = e.label();
            // Zero-length frames are `unknown` start — miss.
            emit_ptr_bounds(&mut e, P_DATA, 1, miss);
            e.raw(Insn::ldx_b(R5, P_DATA, 0));
            e.raw(Insn::rsh64_imm(R5, 4));
            e.raw(Insn::and64_imm(R5, 0xf));
            e.jump(Some((JmpOp::Eq, R5, 4)), raw_v4);
            e.jump(Some((JmpOp::Eq, R5, 6)), raw_v6);
            e.jump(None, ethish);
            // Raw families: P_L3 = 0 (the frame IS the ip datagram);
            // eth/vlan layers are absent — their terms are false.
            e.place(raw_v4);
            e.raw(Insn::mov64_imm(P_L3, 0));
            if plan.l2_eth || plan.vlan {
                e.jump(None, miss);
            }
            e.jump(None, v4);
            e.place(raw_v6);
            e.raw(Insn::mov64_imm(P_L3, 0));
            if plan.l2_eth || plan.vlan {
                e.jump(None, miss);
            }
            e.jump(None, v6);
            // The eth (+ tag chain) path — the frame is ≥14 bytes here.
            e.place(ethish);
            emit_l3_walk(&mut e, miss);
            if plan.vlan {
                emit_term_chain(
                    &mut e,
                    registry,
                    terms.iter().filter(|t| t.layer == "vlan"),
                    Base::Abs(14),
                    miss,
                )?;
            }
            // Family dispatch on the version nibble at r8.
            e.raw(Insn::mov64_reg(R4, P_DATA));
            e.raw(Insn::add64_reg(R4, P_L3));
            e.raw(Insn::ldx_b(R5, R4, 0));
            e.raw(Insn::rsh64_imm(R5, 4));
            e.raw(Insn::and64_imm(R5, 0xf));
            e.jump(Some((JmpOp::Eq, R5, 4)), v4);
            e.jump(Some((JmpOp::Eq, R5, 6)), v6);
            e.jump(None, miss);
            // v4 branch: symmetric v6-only gate.
            e.place(v4);
            if plan.v6 {
                e.jump(None, miss);
            }
            emit_term_chain(
                &mut e,
                registry,
                terms.iter().filter(|t| t.layer == "ipv4"),
                Base::L3,
                miss,
            )?;
            if plan.needs_l4() {
                let l4 = emit_l4_dispatch(&mut e, 4, &plan, miss);
                for (kind, _, lbl) in &l4 {
                    e.place(*lbl);
                    emit_term_chain(
                        &mut e,
                        registry,
                        terms.iter().filter(|t| t.layer == *kind),
                        Base::L4,
                        miss,
                    )?;
                    e.jump(None, matched);
                }
            } else {
                e.jump(None, matched);
            }
            // v6 branch: a v4-only term set misses here (the engine's
            // absent-layer rule — every v6 frame fails an ipv4 term).
            e.place(v6);
            if plan.v4 {
                e.jump(None, miss);
            }
            emit_term_chain(
                &mut e,
                registry,
                terms.iter().filter(|t| t.layer == "ipv6"),
                Base::L3,
                miss,
            )?;
            if plan.needs_l4() {
                let l4 = emit_l4_dispatch(&mut e, 6, &plan, miss);
                for (kind, _, lbl) in &l4 {
                    e.place(*lbl);
                    emit_term_chain(
                        &mut e,
                        registry,
                        terms.iter().filter(|t| t.layer == *kind),
                        Base::L4,
                        miss,
                    )?;
                    e.jump(None, matched);
                }
            } else {
                e.jump(None, matched);
            }
        }
    }
    e.place(matched);
    emit_action(&mut e, action, &mut maps);
    e.place(miss);
    // The fallback is ALWAYS pass (the sound-fallback contract — even
    // for the ACL shape, a non-matching frame passes).
    e.raw(Insn::mov64_imm(0, XDP_PASS));
    e.raw(Insn::exit());
    Ok(Program {
        name: name.to_string(),
        maps,
        insns: e.finish(),
    })
}

/// [`compile_filter`] with the capture redirect action (the default
/// capture prefilter).
pub fn compile_capture_prefilter(
    registry: &Registry,
    filter: &Filter,
) -> Result<Program, CompileError> {
    compile_filter(registry, filter, "capture-prefilter", Action::Redirect)
}

/// [`compile_filter`] with the ACL drop action.
pub fn compile_acl(registry: &Registry, filter: &Filter) -> Result<Program, CompileError> {
    compile_filter(registry, filter, "acl", Action::Drop)
}

/// The L4 walk for a family branch: bounds + fragment guard (v4) /
/// fixed 40 (v6), `r9` = the L4 start, then the proto dispatch. Returns
/// the per-kind branch labels in dispatch order; the caller places
/// term code between them.
/// The L4 walk for a family branch: v4 (fragment guard + ihl) or v6
/// (the bounded RFC 8200 ext-chain skip), `r9` = the L4 start offset,
/// then the proto dispatch. Returns the per-kind branch labels in
/// dispatch order; the caller places term code between them.
fn emit_l4_dispatch(
    e: &mut E,
    family: u8,
    plan: &Plan,
    miss: u32,
) -> Vec<(&'static str, i32, u32)> {
    e.raw(Insn::mov64_reg(R4, P_DATA));
    e.raw(Insn::add64_reg(R4, P_L3));
    if family == 4 {
        emit_ptr_bounds(e, R4, 20, miss);
        // NOTE no fragment guard: the engine's ipv4 codec descends
        // into the L4 header whatever frag_off says (deliberately-
        // invalid packets are a feature — the dissected tcp/udp layer
        // exists, so its terms apply). The v6 ext-frag rule differs
        // (T17a made offset > 0 terminal THERE).
        // ihl → P_L4 = P_L3 + ihl*4 (P_L4 stays an OFFSET).
        e.raw(Insn::ldx_b(R5, R4, 0));
        e.raw(Insn::and64_imm(R5, 0xf));
        e.raw(Insn::lsh64_imm(R5, 2));
        e.raw(Insn::mov64_reg(P_L4, P_L3));
        e.raw(Insn::add64_reg(P_L4, R5));
        // The v4 proto byte.
        e.raw(Insn::ldx_b(R5, R4, 9));
    } else {
        // v6: P_L3 keeps the ipv6 header (its terms read Base::L3);
        // P_L4 starts at P_L3+40 and walks the RFC 8200 ext chain — a
        // bounded unrolled skip (the verifier-safety rule). r5 holds
        // the ipv6 next_header first, each ext header's own byte after.
        emit_ptr_bounds(e, R4, 40, miss);
        e.raw(Insn::mov64_reg(P_L4, P_L3));
        e.raw(Insn::add64_imm(P_L4, 40));
        e.raw(Insn::ldx_b(R5, R4, 6)); // the ipv6 next_header field
        let dispatch = e.label();
        for _hop in 0..8 {
            let is_ext = e.label();
            for nh in [0u8, 43, 44, 51, 60] {
                e.jump(Some((JmpOp::Eq, R5, nh as i32)), is_ext);
            }
            e.jump(None, dispatch);
            e.place(is_ext);
            // The ext header lives AT P_L4: its len byte at +1, and
            // frag(44) checks its 13-bit offset (BE u16 at +2) — a
            // non-initial fragment is terminal (the T17a rule).
            e.raw(Insn::mov64_reg(R4, P_DATA));
            e.raw(Insn::add64_reg(R4, P_L4));
            let not_frag = e.label();
            e.jump(Some((JmpOp::Ne, R5, 44)), not_frag);
            e.raw(Insn::ldx_b(R3, R4, 2));
            e.raw(Insn::and64_imm(R3, 0x1f));
            e.jump(Some((JmpOp::Ne, R3, 0)), miss);
            e.raw(Insn::ldx_b(R3, R4, 3));
            e.raw(Insn::and64_imm(R3, 0xf8));
            e.jump(Some((JmpOp::Ne, R3, 0)), miss);
            e.place(not_frag);
            // Size: ah(51) = (len+2)*4; frag = 8; the rest = (len+1)*8.
            e.raw(Insn::mov64_imm(R3, 0));
            e.raw(Insn::ldx_b(R3, R4, 1));
            let ah = e.label();
            let units8 = e.label();
            let shared_advance = e.label();
            e.jump(Some((JmpOp::Eq, R5, 51)), ah);
            e.jump(None, units8);
            e.place(ah);
            e.raw(Insn::add64_imm(R3, 2));
            e.raw(Insn::lsh64_imm(R3, 2));
            e.jump(None, shared_advance);
            e.place(units8);
            let not_frag_sz = e.label();
            e.jump(Some((JmpOp::Ne, R5, 44)), not_frag_sz);
            e.raw(Insn::mov64_imm(R3, 8));
            e.jump(None, shared_advance);
            e.place(not_frag_sz);
            e.raw(Insn::add64_imm(R3, 1));
            e.raw(Insn::lsh64_imm(R3, 3));
            e.place(shared_advance);
            // The chain pointer: the CONSUMED header's own next byte
            // (at P_L4+0) names what follows — read BEFORE advancing
            // (the terminal header's byte 0 is its own data, not a
            // next-header). R2 ferries the size past the read; R3 the
            // chain byte past the bounds check (whose scratch is r5).
            e.raw(Insn::mov64_reg(R2, R3));
            e.raw(Insn::mov64_reg(R4, P_DATA));
            e.raw(Insn::add64_reg(R4, P_L4));
            e.raw(Insn::ldx_b(R3, R4, 0));
            e.raw(Insn::add64_reg(P_L4, R2));
            e.raw(Insn::mov64_reg(R4, P_DATA));
            e.raw(Insn::add64_reg(R4, P_L4));
            emit_ptr_bounds(e, R4, 8, miss);
            e.raw(Insn::mov64_reg(R5, R3));
        }
        // The 8-hop budget ran out mid-chain: unwalkable → fallback.
        e.jump(None, miss);
        e.place(dispatch);
        // P_L4 is the terminal L4 start. NO bounds here: r5 carries
        // the terminal next-header (emit_ptr_bounds would clobber it),
        // and every term load bounds-checks its own bytes.
    }
    let mut branches = Vec::new();
    if plan.l4_tcp {
        branches.push(("tcp", 6, e.label()));
    }
    if plan.l4_udp {
        branches.push(("udp", 17, e.label()));
    }
    // icmp rides the v4 branch only; icmpv6 the v6 branch only (the
    // kinds differ — the engine's absent-layer rule does the rest).
    if plan.l4_icmp && family == 4 {
        branches.push(("icmp", 1, e.label()));
    }
    if plan.l4_icmpv6 && family == 6 {
        branches.push(("icmpv6", 58, e.label()));
    }
    for (_, proto, lbl) in &branches {
        e.jump(Some((JmpOp::Eq, R5, *proto)), *lbl);
    }
    e.jump(None, miss);
    branches
}

// --- term compilation -------------------------------------------------------

/// A conjunction chain: every term's success jumps to the NEXT term's
/// start (a fresh label); the last term's success lands on the caller's
/// continuation (the label placed right after the group) — a matching
/// term continues, a failing one jumps to `miss`.
fn emit_term_chain<'t>(
    e: &mut E,
    registry: &Registry,
    terms: impl Iterator<Item = &'t Term>,
    base: Base,
    miss: u32,
) -> Result<(), CompileError> {
    let group: Vec<&Term> = terms.collect();
    for t in group {
        let ok = e.label();
        emit_term(e, registry, t, base, ok, miss)?;
        e.place(ok);
    }
    Ok(())
}

/// One term: resolve the field through the schema + layouts, load, cmp.
/// `ok` is where a HOLDING term continues (the next term / the group
/// continuation); `miss` the fallback.
fn emit_term(
    e: &mut E,
    registry: &Registry,
    t: &Term,
    base: Base,
    ok: u32,
    miss: u32,
) -> Result<(), CompileError> {
    let codec = registry
        .get(t.layer)
        .ok_or_else(|| CompileError::UnsupportedLayer { term: term_str(t) })?;
    let schema = codec.schema();
    let resolved = schema
        .resolve(&t.field)
        .ok_or_else(|| CompileError::UnsupportedField {
            term: term_str(t),
            why: "field not in schema".into(),
        })?;
    let (field_name, kind) =
        match &resolved {
            ResolvedField::Field(f) => (f.name, f.kind),
            // FlagBit terms re-resolve the aggregate: t.field carries only
            // the aggregate name; the bit lives in the value.
            ResolvedField::FlagBit { parent, .. } => (parent.name, parent.kind),
            ResolvedField::RecordField { .. } => return Err(CompileError::UnsupportedField {
                term: term_str(t),
                why: "record sections are not fixed-offset (the dns/dhcp/opt paths stay userspace)"
                    .into(),
            }),
        };
    let field_schema = schema
        .field(field_name)
        .ok_or_else(|| CompileError::UnsupportedField {
            term: term_str(t),
            why: "field not in schema table".into(),
        })?;
    let layout = codec
        .layouts()
        .iter()
        .find(|(n, _)| *n == field_name)
        .map(|(_, l)| *l)
        .ok_or_else(|| CompileError::UnsupportedField {
            term: term_str(t),
            why: "no fixed layout for the field (dynamic region)".into(),
        })?;

    match (&t.value, kind) {
        (FilterTermValue::Int(want), FieldKind::U8 | FieldKind::U16 | FieldKind::U32) => {
            let v = emit_load(e, layout, base, miss)?;
            emit_int_cmp(e, v, t.op, *want, ok, miss)?;
        }
        (FilterTermValue::Int(want), FieldKind::FlagSet) => {
            // The engine's type-mismatch rule: an Int term against the
            // List-rendered aggregate is FALSE — mirror it (never a
            // silent different answer).
            let _ = want;
            e.jump(None, miss);
        }
        (FilterTermValue::Ipv4 { addr, prefix }, FieldKind::Ipv4) => {
            let v = emit_load(e, layout, base, miss)?;
            let mask: u32 = match prefix {
                None | Some(32) => u32::MAX,
                Some(0) => 0,
                Some(p) => u32::MAX << (32 - p),
            };
            let want: u32 = u32::from(*addr) & mask;
            e.raw(Insn::and64_imm(v, mask as i32));
            match t.op {
                FilterOp::Eq => {
                    e.jump(Some((JmpOp::Eq, v, want as i32)), ok);
                    e.jump(None, miss);
                }
                FilterOp::Ne => {
                    e.jump(Some((JmpOp::Eq, v, want as i32)), miss);
                    e.jump(None, ok);
                }
                _ => {
                    return Err(CompileError::UnsupportedValue {
                        term: term_str(t),
                        why: "ipv4 fields support only = and != in filters".into(),
                    });
                }
            }
        }
        (FilterTermValue::Ipv6 { addr, prefix }, FieldKind::Ipv6) => {
            // 16 bytes: two 64-bit halves, byte-loaded. Prefix p ≥ 64:
            // the high half exactly + the masked low half; p < 64: the
            // masked high half only (the engine's mask arithmetic
            // transposed — 64-bit constants ride registers).
            let octets = addr.octets();
            let (hi, lo) = (
                u64::from_be_bytes(octets[..8].try_into().expect("8")),
                u64::from_be_bytes(octets[8..].try_into().expect("8")),
            );
            let (at, len) = match layout {
                Layout::Bytes { at, len } => (at, len),
                _ => {
                    return Err(CompileError::UnsupportedField {
                        term: term_str(t),
                        why: "ipv6 fields need a bytes layout".into(),
                    });
                }
            };
            if len != 16 {
                return Err(CompileError::UnsupportedField {
                    term: term_str(t),
                    why: "ipv6 layout narrower than 16".into(),
                });
            }
            if !matches!(t.op, FilterOp::Eq | FilterOp::Ne) {
                return Err(CompileError::UnsupportedValue {
                    term: term_str(t),
                    why: "ipv6 fields support only = and != in filters".into(),
                });
            }
            let p = prefix.unwrap_or(128) as u32;
            if p >= 64 {
                // The 64-bit constants live in R2 (R3 is the load
                // destination — sharing it would self-compare).
                emit_const_u64(e, R2, hi);
                let a = emit_load_wide(e, base, at, 8, miss)?;
                let (lo_mask, lo_want) = if p == 64 {
                    (0u64, 0u64)
                } else if p >= 128 {
                    (u64::MAX, lo)
                } else {
                    let m = u64::MAX << (128 - p);
                    (m, lo & m)
                };
                match t.op {
                    FilterOp::Eq => {
                        e.jump_reg(JmpOp::Ne, a, R2, miss);
                        if lo_mask == 0 {
                            e.jump(None, ok);
                        } else {
                            let b = emit_load_wide(e, base, at + 8, 8, miss)?;
                            emit_const_u64(e, R2, lo_mask);
                            e.raw(Insn::and64_reg(b, R2));
                            emit_const_u64(e, R2, lo_want);
                            e.jump_reg(JmpOp::Ne, b, R2, miss);
                            e.jump(None, ok);
                        }
                    }
                    FilterOp::Ne => {
                        e.jump_reg(JmpOp::Ne, a, R2, ok);
                        if lo_mask == 0 {
                            e.jump(None, miss);
                        } else {
                            let b = emit_load_wide(e, base, at + 8, 8, miss)?;
                            emit_const_u64(e, R2, lo_mask);
                            e.raw(Insn::and64_reg(b, R2));
                            emit_const_u64(e, R2, lo_want);
                            e.jump_reg(JmpOp::Ne, b, R2, ok);
                            e.jump(None, miss);
                        }
                    }
                    _ => unreachable!("guarded above"),
                }
            } else {
                let hi_mask: u64 = if p == 0 { 0 } else { u64::MAX << (64 - p) };
                let want = hi & hi_mask;
                if hi_mask == 0 {
                    // /0: anything is a member (the engine's zero mask).
                    match t.op {
                        FilterOp::Eq => e.jump(None, ok),
                        FilterOp::Ne => e.jump(None, miss),
                        _ => unreachable!("guarded above"),
                    }
                } else {
                    let a = emit_load_wide(e, base, at, 8, miss)?;
                    emit_const_u64(e, R2, hi_mask);
                    e.raw(Insn::and64_reg(a, R2));
                    emit_const_u64(e, R2, want);
                    match t.op {
                        FilterOp::Eq => {
                            e.jump_reg(JmpOp::Ne, a, R2, miss);
                            e.jump(None, ok);
                        }
                        FilterOp::Ne => {
                            e.jump_reg(JmpOp::Ne, a, R2, ok);
                            e.jump(None, miss);
                        }
                        _ => unreachable!("guarded above"),
                    }
                }
            }
        }
        (FilterTermValue::Mac(want), FieldKind::Mac) => {
            let (at, len) = match layout {
                Layout::Bytes { at, len } => (at, len),
                _ => {
                    return Err(CompileError::UnsupportedField {
                        term: term_str(t),
                        why: "mac fields need a bytes layout".into(),
                    });
                }
            };
            if len < 6 {
                return Err(CompileError::UnsupportedField {
                    term: term_str(t),
                    why: "mac layout narrower than 6".into(),
                });
            }
            // Per-byte compares; Ne polarity = any difference matches.
            for (i, b) in want.iter().enumerate() {
                base.emit_ptr(e, R4, (at + i) as i32);
                emit_ptr_bounds(e, R4, 1, miss);
                e.raw(Insn::ldx_b(R3, R4, 0));
                match t.op {
                    FilterOp::Eq => e.jump(Some((JmpOp::Ne, R3, *b as i32)), miss),
                    FilterOp::Ne => e.jump(Some((JmpOp::Ne, R3, *b as i32)), ok),
                    _ => {
                        return Err(CompileError::UnsupportedValue {
                            term: term_str(t),
                            why: "mac fields support only = and != in filters".into(),
                        });
                    }
                }
            }
            if t.op == FilterOp::Eq {
                e.jump(None, ok);
            } else {
                e.jump(None, miss);
            }
        }
        (FilterTermValue::Names(want), FieldKind::FlagSet) => {
            let window = emit_load(e, layout, base, miss)?;
            let mut mask: u32 = 0;
            for name in want {
                let pos =
                    field_schema
                        .bit_pos(name)
                        .ok_or_else(|| CompileError::UnsupportedValue {
                            term: term_str(t),
                            why: format!("unknown flag `{name}`"),
                        })?;
                mask |= 1u32 << pos;
            }
            e.raw(Insn::and64_imm(window, mask as i32));
            match t.op {
                FilterOp::Eq => {
                    e.jump(Some((JmpOp::Ne, window, mask as i32)), miss);
                    e.jump(None, ok);
                }
                FilterOp::Ne => {
                    e.jump(Some((JmpOp::Ne, window, mask as i32)), ok);
                    e.jump(None, miss);
                }
                _ => {
                    return Err(CompileError::UnsupportedValue {
                        term: term_str(t),
                        why: "flagsets support only = and != in filters".into(),
                    });
                }
            }
        }
        (FilterTermValue::FlagBit { name, set }, FieldKind::FlagSet) => {
            let pos = field_schema
                .bit_pos(name)
                .ok_or_else(|| CompileError::UnsupportedValue {
                    term: term_str(t),
                    why: format!("unknown flag bit `{name}`"),
                })?;
            let window = emit_load(e, layout, base, miss)?;
            e.raw(Insn::and64_imm(window, (1u64 << pos) as i32));
            // Engine: contains == set (op-polarized: Ne complements).
            let (jump_zero, target) = match (t.op, set) {
                (FilterOp::Eq, true) | (FilterOp::Ne, false) => (true, miss),
                (FilterOp::Eq, false) | (FilterOp::Ne, true) => (false, miss),
                _ => {
                    return Err(CompileError::UnsupportedValue {
                        term: term_str(t),
                        why: "flag bits support only = and != in filters".into(),
                    });
                }
            };
            if jump_zero {
                e.jump(Some((JmpOp::Eq, window, 0)), target);
                e.jump(None, ok);
            } else {
                e.jump(Some((JmpOp::Ne, window, 0)), target);
                e.jump(None, ok);
            }
        }
        (FilterTermValue::HexPrefix(want), FieldKind::Bytes | FieldKind::ByteList) => {
            if want.len() > 8 {
                return Err(CompileError::UnsupportedValue {
                    term: term_str(t),
                    why: "hex-prefix operands cap at 8 fixed bytes".into(),
                });
            }
            let at = match layout {
                Layout::Bytes { at, .. } => at,
                _ => {
                    return Err(CompileError::UnsupportedField {
                        term: term_str(t),
                        why: "hex prefixes need a bytes layout".into(),
                    });
                }
            };
            for (i, b) in want.iter().enumerate() {
                base.emit_ptr(e, R4, (at + i) as i32);
                emit_ptr_bounds(e, R4, 1, miss);
                e.raw(Insn::ldx_b(R3, R4, 0));
                match t.op {
                    FilterOp::Eq => e.jump(Some((JmpOp::Ne, R3, *b as i32)), miss),
                    FilterOp::Ne => e.jump(Some((JmpOp::Ne, R3, *b as i32)), ok),
                    _ => {
                        return Err(CompileError::UnsupportedValue {
                            term: term_str(t),
                            why: "bytes fields support only = and != in filters".into(),
                        });
                    }
                }
            }
            if t.op == FilterOp::Eq {
                e.jump(None, ok);
            } else {
                e.jump(None, miss);
            }
        }
        (FilterTermValue::Str(_), _) => {
            return Err(CompileError::UnsupportedValue {
                term: term_str(t),
                why: "string fields stay in the userspace engine (the dhcp6/sll shapes)".into(),
            });
        }
        _ => {
            return Err(CompileError::UnsupportedValue {
                term: term_str(t),
                why: "operand/field-kind mismatch".into(),
            });
        }
    }
    Ok(())
}

fn emit_int_cmp(
    e: &mut E,
    v: u8,
    op: FilterOp,
    want: u128,
    ok: u32,
    miss: u32,
) -> Result<(), CompileError> {
    if want > u32::MAX as u128 {
        return Err(CompileError::UnsupportedValue {
            term: format!("int operand {want}"),
            why: "exceeds the 32-bit imm subset".into(),
        });
    }
    let imm = want as i32;
    match op {
        FilterOp::Eq => e.jump(Some((JmpOp::Eq, v, imm)), ok),
        FilterOp::Ne => e.jump(Some((JmpOp::Ne, v, imm)), ok),
        FilterOp::Lt => e.jump(Some((JmpOp::Lt, v, imm)), ok),
        FilterOp::Le => e.jump(Some((JmpOp::Le, v, imm)), ok),
        FilterOp::Gt => e.jump(Some((JmpOp::Gt, v, imm)), ok),
        FilterOp::Ge => e.jump(Some((JmpOp::Ge, v, imm)), ok),
    }
    e.jump(None, miss);
    Ok(())
}

/// Build a 64-bit constant in `dst` (LD_IMM64; map=None plain).
fn emit_const_u64(e: &mut E, dst: u8, v: u64) {
    let [a, b] = Insn::ld_imm64(dst, v as u32, (v >> 32) as u32, None);
    e.raw(a);
    e.raw(b);
}

/// Load a big-endian integer (≤ 4 bytes) into r3 (scratch), or extract
/// a bit window (the patch engine's MSB-first convention, transposed).
fn emit_load(e: &mut E, layout: Layout, base: Base, miss: u32) -> Result<u8, CompileError> {
    let (at, shift, width) = match layout {
        Layout::Bytes { at, len } => (at, 0u8, (len * 8) as u8),
        Layout::Bits { at, shift, width } => (at, shift, width),
        _ => {
            return Err(CompileError::UnsupportedField {
                term: "load".into(),
                why: "re-encode regions are not loadable".into(),
            });
        }
    };
    let is_bits = matches!(layout, Layout::Bits { .. });
    // The container: ceil((shift + width)/8) bytes for windows; the
    // full width for plain ints.
    let need = if is_bits {
        (shift as usize + width as usize).div_ceil(8).max(1)
    } else {
        (width as usize) / 8
    };
    if need == 0 || need > 4 {
        return Err(CompileError::UnsupportedField {
            term: "load".into(),
            why: format!("width {need}B outside the 1..=4-byte subset"),
        });
    }
    let dst = R3;
    e.raw(Insn::mov64_imm(dst, 0));
    for i in 0..need {
        base.emit_ptr(e, R4, (at + i) as i32);
        emit_ptr_bounds(e, R4, 1, miss);
        e.raw(Insn::ldx_b(R5, R4, 0));
        if i + 1 < need {
            e.raw(Insn::lsh64_imm(R5, 8 * (need - 1 - i) as i32));
        }
        e.raw(Insn::or64_reg(dst, R5));
    }
    if is_bits {
        let bits = need * 8;
        let right = bits - shift as usize - width as usize;
        if right > 0 {
            e.raw(Insn::rsh64_imm(dst, right as i32));
        }
        let mask: u32 = if width >= 32 {
            u32::MAX
        } else {
            (1u32 << width) - 1
        };
        e.raw(Insn::and64_imm(dst, mask as i32));
    }
    Ok(dst)
}

/// Load a 5..8-byte BE integer (the v6 halves) into a scratch reg.
fn emit_load_wide(
    e: &mut E,
    base: Base,
    at: usize,
    len: usize,
    miss: u32,
) -> Result<u8, CompileError> {
    if len == 0 || len > 8 {
        return Err(CompileError::UnsupportedField {
            term: "load".into(),
            why: "wide loads cap at 8 bytes".into(),
        });
    }
    let dst = R3;
    e.raw(Insn::mov64_imm(dst, 0));
    for i in 0..len {
        base.emit_ptr(e, R4, at as i32 + i as i32);
        emit_ptr_bounds(e, R4, 1, miss);
        e.raw(Insn::ldx_b(R5, R4, 0));
        if i + 1 < len {
            e.raw(Insn::lsh64_imm(R5, 8 * (len - 1 - i) as i32));
        }
        e.raw(Insn::or64_reg(dst, R5));
    }
    Ok(dst)
}

// --- the translate subset ---------------------------------------------------

/// One rewrite for the translator: a layer kind, the field's layout
/// offset within it, its width, and the new wire bytes (the caller
/// resolves the CLI path through the registry layouts and serializes
/// the operand via the engine's own `serialize_field_value`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edit {
    /// The field's layer kind (eth/ipv4/ipv6/tcp/udp).
    pub kind: &'static str,
    /// The field's layout offset relative to its layer start.
    pub at: usize,
    /// The layout width in bytes.
    pub width: usize,
    /// The new bytes (exactly `width` long, big-endian).
    pub value: Vec<u8>,
}

/// A checksum to re-fold after the edits (RFC 1624 incremental): the
/// 16-bit checksum field's layer-relative offset, plus WHICH edits feed
/// it — the coverage the engine's scope walk computes (ipv4.checksum ←
/// ipv4-header edits; tcp/udp.checksum ← own-layer edits + the
/// pseudo-header's src/dst edits).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChecksumTarget {
    /// The checksum layer kind.
    pub kind: &'static str,
    /// The checksum field's layer-relative offset.
    pub at: usize,
    /// Indices into the edit list whose old/new bytes fold into this
    /// checksum (empty = re-fold over nothing = a no-op rewrite).
    pub contrib: Vec<usize>,
}

/// The translator: fixed-offset same-width rewrites with incremental
/// checksum re-folds over `bpf_csum_diff`. The oracle is the T14
/// engine — for same-width in-place edits the incremental fold and the
/// full recompute are byte-identical (RFC 1624 §3, pinned by test).
///
/// `checksums` names the derived checksum fields to keep valid; the
/// caller derives the list from the edited fields (any ipv4 header
/// edit ⇒ `ipv4.checksum`; ipv4/ipv6 src/dst or own-layer edits ⇒ the
/// l4 checksum) — the same policy the engine's scope walk applies.
pub fn compile_translate(
    registry: &Registry,
    edits: &[Edit],
    checksums: &[ChecksumTarget],
) -> Result<Program, CompileError> {
    let mut e = E::new();
    emit_prologue(&mut e);
    let miss = e.label();
    // Walk: eth bounds; L3 dispatch if any edit/checksum sits at L3/L4.
    let needs_l3 = edits
        .iter()
        .any(|ed| matches!(ed.kind, "ipv4" | "ipv6" | "tcp" | "udp"))
        || checksums
            .iter()
            .any(|c| matches!(c.kind, "ipv4" | "ipv6" | "tcp" | "udp"));
    emit_ptr_bounds(&mut e, P_DATA, 14, miss);
    let mut v4: Option<u32> = None;
    let mut v6: Option<u32> = None;
    if needs_l3 {
        emit_l3_walk(&mut e, miss);
        let a = e.label();
        let b = e.label();
        e.raw(Insn::mov64_reg(R4, P_DATA));
        e.raw(Insn::add64_reg(R4, P_L3));
        e.raw(Insn::ldx_b(R5, R4, 0));
        e.raw(Insn::rsh64_imm(R5, 4));
        e.raw(Insn::and64_imm(R5, 0xf));
        e.jump(Some((JmpOp::Eq, R5, 4)), a);
        e.jump(Some((JmpOp::Eq, R5, 6)), b);
        e.jump(None, miss);
        v4 = Some(a);
        v6 = Some(b);
    }
    // Emit the edit bodies per family branch (v4 / v6 / L2-only).
    let done = e.label();
    if let Some(a) = v4 {
        e.place(a);
        emit_edit_body(&mut e, registry, edits, checksums, Some(4), miss, done)?;
        e.jump(None, done);
    }
    if let Some(b) = v6 {
        e.place(b);
        emit_edit_body(&mut e, registry, edits, checksums, Some(6), miss, done)?;
        e.jump(None, done);
    }
    if v4.is_none() && v6.is_none() {
        // L2-only edits (eth fields): no walk.
        emit_edit_body(&mut e, registry, edits, checksums, None, miss, done)?;
    }
    e.place(done);
    e.raw(Insn::mov64_imm(0, XDP_PASS));
    e.raw(Insn::exit());
    e.place(miss);
    e.raw(Insn::mov64_imm(0, XDP_PASS));
    e.raw(Insn::exit());
    Ok(Program {
        name: "translate".to_string(),
        maps: Vec::new(),
        insns: e.finish(),
    })
}

/// The per-family edit body: rewrites at runtime layer bases, then the
/// checksum re-folds (csum_diff chained over the old/new byte pairs,
/// the stored complement folded back).
#[allow(clippy::too_many_arguments)]
fn emit_edit_body(
    e: &mut E,
    registry: &Registry,
    edits: &[Edit],
    checksums: &[ChecksumTarget],
    family: Option<u8>,
    miss: u32,
    done: u32,
) -> Result<(), CompileError> {
    // The L4 offset must be computed before tcp/udp edits/checksums.
    let needs_l4 = edits.iter().any(|ed| matches!(ed.kind, "tcp" | "udp"))
        || checksums.iter().any(|c| matches!(c.kind, "tcp" | "udp"));
    if needs_l4 && family.is_some() {
        match family {
            Some(4) => {
                // 20-byte header + ihl walk (fragments: translate only
                // initial fragments — pointed fallback otherwise).
                e.raw(Insn::mov64_reg(R4, P_DATA));
                e.raw(Insn::add64_reg(R4, P_L3));
                emit_ptr_bounds(e, R4, 20, miss);
                e.raw(Insn::ldx_b(R5, R4, 6));
                e.raw(Insn::and64_imm(R5, 0x1f));
                e.jump(Some((JmpOp::Ne, R5, 0)), miss);
                e.raw(Insn::ldx_b(R5, R4, 7));
                e.jump(Some((JmpOp::Ne, R5, 0)), miss);
                e.raw(Insn::ldx_b(R5, R4, 0));
                e.raw(Insn::and64_imm(R5, 0xf));
                e.raw(Insn::lsh64_imm(R5, 2));
                // P_L4 stays an OFFSET (the Base::L4 convention).
                e.raw(Insn::mov64_reg(P_L4, P_L3));
                e.raw(Insn::add64_reg(P_L4, R5));
            }
            Some(6) => {
                e.raw(Insn::mov64_reg(R4, P_DATA));
                e.raw(Insn::add64_reg(R4, P_L3));
                emit_ptr_bounds(e, R4, 40, miss);
                e.raw(Insn::mov64_reg(P_L4, P_L3));
                e.raw(Insn::add64_imm(P_L4, 40));
            }
            _ => {}
        }
    }
    // Rewrites: per edit, at its layer's runtime base. Each edit parks
    // its OLD bytes at the stack slot (r10 - width) and folds into every
    // checksum it contributes to RIGHT HERE (the stack copy is live
    // only until the next edit — the RFC 1624 composition composes
    // across edits through the stored field itself).
    for (ei, ed) in edits.iter().enumerate() {
        let base = layer_base(ed.kind)?;
        if ed.value.len() != ed.width {
            return Err(CompileError::UnsupportedEdit {
                edit: format!("{}@{}", ed.kind, ed.at),
                why: format!(
                    "value {} bytes ≠ width {} (same-width rewrites only)",
                    ed.value.len(),
                    ed.width
                ),
            });
        }
        // Bounds for the edit span AND its enclosing word(s): the
        // checksum folds run over WORD-ALIGNED ranges (a one-byte edit
        // at an odd offset moves the LOW byte of its word — diffing the
        // lone byte would fold it as a high byte and corrupt the sum).
        // All walk bases are even, so the layer-relative parity decides.
        let misalign = ed.at & 1;
        let span = misalign + ed.width + (misalign + ed.width) % 2; // even
        let word_at = ed.at & !1;
        base.emit_ptr(e, R4, word_at as i32);
        emit_ptr_bounds(e, R4, span, miss);
        // Old bytes (the whole aligned span) → the stack slot.
        for i in 0..span {
            e.raw(Insn::ldx_b(R5, R4, i as i16));
            e.raw(Insn::stx_b(10, -(span as i16) + i as i16, R5));
        }
        // Move to the edit position within the word span.
        if misalign == 1 {
            e.raw(Insn::add64_imm(R4, 1));
        }
        // New bytes → in place (R4 keeps the edit pointer for the folds).
        for (i, b) in ed.value.iter().enumerate() {
            e.raw(Insn::mov64_imm(R5, *b as i32));
            e.raw(Insn::stx_b(R4, i as i16, R5));
        }
        // Per contributing checksum: seed from the CURRENT stored value,
        // one csum_diff over the aligned old/new span, carry-fold,
        // complement, store BE (kernel signature: csum_diff(from=r1,
        // from_size=r2, to=r3, to_size=r4, seed=r5)).
        for c in checksums {
            if !c.contrib.contains(&ei) {
                continue;
            }
            let cbase = layer_base(c.kind)?;
            // Save the WORD-ALIGNED edit pointer (r0 is scratch inside
            // the body — the final verdict MOV overwrites it).
            e.raw(Insn::mov64_reg(R0, R4));
            e.raw(Insn::sub64_imm(R0, misalign as i32));
            // Seed: the stored checksum as the raw fold (~stored).
            cbase.emit_ptr(e, R4, c.at as i32);
            emit_ptr_bounds(e, R4, 2, miss);
            e.raw(Insn::ldx_b(R5, R4, 0));
            e.raw(Insn::lsh64_imm(R5, 8));
            e.raw(Insn::ldx_b(R3, R4, 1));
            e.raw(Insn::or64_reg(R5, R3));
            e.raw(Insn::xor64_imm(R5, 0xffff));
            // The diff over the aligned old/new span.
            e.raw(Insn::mov64_reg(1, 10));
            e.raw(Insn::add64_imm(1, -(span as i32)));
            e.raw(Insn::mov64_imm(2, span as i32));
            e.raw(Insn::mov64_reg(3, R0));
            e.raw(Insn::mov64_imm(4, span as i32));
            e.raw(Insn::mov64_reg(5, R5));
            e.raw(Insn::call(BPF_FUNC_csum_diff));
            e.raw(Insn::mov64_reg(R5, R0));
            // Carry-fold twice, complement, store BE at the field.
            for _ in 0..2 {
                e.raw(Insn::mov64_reg(R3, R5));
                e.raw(Insn::rsh64_imm(R3, 16));
                e.raw(Insn::and64_imm(R5, 0xffff));
                e.raw(Insn::add64_reg(R5, R3));
            }
            e.raw(Insn::xor64_imm(R5, 0xffff));
            cbase.emit_ptr(e, R4, c.at as i32);
            e.raw(Insn::mov64_reg(R3, R5));
            e.raw(Insn::rsh64_imm(R3, 8));
            e.raw(Insn::and64_imm(R3, 0xff));
            e.raw(Insn::and64_imm(R5, 0xff));
            e.raw(Insn::stx_b(R4, 0, R3));
            e.raw(Insn::stx_b(R4, 1, R5));
        }
    }
    let _ = (registry, done);
    Ok(())
}

fn layer_base(kind: &str) -> Result<Base, CompileError> {
    match kind {
        "eth" => Ok(Base::Abs(0)),
        "ipv4" | "ipv6" => Ok(Base::L3),
        "tcp" | "udp" => Ok(Base::L4),
        other => Err(CompileError::UnsupportedEdit {
            edit: other.to_string(),
            why: "layer not walkable by the translate subset".into(),
        }),
    }
}

/// The ICMPv4-echo XDP_TX responder (the T33 `listen` fast-path arm):
/// an echo request becomes a reply in place — swap eth src/dst and ipv4
/// src/dst (a sum-preserving swap: the ipv4 checksum stays valid),
/// rewrite icmp type 8→0 and fold the delta into the icmp checksum.
pub fn compile_responder() -> Program {
    let mut e = E::new();
    emit_prologue(&mut e);
    let miss = e.label();
    emit_ptr_bounds(&mut e, P_DATA, 38, miss);
    // eth.type == 0x0800 (BE u16 at 12).
    e.raw(Insn::ldx_b(R4, P_DATA, 12));
    e.raw(Insn::lsh64_imm(R4, 8));
    e.raw(Insn::ldx_b(R5, P_DATA, 13));
    e.raw(Insn::or64_reg(R4, R5));
    e.jump(Some((JmpOp::Ne, R4, 0x0800)), miss);
    // Version 4, proto 1.
    e.raw(Insn::ldx_b(R4, P_DATA, 14));
    e.raw(Insn::rsh64_imm(R4, 4));
    e.jump(Some((JmpOp::Ne, R4, 4)), miss);
    e.raw(Insn::ldx_b(R5, P_DATA, 14 + 9));
    e.jump(Some((JmpOp::Ne, R5, 1)), miss);
    // ihl ≥ 5 (r4 holds the byte) → r9 = 14 + ihl*4.
    e.raw(Insn::ldx_b(R4, P_DATA, 14));
    e.raw(Insn::and64_imm(R4, 0xf));
    e.jump(Some((JmpOp::Lt, R4, 5)), miss);
    e.raw(Insn::lsh64_imm(R4, 2));
    e.raw(Insn::add64_imm(R4, 14));
    e.raw(Insn::mov64_reg(P_L4, R4));
    // icmp at r9: bounds + type == 8.
    e.raw(Insn::mov64_reg(R4, P_DATA));
    e.raw(Insn::add64_reg(R4, P_L4));
    emit_ptr_bounds(&mut e, R4, 8, miss);
    e.raw(Insn::ldx_b(R5, R4, 0));
    e.jump(Some((JmpOp::Ne, R5, 8)), miss);
    // Swap eth addrs.
    for (i, j) in [(0i16, 6i16), (1, 7), (2, 8), (3, 9), (4, 10), (5, 11)] {
        e.raw(Insn::ldx_b(R2, P_DATA, i));
        e.raw(Insn::ldx_b(R3, P_DATA, j));
        e.raw(Insn::stx_b(P_DATA, i, R3));
        e.raw(Insn::stx_b(P_DATA, j, R2));
    }
    // Swap ipv4 src/dst (26..30 ↔ 30..34).
    for (i, j) in [(26i16, 30i16), (27, 31), (28, 32), (29, 33)] {
        e.raw(Insn::ldx_b(R2, P_DATA, i));
        e.raw(Insn::ldx_b(R3, P_DATA, j));
        e.raw(Insn::stx_b(P_DATA, i, R3));
        e.raw(Insn::stx_b(P_DATA, j, R2));
    }
    // icmp type → 0; the fold loses the old type word's contribution:
    // fold' = fold − 0x0800 ≡ fold + ~0x0800 (one's complement, the
    // end-around carry folded below).
    e.raw(Insn::mov64_imm(R3, 0));
    e.raw(Insn::stx_b(R4, 0, R3));
    // r5 = BE stored checksum at l4+2 → fold = ~stored.
    e.raw(Insn::ldx_b(R5, R4, 2));
    e.raw(Insn::lsh64_imm(R5, 8));
    e.raw(Insn::ldx_b(R3, R4, 3));
    e.raw(Insn::or64_reg(R5, R3));
    e.raw(Insn::xor64_imm(R5, 0xffff));
    // + 0xF7FF (the one's complement of 0x0800), end-around fold.
    e.raw(Insn::mov64_imm(R3, 0xf7ff));
    e.raw(Insn::add64_reg(R5, R3));
    for _ in 0..2 {
        e.raw(Insn::mov64_reg(R3, R5));
        e.raw(Insn::rsh64_imm(R3, 16));
        e.raw(Insn::and64_imm(R5, 0xffff));
        e.raw(Insn::add64_reg(R5, R3));
    }
    e.raw(Insn::xor64_imm(R5, 0xffff));
    // Store BE.
    e.raw(Insn::mov64_reg(R3, R5));
    e.raw(Insn::rsh64_imm(R3, 8));
    e.raw(Insn::and64_imm(R3, 0xff));
    e.raw(Insn::and64_imm(R5, 0xff));
    e.raw(Insn::stx_b(R4, 2, R3));
    e.raw(Insn::stx_b(R4, 3, R5));
    e.raw(Insn::mov64_imm(0, XDP_TX));
    e.raw(Insn::exit());
    e.place(miss);
    e.raw(Insn::mov64_imm(0, XDP_PASS));
    e.raw(Insn::exit());
    Program {
        name: "icmp-echo-responder".to_string(),
        maps: Vec::new(),
        insns: e.finish(),
    }
}

/// The flow-table feed: an XDP pass-through counting v4 TCP/UDP flows
/// by their 4-tuple into a hash map (16-byte key: src[4] dst[4]
/// proto sport dport + 3 zero pad). The userspace reader drains the
/// same map (the live `wrex stats` substrate, T24b's feed).
pub fn compile_flow_table() -> Program {
    let mut e = E::new();
    emit_prologue(&mut e);
    let done = e.label();
    emit_ptr_bounds(&mut e, P_DATA, 38, done);
    // eth.type 0x0800 + version 4.
    e.raw(Insn::ldx_b(R4, P_DATA, 12));
    e.raw(Insn::lsh64_imm(R4, 8));
    e.raw(Insn::ldx_b(R5, P_DATA, 13));
    e.raw(Insn::or64_reg(R4, R5));
    e.jump(Some((JmpOp::Ne, R4, 0x0800)), done);
    e.raw(Insn::ldx_b(R4, P_DATA, 14));
    e.raw(Insn::rsh64_imm(R4, 4));
    e.jump(Some((JmpOp::Ne, R4, 4)), done);
    // ihl ≥ 5 → r9 = 14 + ihl*4 (ports need 4 bytes).
    e.raw(Insn::ldx_b(R4, P_DATA, 14));
    e.raw(Insn::and64_imm(R4, 0xf));
    e.jump(Some((JmpOp::Lt, R4, 5)), done);
    e.raw(Insn::lsh64_imm(R4, 2));
    e.raw(Insn::add64_imm(R4, 14));
    e.raw(Insn::mov64_reg(P_L4, R4));
    e.raw(Insn::mov64_reg(R4, P_DATA));
    e.raw(Insn::add64_reg(R4, P_L4));
    emit_ptr_bounds(&mut e, R4, 4, done);
    // proto 6/17 else pass.
    e.raw(Insn::ldx_b(R5, P_DATA, 14 + 9));
    let is_flow = e.label();
    e.jump(Some((JmpOp::Eq, R5, 6)), is_flow);
    e.jump(Some((JmpOp::Eq, R5, 17)), is_flow);
    e.jump(None, done);
    e.place(is_flow);
    // Key on the stack at r10-16 (src 4, dst 4, proto 1, sport 2,
    // dport 2, 3 zero pad — the stack is pre-zeroed… in-kernel it is
    // NOT; zero the pad explicitly).
    let key: i16 = -16;
    for i in 0..16 {
        e.raw(Insn::mov64_imm(R3, 0));
        e.raw(Insn::stx_b(10, key + i, R3));
    }
    for (i, at) in (0..4usize).map(|i| (i, 14 + 12 + i)) {
        e.raw(Insn::ldx_b(R3, P_DATA, at as i16));
        e.raw(Insn::stx_b(10, key + i as i16, R3));
    }
    for (i, at) in (0..4usize).map(|i| (i, 14 + 16 + i)) {
        e.raw(Insn::ldx_b(R3, P_DATA, at as i16));
        e.raw(Insn::stx_b(10, key + 4 + i as i16, R3));
    }
    e.raw(Insn::ldx_b(R3, P_DATA, 14 + 9));
    e.raw(Insn::stx_b(10, key + 8, R3));
    e.raw(Insn::mov64_reg(R4, P_DATA));
    e.raw(Insn::add64_reg(R4, P_L4));
    e.raw(Insn::ldx_b(R3, R4, 0));
    e.raw(Insn::stx_b(10, key + 9, R3));
    e.raw(Insn::ldx_b(R3, R4, 1));
    e.raw(Insn::stx_b(10, key + 10, R3));
    e.raw(Insn::ldx_b(R3, R4, 2));
    e.raw(Insn::stx_b(10, key + 11, R3));
    e.raw(Insn::ldx_b(R3, R4, 3));
    e.raw(Insn::stx_b(10, key + 12, R3));
    // lookup(map, key): r0 = value ptr or 0.
    e.raw(Insn::mov64_reg(2, 10));
    e.raw(Insn::add64_imm(2, key as i32));
    let [a, b] = Insn::ld_imm64(1, MAP_IDX_FLOW, 0, Some(0));
    e.raw(a);
    e.raw(b);
    e.raw(Insn::call(BPF_FUNC_map_lookup_elem));
    let absent = e.label();
    e.jump(Some((JmpOp::Eq, R0, 0)), absent);
    // present: *(u32*)r0 += 1.
    e.raw(Insn::ldx_w(R3, R0, 0));
    e.raw(Insn::add64_imm(R3, 1));
    e.raw(Insn::stx_w(R0, 0, R3));
    e.jump(None, done);
    e.place(absent);
    // absent: insert 1 (map_update_elem signature: map=r1, key=r2,
    // value=r3, flags=r4).
    e.raw(Insn::mov64_imm(R3, 1));
    e.raw(Insn::stx_w(10, key - 8, R3));
    e.raw(Insn::mov64_reg(3, 10));
    e.raw(Insn::add64_imm(3, (key - 8) as i32));
    e.raw(Insn::mov64_reg(2, 10));
    e.raw(Insn::add64_imm(2, key as i32));
    e.raw(Insn::mov64_imm(4, 0));
    e.raw(Insn::call(BPF_FUNC_map_update_elem));
    e.place(done);
    e.raw(Insn::mov64_imm(0, XDP_PASS));
    e.raw(Insn::exit());
    Program {
        name: "flow-table".to_string(),
        maps: vec![MapDecl {
            idx: MAP_IDX_FLOW,
            kind: MapKind::Hash,
            key_size: 16,
            value_size: 4,
            max_entries: 65536,
        }],
        insns: e.finish(),
    }
}

#[cfg(test)]
mod tests {
    // The differential suites (VM verdict vs the filter engine over the
    // standard registry + the golden corpora) live in
    // crates/wrex/tests/ebpf_differential.rs — this crate cannot depend on
    // wrex (cycle), and the real registry lives there. In-crate units cover
    // the compiler's pointed-error surface over a schema-only registry and
    // the translator's walk mechanics on hand-built frames.
    use super::*;
    use alloc::vec;

    fn mock_registry() -> Registry {
        // Schema-only stand-ins suffice for the pointed-error surface: the
        // compiler consults schemas + layouts, never codecs' read/write.
        wrex_core::Registry::empty()
    }

    #[test]
    fn unknown_layer_is_pointed() {
        let reg = mock_registry();
        let e = Filter::parse(&reg, "nope.duration=1").ok();
        // parse itself validates against the registry first (unknown layer
        // → FilterError at startup); the compiler sees only valid terms.
        assert!(e.is_none());
    }

    #[test]
    fn empty_terms_emit_stub() {
        // With no registry codecs, an empty filter still compiles: the
        // filterless capture tap is the always-redirect stub.
        let reg = mock_registry();
        let f = Filter::parse(&reg, "").unwrap();
        let p = compile_capture_prefilter(&reg, &f).unwrap();
        assert!(p.insns.last().is_some_and(|i| i.code == 0x95));
        assert_eq!(p.maps.len(), 1);
        assert_eq!(p.maps[0].kind.kernel_id(), 17); // BPF_MAP_TYPE_XSKMAP (the uapi enum)
    }

    /// A hand-built eth+ipv4+udp frame (the craft golden's wire bytes)
    /// for the translator mechanics.
    fn udp_frame() -> Vec<u8> {
        vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
            0x08, 0x00, // ethertype
            0x45, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x7c, 0xcb, 0x7f, 0x00,
            0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, // ipv4
            0x00, 0x00, 0x00, 0x35, 0x00, 0x0b, 0x3d, 0x27, // udp
            0xde, 0xad, 0xbe, 0xef, // payload
        ]
    }

    /// The translator rewrites a udp port at the L4 base computed by the
    /// ihl walk — the walk mechanics, pinned without the engine.
    #[test]
    fn translate_rewrites_udp_port() {
        let reg = mock_registry();
        let prog = compile_translate(
            &reg,
            &[Edit {
                kind: "udp",
                at: 2, // dport
                width: 2,
                value: vec![0x35, 0x00],
            }],
            &[ChecksumTarget {
                kind: "udp",
                at: 6,
                contrib: alloc::vec![0],
            }],
        )
        .unwrap();
        let mut vm = crate::vm::Vm::new_default();
        let out = vm.run_with_packet(&prog, &udp_frame()).unwrap();
        // The edit landed at 34+2 (udp at 34, ihl 5): dport.
        assert_eq!(&out[36..38], &[0x35, 0x00]);
        // The checksum fold changed the stored value (engine-side
        // byte-identity is pinned by the differential).
        assert_ne!(&out[40..42], &udp_frame()[40..42]);
    }

    /// Too-short frames pass through unedited (the sound fallback).
    #[test]
    fn translate_short_frame_passes() {
        let reg = mock_registry();
        let prog = compile_translate(
            &reg,
            &[Edit {
                kind: "udp",
                at: 2,
                width: 2,
                value: vec![0x35, 0x00],
            }],
            &[],
        )
        .unwrap();
        let mut vm = crate::vm::Vm::new_default();
        let short = [0x45u8, 0x00, 0x00];
        let out = vm.run_with_packet(&prog, &short).unwrap();
        assert_eq!(out, short.to_vec());
    }

    /// Width mismatches are pointed compile errors (same-width subset).
    #[test]
    fn translate_width_mismatch_is_pointed() {
        let reg = mock_registry();
        let err = compile_translate(
            &reg,
            &[Edit {
                kind: "udp",
                at: 2,
                width: 2,
                value: vec![0x01],
            }],
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, CompileError::UnsupportedEdit { .. }), "{err}");
    }
}
