# ADR 0005 — eBPF loader ownership, the aya deviation, and the wrex-io syscall surface

## Status

Accepted (2026-11-06, tranche T23b/c — pulled forward from the
roadmap's aya recommendation at the T23 planning pass).

## Context

The T29 charter recommended reusing aya as the loader ("the rustls
precedent"), and the ecosystem's userspace-eBPF landscape was audited
at planning: aya (loader/ELF machinery, hand-rolls its own `bpf(2)`
via libc), uBPF (C — Microsoft's eBPF-for-Windows engine), rbpf (a
userspace VM/interpreter), libbpf-rs (C libbpf — the no-C-deps rule
out), xsk-rs (libxdp bindings — C again).

## Decision

**1. The loader is hand-rolled `bpf(2)` + netlink in `wrex-io::xdp`
(aya declined, for this tranche's shapes).** The compiled artifacts are
plain `bpf_insn` streams — no ELF containers, no relocations beyond
the map-fd immediates the loader rewrites in one pass. Aya's value is
the ELF/relocation machinery and its attach orchestration for
CO-RE programs; consuming it for instruction streams would add the
dependency's weight for none of its purpose, and its `BpfLoader`
still expects object files we do not produce. The syscall surface
kept is small and enumerable: `bpf(BPF_MAP_CREATE/BPF_PROG_LOAD/
MAP_UPDATE_ELEM)` + the rtnetlink XDP attach (~200 lines, every block
SAFETY-commented under the standing wrex-io gate). aya remains the
recorded migration path if relocatable-ELF codegen ever lands
(T25+'s filter-AST extensions, a future BTF story) — the roadmap's
open decision #5 is settled as "not aya today, aya-shaped tomorrow if
the artifact shape grows".

**2. The userspace VM stays in-crate (`wrex-ebpf::vm`) with a
recorded swap trigger.** The per-commit verdict differential needs an
executor that runs our generated straight-line programs; the hand-rolled
VM is scaffolding at the ScriptedDriver lineage (test double, never a
shipped wire engine), and no userspace VM — ours or rbpf's — proves
verifier-cleanliness (only the kernel does). Swap trigger: the VM ever
needing loops/JIT/verifier-grade checks → retire it for rbpf rather
than grow it. The authoritative gate is the kernel itself: the
privileged CI job carries `BPF_PROG_TEST_RUN` + live attach, the
per-commit differential carries the semantics everywhere else.

**3. `wrex-io` keeps `libc` as its single syscall vocabulary (nix
declined).** The crate's existing idiom — every driver from T1 on —
is raw `libc` with `// SAFETY:` comments under the per-commit CI
grep gate; nix covers none of the actually-dangerous surface (bpf(2),
SOL_XDP, sockaddr_xdp, rtnetlink message building) and would convert
only the generic 30% (socket/poll/mmap), splitting the idiom. Recorded
candidate: a chartered nix/rustix consolidation of the generic
syscall surface if the unsafe footprint keeps growing (AF_XDP TX, TC
egress) — the T17-0 retrofit precedent is the vehicle.

## Consequences

- Zero new third-party dependencies for the datapath; the unsafe
  surface is auditable in one module under the existing gate.
- The committed deviation from the roadmap's aya recommendation is
  recorded here and in the tranche entry; the swap triggers are
  ledger lines, not silent drift.
- **Hand-marshaled ABI constants come from the system headers, cited
  in the doc comments — never from memory** (the post-mortem rule the
  tranche's live-root debugging forced): the initial XSKMAP constant
  (42) was an unregistered type on every kernel, and the EINVAL it
  produced on two machines masqueraded as a kernel restriction until
  the header pass corrected it (17 — along with SOL_XDP 283, the
  RX-ring sockopt id 2, and the 32-byte umem_reg). The datapath probe
  creates the XSKMAP itself, the step-tagged attach errors name the
  refusing kernel call, and the kernel floor that remains is the
  cheap one: a build without `CONFIG_XDP_SOCKETS` refuses the XSKMAP
  and the transparent AF_PACKET fallback carries capture.