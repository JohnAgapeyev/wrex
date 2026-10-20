# ADR 1 — The protocol registry stays compile-time

- Status: accepted (tranche 7d — the "dynamic `.so` plugin ABI revisit")
- Date: 2026-10-20
- Supersedes: the open question in the tranche-1 standing rules
  ("no dynamic loading until the T7 ABI revisit says otherwise")

## Context

The roadmap's T7 charter carried a "dynamic `.so` plugin ABI revisit":
whether protocol codecs should become dynamically loadable so third
parties can extend `wrex` without recompiling. The tranche-1 contract
deliberately froze the opposite — a compile-time registry:

```rust
pub struct Registry { codecs: Vec<&'static dyn Codec>, … }
pub trait Codec: Send + Sync {
    fn schema(&self) -> &'static LayerSchema;
    …
}
```

A new protocol is a feature-gated `wrex-proto-*` crate plus one
`register` line in `wrex::standard()`; the CLI flags, `wrex fields`,
the filter language, man pages and completions enumerate from the
registry with zero per-protocol code. Six codecs landed this way
(eth, arp, ipv4, icmp, udp, tcp, dns, vlan).

## Decision

The registry stays compile-time. We will not design or ship a
dynamic `.so` codec ABI. The standing rule is retires from "until the
T7 ABI revisit says otherwise" to "unless a future ADR reopens it".

## Reasons

- **Rust has no stable ABI.** A loaded `.so` must be built with the
  exact same compiler version and flags as the host, or speak a
  hand-rolled C ABI. The first turns plugins into build artifacts of
  the host; the second forfeits everything that makes codecs cheap
  here: `&'static LayerSchema`/`FieldSchema` slices, `Value`,
  `Next`/`ReadOutcome`, `serde` derive, `bytes` — all would need a
  mirrored C surface with owned copies on both sides of the boundary.
- **The extension seam is already one line.** The compile-time
  registry delivers the feature-relevant part of pluggability —
  "add a protocol without touching the wrex crate" — via one
  workspace dependency, one feature and one `register` call. Feature
  gates compose builds down to exactly the codecs wanted.
- **The cost side of the ledger is empty.** `#![forbid(unsafe_code)]`
  holds across wrex-core and the codec crates; `dlopen`/`libloading`
  is a new unsafe surface, a new dependency class, a new audit
  surface, and a new fuzzing boundary — for a benefit nobody has
  asked for: no user request, no downstream consumer, no blocked
  protocol.
- **Verification assumes type knowledge.** The differential stack
  (proptest strategies per codec, etherparse/tshark oracles, cargo-fuzz
  targets, golden corpora, Kani harnesses) is keyed to concrete types
  and registered schemas. A dynamically loaded codec arrives with
  none of that: every quality gate would need a "trust the plugin"
  carve-out, which is the one thing the per-tranche verification
  contract forbids.

## Consequences

- The T7 "dissect-only profiles" item is dropped (the revisit's other
  half): no codec needs a registry-level dissect-only toggle; dns
  record sections (`an.0.*`) already carry the dissect-only surface
  for record data.
- Protocols stay reviewable units: in-tree, feature-gated, CI-gated,
  MSRV-gated. Third-party distributions are source trees or forks,
  not binary drops.
- If a real requirement arrives (out-of-tree protocols that cannot
  upstream), reopen with a new ADR; the likely shape then is a stable
  C ABI over an owned, versioned schema format — a much larger design
  than the current registry, and it should not be accreted onto it.