# ADR 3 — Codec dependency direction: parents are Cargo deps, dispatch stays registry strings

- Status: accepted (chartered at the T17 planning pass; landed by the
  T17-0 retrofit)
- Date: 2026-10-22
- Companions: [ADR 1](0001-compile-time-registry.md) keeps the registry
  compile-time — this ADR defines what "compile-time" now *guarantees*.
  [ADR 2](0002-protocol-selection.md) decides which protocols exist —
  this ADR decides how the implemented crates relate as build artifacts.

## Context

The registry cross-references codecs by kind string for two structurally
different relations:

- **parents** — the stacking relation. A child is craft-stackable and
  dissection-reachable *only through* its parents; dns without udp,
  icmpv6 without ipv6, are unreachable fragments.
- **dispatch targets** — the encapsulation relation. udp's port-53
  table names dns; ipv6's next-header table names icmpv6. The parent
  works fine without the child.

Both were string-mediated with nothing enforcing either, and the `wrex`
crate's features were eleven orthogonal switches with no closure
(`proto-dns = ["dep:wrex-proto-dns"]`, nothing more). A build like
`--no-default-features --features proto-dns` compiled and registered a
DNS codec with no udp/ipv4/ipv6/eth beneath it: chains fail with pointed
errors, dissection never reaches the kind, and — because the first
craft layer may start anywhere — bare-layer crafting half-succeeds.
Legal-but-half-working compositions are a shipped footgun, and they
hollow out ADR 1's own promise: if feature gates can assemble
fragments that cannot work, "compose builds down to exactly the codecs
wanted" means nothing. The meaningful composition axis is *which
protocols a build supports*, and the dependency graph should say so.

## Decision

Split the two relations by their true dependency semantics:

1. **Requires ⇒ Cargo dependency.** Every codec crate depends on the
   crates implementing its `parents` (the parent graph is a DAG at
   crate granularity: vlan→eth; arp/ip/ip6→eth,vlan; icmp→ip;
   icmpv6→ip6; udp/tcp→ip,ip6; dns/dhcp→udp; eth→none). `parents`
   arrays reference the parent crates' `pub const KIND` — the kind
   vocabulary is compile-checked and can no longer drift.
2. **Enhances ⇒ registry strings, unchanged.** Dispatch tables naming
   children stay kind strings: that edge cycles (udp ⇄ dns/dhcp — the
   tranche-7c in-crate stubs exist precisely because it cannot be a
   dep), and parent-without-child is the *meaningful* lean build —
   ipv6 without extension headers is exactly the pre-T17 degradation
   and stays selectable.
3. **Registration closure by construction.** Each codec crate exports
   `register(&mut Registry)`: register self, then ensure each parent
   crate's `register()` ran, dedup-guarded via `Registry::get`.
   Self-first keeps `wrex::standard()`'s fixed registration order
   byte-identical (the enumeration surfaces — `wrex fields`, man
   pages, completions, the "(registered: …)" error lists — are
   registration-ordered); presence, not order, is the guarantee.
   ADR 1's "one register line" seam becomes "parent deps + one
   `register()` call". The raw `Registry::register(&CODEC)` remains
   for bespoke single-codec registries (fuzz targets, isolation
   tests) — explicit choice, not a footgun.

## Consequences

- Child-without-parent becomes unbuildable (dep graph) and
  unconstructible through the documented seam (closure): a lean
  selection like `--features proto-dns` now registers a complete,
  parent-complete stack (dns, udp, ipv4, ipv6, eth, vlan) computed by
  cargo from the dep graph; `--no-default-features` builds the honest
  minimal (an empty registry — craft/dissect degrade pointedly, never
  crash). The lean axis that remains, parent-without-optional-child, is
  the one that actually works.
- Child crates gain in-crate integration tests against the real
  parent (dns asserting a port-53 udp datagram dissects into dns) —
  impossible before without stubs. The tranche-7c dispatch-*out*
  stubs remain for absent-kind degradation tests: dispatching into a
  child that is not registered degrades to the synthetic `unknown`
  layer, never fatal, by the tranche-1 engine contract.
- Parents are disjunctive (udp stacks on ipv4 *or* ipv6) while Cargo
  deps are conjunctive: family deps are all-or-nothing for now; a
  hypothetical v4-only embedder would need per-parent optional-dep
  features, which are additive if a real consumer asks (the
  "stability is a 1.0 event" rule).
- First-layer-anywhere craft is unchanged: deps guarantee presence,
  not stacking — bare `wrex craft tcp` as a stack start stays legal.
- Rejected alternatives: strings-only (the footgun — legal,
  half-working fragments); both-direction deps (cycles: udp⇄dns);
  per-parent feature matrices now (speculative complexity, zero
  embedders); core-level registration *validation* of parent presence
  (wrong layer — it would forbid legitimate single-codec test
  registries and police what construction already guarantees).
- ADR 1's extension seam description is amended accordingly: a new
  protocol crate declares its parent deps and one `register()` call;
  the registry itself stays compile-time and the ADR-1 decision is
  untouched.
