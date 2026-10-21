# ADR 2 — Codec selection: own the wire only where byte control is the point

- Status: accepted (recorded ahead of the first protocol tranche where
  the rule bites: BGP, SMB2/3, HTTP/2, HTTP/3)
- Date: 2026-10-21
- Companion policy: [ADR 1](0001-compile-time-registry.md) keeps the
  *registry* compile-time; this ADR decides *which parts of each
  protocol we implement at all*.

## Context

wrex is a packet crafting / mutation / dissection toolbox that also
grows client verbs (`query`, `http`, `scan`). Two instincts pull
against each other as the protocol surface expands:

- **Own everything**: high-level client libraries (reqwest, libcurl,
  hickory-as-a-client) are the wrong abstraction for a crafter — they
  own request construction, framing, and validation, and deliberately
  refuse to emit illegal representations. For a tool whose point
  includes *sending* those representations, owning the wire layer is
  justified more strongly than for an ordinary application.
- **Reuse everything**: every owned codec is a permanent testing and
  maintenance surface — specs evolve, real implementations exhibit
  undocumented quirks, extensions accumulate. Owning a TLS stack or
  an SMB session layer would be a multi-year liability with near-zero
  value for the tool's differentiators.

The delivered tranches already followed a selection pattern without
writing the rule down: DNS, HTTP/1.x, DHCP, and all L2–L4 headers are
in-house (tractable, mutation-central); TLS is rustls (delegated);
wire parsing where cheap is httparse (reused) with the `http` crate as
the typed vocabulary.

## Decision

**Reimplement a wire codec only when both hold:**

1. **Precise byte control over that protocol is central to its value
   in wrex** — i.e. the tool must craft or mutate *that protocol's*
   fields, including deliberately invalid encodings; and
2. **Adapting an existing library's lowest exposed layer costs about
   as much as implementing the needed subset ourselves.**

**Otherwise reuse** — but always *behind the standard registry
contract*: a reused codec still lands as a `wrex-proto-*` crate
speaking `Codec` (`schema()`, `kind`, `rank`, `parents`, the
dissection/anomaly contract), so reuse is invisible to the CLI, the
filters, `wrex fields`, man pages, and completions. When a reused
codec cannot express a malformed variant, `wrex-mut`'s raw level
(`flip`/`raw`/`splice` over the byte buffer) remains the
arbitrary-byte authority — never bend the semantic layer around it.

**Validity stays a selectable policy, not an invariant** (the encode
engine's explicit-field-wins rule): the same codec serves ordinary
client verbs, crafting, dissection, and fuzzing without a second
representation.

### Per-protocol dispositions (advisory; each confirmed at its own
planning pass)

- **BGP** — reuse the wire codec (evaluate NetGauze `bgp-pkt`-class
  crates at planning; test whether their type-safe representations
  can express the malformed variants we need before committing); *own*
  only a minimal session driver (OPEN handshake to established state,
  inject crafted messages, capture replies) over the frozen
  `wrex-session` contract. No speaker, no RIB, no route selection.
- **SMB2/3** — reuse message definitions *and* session machinery
  (negotiate, authenticate, sign); wrex's contribution is crafted or
  mutated commands *inside* a working session. Maturity and coverage
  eval at planning; do not reimplement signing/encryption/auth.
- **HTTP/2** — hybrid: the binary framing layer is ownable if
  segment-level byte control is needed; HPACK and session semantics
  are reuse candidates.
- **HTTP/3** — heavily reuse: QUIC + TLS + QPACK via quinn-proto /
  rustls lineage (the hickory/dhcpro/reqwest oracle-lineage pattern
  extended to transport). wrex owns only the probe/mutation surface.
- **TLS** — delegated, stays delegated ([tranche 8a]); see also the
  note below on TLS-protocol fuzzing as a separate capability.

## The oracle inversion rule (verification requirement)

For **owned** codecs, the external crate is the differential oracle
(hickory-proto vs `wrex-proto-dns`, dhcproto vs `wrex-proto-dhcp`,
reqwest/curl vs `wrex-http`). For **reused** codecs that arrangement
is self-confirming — diffing against the thing we wrapped proves
nothing. Every reused-codec tranche must instead carry one of:

- differential against a *different* implementation lineage
  (tshark/golden corpora, a cross-target comparison), or
- specification-derived known-answer vectors.

## Consequences

- One protocol may be fully in-house, another a registry-shaped
  wrapper over a third-party crate, a third delegating connection
  setup to a full client — the public surface (CLI verbs, filter
  language, output formats) stays uniform regardless of origin.
- A reused codec can later be swapped for an in-house one (or vice
  versa) without changing the rest of the tool; that escape hatch is
  part of the point.
- The selection rule is applied at *tranche planning*, and the
  disposition is recorded there (the T7b/T8 pattern), not improvised
  mid-tranche.

## Note on TLS-protocol fuzzing

Crafting *malformed but correctly authenticated* TLS records
requires session keys and record-layer cryptography; arbitrary byte
mutation of an encrypted record fails authentication before the
interesting fields. TLS-protocol fuzzing is therefore a separate
specialized capability — never a prerequisite for HTTPS crafting,
never scope-crept into the rustls delegation. If ever chartered, it
composes with the lossless-dissection span model via rustls's
unbuffered-style access.