# wrex — Verification doctrine

How correctness is enforced as tranches keep landing. Adopted at the
2026-10-23 extension pass; **the machinery is chartered as hardening
pass 3 (HP3) in the [roadmap](roadmap.md) and lands before T19.** From
T19 on, every codec/verb tranche lands with the gates below wired
(the per-tranche checklist at the end) — the doctrine is a charter
checklist item, not an aspiration.

## Why this document exists: the mf bug

The motivating case. A T1-era bug — the ipv4 `flags` aggregate mapped
`mf` onto the reserved bit 13 — survived **every layer of the
methodology** until the T18a fragment-reassembly work happened to
introduce real fragmented captures. Craft emitted reserved-bit
packets; real fragmented captures dissected with no `mf` at all.

Why each gate passed:

| Gate | Why it passed |
|------|---------------|
| Proptest round-trip (256 cases) | **Symmetric error cancels**: craft wrote `mf` to bit 13, dissect read it from bit 13 — round-trip byte-perfect while both were wrong. |
| etherparse + tshark differential | The ipv4 strategy (verified post-hoc) samples `tos/id/ttl/frag_off/src/dst/options` and **never sets `flags`** — every compared frame had all flag bits zero. A bit-*position* error is invisible at value 0. |
| T14 identity sweep (per-field!) | It sets each field to *its own dissected value* under `Scope::none`. Self-value writes reproduce input by construction — an **engine** gate, structurally incapable of catching **semantics** errors. |
| Normalize fixed point | Zero-anomaly in ⇒ zero-anomaly out; flags=0 stays flags=0. |
| Golden corpus + expected.json | The T1 corpora contained no fragmented capture, and expected.json files are wrex-generated — a wrong-but-consistent value gets pinned as golden (self-confirmation). |
| Fuzz targets / Kani / Miri | Robustness and panic-freedom, not bit semantics. |

Two more catches confirm the pattern: the NS-SLLA 10-byte option
(T17b — a hand-rolled driver whose unit goldens *self-confirmed* until
the codec cross-checked it) and the pcapng SHB BOM (hardening pass 2 —
invisible until compared against real Wireshark). Every bug the
project has actually caught came from an **asymmetric oracle**: a real
capture, a spec vector, an independent lineage, or ground truth.

## The principle: self-consistency vs asymmetric oracles

The existing stack is mostly **self-consistency** (round-trips,
identity sweeps, fixed points, self-generated goldens) plus
**robustness** (fuzz, Miri, Kani panic-freedom). Neither class can
catch a systematic error shared by encode and decode. The doctrine
makes the **asymmetric layer complete at field granularity and
mechanically enforced**, instead of incidental:

| Class | Catches | Structurally cannot catch |
|-------|---------|---------------------------|
| Self-consistency (round-trip, identity, normalize, reassemble) | Engine logic: splicing, spans, geometry, re-encoding | Any error symmetric across encode/decode |
| Robustness (fuzz, Miri, Kani) | Panics, UB, arithmetic bounds, determinism | Bit/field *semantics* |
| **Asymmetric** (differentials, RFC vectors, foreign captures, ground truth, mutation kills) | **Everything above + systematic mapping errors** | (needs the other two for engine/robustness coverage) |

Three oracle kinds stay distinct and none is optional: **captured
corpora give realism, RFC vectors give authority, proptest strategies
give exhaustiveness.** Foreign quirks are never mistaken for contract
(see spec-vs-quirk annotations below).

## The field-coverage gates (HP3-a)

**G1 — Strategy completeness audit.** The schema already enumerates
every settable field; make it the completion oracle. For each
registered codec, run its strategy N times and assert every settable
schema field appears with ≥K distinct values; fail with a pointed
"`ipv4.flags` never randomized" list. Would have caught the mf bug at
its first run. Cost: one harness in wrex-test, near-zero per codec.
Retroactively applied to every existing codec at HP3 (expect to find
more instances of the class — that is the point).

**G2 — Bit-toggle sweep feeding the differential.** For every
`FlagSet` aggregate and named bit, generate a frame with that bit = 1,
assert it lands where the span map says, and **feed those frames into
the tshark/etherparse differential**. Fuses two half-gates into a
property: *differential coverage = schema coverage* — the differential
only ever sees values the strategies generate, so the sweep closes
the value blind spot systematically. Enum-ish fields: every named
variant exercised.

**G3 — RFC position vectors (KAV), mandatory per bit aggregate.**
Each codec ships a known-answer table asserting wire bytes/positions
for every bit-aggregate field, RFC section cited in a comment (the
`mf=bit 15` line in the ipv4 schema docs is what this looks like — as
a *test*, not a comment). The only oracle that catches a symmetric
encode/decode error deterministically at authoring time. Extend to
geometry: assert span layouts against an RFC-derived table, never
against the schema's own declarations (they share the bug surface).

**G4 — Mutation kill-list for codec crates.** The cargo-mutants release
gate extends to the proto crates (`mutants-codecs` job, advisory
first). A bit-mapping bug *is* a surviving mutant; layout/bit-packing
mutants must die. Track per-crate scores; promote codec crates to
gating once scores are healthy. Mutation testing is the audit that
proves G1–G3 are real, not theatrical. The wrex-core full-scope run is
**gated** since the kill-strength pass (737 mutants, 0 missed).

First recorded baseline (2026-10-28, local, `--no-shuffle` — the
scores are the product; the gap is the honest state: the codecs'
write paths are exercised mainly by the `wrex` crate's integration
suites, which cargo-mutants does not run per package):

| crate | mutants | missed | caught | unviable | timeouts |
|---|---|---|---|---|---|
| wrex-proto-eth | 31 | 12 | 15 | 4 | 0 |
| wrex-proto-arp | 19 | 7 | 7 | 5 | 0 |
| wrex-proto-vlan | 48 | 12 | 31 | 5 | 0 |
| wrex-proto-ip | 117 | 51 | 60 | 6 | 0 |
| wrex-proto-ip6 | 61 | 31 | 24 | 6 | 0 |
| wrex-proto-icmp | 27 | 9 | 12 | 6 | 0 |
| wrex-proto-icmpv6 | 258 | 65 | 180 | 13 | 0 |
| wrex-proto-udp | 54 | 14 | 34 | 6 | 0 |
| wrex-proto-tcp | 87 | 24 | 57 | 6 | 0 |
| wrex-proto-dns | 313 | 106 | 194 | 12 | 1 |
| wrex-proto-dhcp | 217 | 77 | 133 | 5 | 2 |
| wrex-proto-dhcp6 | 289 | 112 | 169 | 6 | 2 |
| wrex-proto-ip6ext | 308 | 160 | 115 | 32 | 1 |

**G5 — Foreign-value corpus policy.** Every codec's golden corpus
contains at least one **real foreign capture** (or fixture), and its
expected values are **tshark-reviewed, never wrex-generated**. One
foreign frame per codec breaks the self-confirmation loop. Delivered
by the [oracle-capture scenarios](#oracle-captured-corpora-hp3-b) (HP3-b)
rather than manual curation.

**G6 — Differential key-completeness audit.** The hardening-pass-2
drift guard checks the tshark map's keys are live; add the inverse —
every scalar schema field of a compared codec appears in the map's
compared set unless explicitly exempted with a recorded comment (the
dhcp-options exemption is the precedent shape). A silently
un-compared field is a field whose mapping bugs are invisible.

State-machine analog (for verb tranches): every outcome must be
reachable in ground truth — the env-gated `lo` tests already practice
this; T21's new `unfiltered` outcome, T29's XDP verdicts, etc. must
keep it.

## Oracle-captured corpora (HP3-b)

Differentials today are *ephemeral* — curl runs against a stub, bytes
flow, comparisons happen, nothing is retained. The scenario framework
makes them *persistent*: foreign-lineage traffic committed as corpus
artifacts, feeding every gate that runs over the golden corpora
(population, identity, normalize, reassemble, tshark differential)
plus the committed fuzz seed corpora.

**One declarative harness, not N scripts** (the rule of three from
day one): a scenario is a table row — *(foreign server, foreign
client invocation, network setup, tool optionality, expected frame
classes)*. Independence at every layer: server bytes from a foreign
library, client bytes from a foreign tool, capture container from
tcpdump/libpcap (which also keeps `wrex-pcap` continuously tested
against libpcap's writer lineage — the SHB-BOM class).

First-wave scenarios:

| Scenario | Server lineage | Client lineage | Feeds |
|----------|----------------|----------------|-------|
| DNS real traffic | hickory server (in-tree dep) | dig | EDNS/DO/compression coverage; T20 pre-stage |
| HTTP/1.1 + h2 | hyper | curl | header orders, HPACK patterns; `fuzz_h2_frame_decoder` seeds |
| h3/QUIC | quinn | curl --http3 (optional) | **T26 pre-stage**: initial packets decryptable via the RFC 9001 DCID-derived keys, cross-checkable against tshark's QUIC dissector |
| Kernel TCP conversations | kernel | curl/nc | **T22 options typing**; OS fingerprint signatures (T30 pre-stage) |
| Fragmentation | kernel (lo MTU lowered / veth 1500) | ping -M want | **the recorded T18a foreign-fragment deferral — the mf bug's own corpus** |
| ICMP variety | kernel | ping, traceroute | echo/TTL-exceeded corpus |
| ARP/NDP on veth | kernel | arping, ndisc6 | third-lineage check against the io::ndp hand-roll |
| Scan parity | listener farm in the namespace | **nmap vs wrex scan** | classification oracle for the *scan verb*, not just dissection |

(DHCP/DHCPv6 scenarios: evaluate the server lineage at HP3 planning —
dhcproto's server side or an optional dnsmasq tool scenario.)

Per scenario, the harness commits: the pcap (written by tcpdump), a
**manifest** (client command, tool versions, kernel sysctls, seed if
any, **spec-vs-quirk annotations** — "this server pads X:
RFC-permitted, not required" — so foreign quirks never silently
become contract), and expected values **tshark-reviewed before
commit**.

CI wiring: per-commit runs the *gates over the committed artifacts*
(cheap, deterministic); **generation runs on demand** (`cargo xtask
corpus-capture`) plus a release-gate freshness job that regenerates
and diffs *structurally* (frame classes, field fingerprints) — bytes
never match across runs (ephemeral ports, seqs, timestamps) and that
is fine: the committed snapshot is authoritative, regeneration is a
review workflow, like man pages without the bit-identity requirement.
Regeneration review starts advisory-with-report and promotes to
blocking once cycles prove the diff reviewable (recorded open
decision).

Honest constraints: pre-staging works ahead of codecs (QUIC captured
today is fuzz seed + tranche-ready verification material the day the
codec lands); veth-pair setups (not bare `lo`) for MTU-sensitive
scenarios; scapy stays optional-if-present (valid-but-unusual frames,
never a required dev-dep); the three oracle classes stay distinct.

## Executable golden workflows (HP3-c)

A catalog rots unless every entry is a test: `tests/cli_workflows.rs`
+ xtask scenarios running in the existing `unshare -Urn` harness,
organized by job instead of by crate. `WF-n` runs `UC-n`'s `Today:`
incantation from [usecases.md](usecases.md) end-to-end — offline
workflows per-commit, driver-dependent ones in the env-gated job.
Documentation cannot lie: every documented command is a command CI
actually runs.

## Maintainability rails (HP3-d/e)

**The grammar census (consolidation target).** Five codec crates carry
their own `options.rs` list-grammar implementation — dhcp (375
lines), dhcp6 (571), icmpv6 (388), ip (187), tcp (153), ~1,674 lines
total, each re-implementing tokenization, pending-continuation state,
hex/raw escapes, and error mapping. The genuinely common skeleton
moves to a shared `wrex-core` grammar/TLV module (legal under ADR 3 —
codecs already depend on core); each codec keeps a **declarative
table** of option parsers. **Honest boundary**: dhcp6's nested IAADDR
and icmpv6's prefix plastering push on any shared abstraction —
extract only the skeleton, leave value encoders codec-side;
over-generalizing those two costs more than the duplication saves.
Expected win: a few hundred lines retired and the mutation/coverage
story written once instead of five times.

The standing rails (added to the roadmap's standing rules):

- **Rule of three** — third instance of a pattern ⇒ extract to the
  shared layer (wrex-core for codecs, wrex-test for verification
  machinery) or record why not in the charter.
- **Deletion budget** — every planning pass answers "what does this
  tranche delete or retire?" (the non-Linux removal and the dns
  Kani-proof retirement are the precedents).
- **API surface ratchet** — advisory per-crate public-API snapshots
  in CI; "would we freeze this?" stays the pre-1.0 tie-breaker, now
  with a diff, so the eventual 1.0 API review is a diff instead of an
  excavation.
- **Crate-count discipline** — new crates only via chartered tranche;
  prefer growing existing crates (the T17 ip6ext multi-kind decision).
- **Tripwire-before-optimization** — hot paths get a bench before they
  get optimized; regressions fail the budget (the const-eval pass 5
  precedent: passes 1–4 silently regressed the checksum fast path and
  the tripwire bench caught it). Dissect pps on a fixed corpus,
  patch-engine ops, filter eval, capture loop — one bench each,
  advisory first, gating on >x% regression once stable.
- **Suite-time ratchet** — per-suite wall-clock recorded by xtask;
  >20% growth fails with a pointed name, so the test side of the
  doctrine doesn't bloat CI. Slow suites move to the extended gate
  (the Miri precedent).
- **Sanctioned duplication** — the only allowed copies are deliberate
  two-lineage cross-checks (io::ndp vs the icmpv6 codec; the
  oracle-capture "kernel vs wrex" rows extend the pattern).

## Per-tranche checklist (charter item from T19 on)

1. Gates wired: G1 strategy audit, G2 toggle sweep into the
   differential, G3 KAVs for every bit aggregate, G6 key completeness
   (codec tranches); outcome-reachability in ground truth (verb
   tranches).
2. An [oracle-capture scenario row](#oracle-captured-corpora-hp3-b)
   added for every new protocol.
3. Golden workflow tests for every UC the tranche closes.
4. Mutation scope extended to any new codec crate (G4).
5. Perf tripwires for any touched hot path; suite-time delta recorded.
6. Charter names: UCs closed, deferrals swept, what the tranche
   deletes.
