# Changelog

All notable changes to wrex are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); until the 1.0
tranche lands (see `docs/roadmap.md`), versions are unreleased
development tranches — entries below are grouped by hardening pass and
tranche.

## [Unreleased]

### Added — hardening pass 3 (field-coverage doctrine)

- **G1 strategy-completeness audit** (`wrex-test::gates`, gated in
  `tests/field_coverage.rs`): the schema as the completion oracle —
  every codec's own strategy must randomize every settable schema
  field (derived/dissect-only/recorded exemptions aside). The first
  run found 37 unrandomized fields across 9 codecs; the sweep fixed
  the strategies and **caught two real bugs**: the ipv4 flags
  renderer emitted the stale `[df,mf]` order and silently dropped
  `res`, and **the T18a flags repair itself was wire-inverted** —
  RFC 791 puts MF at word bit 13 (0x2000; Linux `IP_MF`,
  etherparse `byte6&0x20`) with the reserved bit at 15, while the
  landed schema mapped `mf` onto the reserved position; the committed
  frag corpus self-confirmed (tshark: `ip.flags.rb=1`). The schema now
  matches the RFC wire order `[res,df,mf]`, the frag carve + `ClearMf`
  rewrite moved to 0x2000, and the corpus was regenerated.
- **G2 bit-toggle sweep** (same gate file): every FlagSet aggregate,
  every named bit — toggle-on renders exactly the bit, lands where the
  span map says (aggregate window / byte-aligned / scattered sub-bit),
  and passes both stack oracles; toggle-off clears. 23 bits across
  7 aggregates. Also caught the MLDv2-query sources over-read
  (8 payload bytes leaking into the region) and — with G6 — the dead
  tshark dstopts arm.
- **G3 RFC position vectors** (KAV): wire bytes at hand-computed
  absolute offsets for every bit aggregate, RFC section per row (ipv4
  ver/ihl/tos/flags/frag_off, tcp data_off/flags, vlan TCI, the ipv6
  flow word, frag offset|M, hopopts len, icmpv6 na/ra flags, MLDv2
  flags/QRV, dhcp broadcast, dns qr/rd, icmp type/code/echo).
- **G6 differential key-completeness audit**: every scalar schema
  field of a compared codec must appear in at least one oracle map's
  attempted-comparison inventory (a new `compared` record on
  `DiffReport`; `compare()` methods return the full report), with a
  recorded-reason exemption table that is itself audited for
  staleness. The maps grew to carry what the oracles render: ipv4
  ver/ihl/tos/total_len/checksum/flags, tcp flags/data_off/urgent/
  checksum, udp/icmp/icmpv6 checksums + echo bodies, ipv6 ver/tclass/
  flow, ext lens, dhcp flags. The audit caught the **dead dstopts
  arm** (tshark nests ext headers inside the ipv6 dict; the top-level
  read never fired and the pass-2 drift guard checks key presence, not
  access paths) and the tshark-oracle **pcap path race** under
  parallel test threads (now unique per invocation).
- **HP3-c executable golden workflows** (`tests/cli_workflows.rs`):
  every `Today:` incantation of the use-case catalog runs in CI —
  12 offline workflows per-commit (foreign captures, reassembly,
  craft-by-hand, stream rewrite, normalize, stale checksums, spans,
  the dns pointer-target, mutation, diff, TLS fuzz, recipe replay)
  and 5 driver-dependent ones env-gated (scan, capture-then-inspect,
  send, fuzz-probe, replay-probe — verified under the `unshare -Urn`
  harness).
- **HP3-d grammar consolidation**: `wrex-core::options` — the five
  codec list grammars (ip/tcp/dhcp/dhcp6/icmpv6) ride one skeleton
  (tokenization, the known-name-gated split — the uniform fix for the
  bare-continuation-with-colon gotcha — pointed error mapping, the two
  TLV shapes, grid padding); value encoders and pending semantics
  stay codec-side. Net 57 lines retired; the skeleton's mutation
  coverage is now wrex-core's (0 missed).
- **HP3-e maintainability rails**: the mutants release gate extended
  with per-crate advisory kill-strength scores for every proto codec
  (`mutants-codecs` job; the wrex-core full-scope run promoted from
  measurement to GATED at its 0-missed state); the suite-time ratchet
  (`cargo xtask suitetime`, one capture-and-ratchet pass over the
  verify tests, >2x growth fails with the pointed name); the API
  surface ratchet (`cargo xtask api-snapshot`, per-crate
  public-API snapshots under `xtask/api-snapshots/`, checked in CI
  like the man pages — advisory while the snapshots settle).
- wrex-core kill-strength pass (the pass before HP3-a's gates):
  737 mutants, 312 missed → 0; `.cargo/mutants.toml` exclusions limited
  to provably-unkillable classes; two-tier mutants workflow (gating
  PR `--in-diff` run + full-scope release run).

### Added — 2026-10-23 extension planning pass (docs only)

- Roadmap extension: mission scoreboard (fusion-parity audit),
  hardening pass 3 charter (field-coverage doctrine + grammar
  consolidation + oracle-captured corpora + executable use-cases),
  planned tranches T19–T39 in priority waves (verb parity → analysis
  plane → transport/tunnels/eBPF kernel datapath → specialized
  capabilities → scale/1.0), open-decision register, and new standing
  rules (rule of three, deletion budget, API ratchet, eBPF
  compiled-artifacts).
- New companion planning documents: the use-case catalog
  (`docs/usecases.md`), the verification doctrine
  (`docs/verification.md`, incl. the IPv4-flags post-mortem),
  the deferral ledger (`docs/deferred.md`), and the backlog
  (`docs/backlog.md`).

### Added — hardening pass 2

- Formal + fuzz coverage for the two highest-risk modules: the
  span-patch engine (`fuzz_patch_engine`) and the `--filter` engine
  (`fuzz_filter`); Kani proofs for the filter `eval` core (operator
  semantics, CIDR mask safety) and the patch bit-window arithmetic.
- tshark field-map drift guard: a keys-present inventory test and a
  comparisons-are-live tamper test (a tshark release renaming a JSON
  key, or a map-side typo, now fails CI loudly instead of silently
  killing a comparison).
- Fault injection at the pcap-writer/stdout seams: mid-write faults
  propagate; faulted (partial) files never read back as clean captures;
  EPIPE-class stdout failures map to exit 1, never a panic.
- Foreign-capture compatibility: real text2pcap/editcap fixtures
  (classic pcap all four magic variants + pcapng) pinned by test.
- Event-schedule property suites for the h2 framing and session:
  arbitrary split feeds and housekeeping interleavings never desync
  outcomes; every fixture frame truncation is Need/Malformed/Hav only.
- Scheduled mutation testing (weekly cargo-mutants on wrex-core,
  artifacts + summary, no gate yet).
- Miri release-gate coverage for wrex-mut and wrex-fuzz (both verified
  Miri-safe).
- SAFETY-comment gate in CI: every unsafe site in wrex-io (the only
  crate with unsafe) must carry a SAFETY comment.
- Driver-test capability probes: missing `lo`/IPv6 on a runner skips
  with a notice instead of failing red.
- Fuzz corpora for every target (all 27 targets have committed seeds)
  and a libFuzzer dictionary.

### Fixed — hardening pass 2

- **pcapng Section Header Block was spec-nonconformant** (BOM written
  at offset 4 instead of 8): `wrex capture --pcapng` files were
  unreadable by Wireshark, and real pcapng files were unreadable by
  wrex. Both sides now speak RFC-standard SHB layout; verified
  bidirectionally against Wireshark 4.7.4.
- **Five fuzz targets had no `[[bin]]` declarations** (dissect_ipv6,
  dissect_icmpv6, dissect_dhcp, dissect_dhcp6, app_session): the CI
  fuzz loops referenced them and `cargo fuzz run` failed.
- **Four tshark differential arms were silently dead since tranche
  17a**: hopopts/routing/ah read as top-level layer keys (tshark nests
  them inside the `ipv6` dict), dstopts under a wrong name. Live
  again; chained same-kind ext headers compare match-by-value (the
  repeated-key collapse).
- Chained same-kind ext headers (dstopts,dstopts) false-mismatched in
  the newly-live tshark comparison — now match-by-value.

### Removed — hardening pass 2

- The non-Linux stub code in wrex-io (`#[cfg(not(target_os =
  "linux"))]` arms, `_unsupported` fields, `DriverError::
  UnsupportedPlatform`): macOS/BSD support is out of scope by owner
  decision; a non-Linux build now fails loudly at the libc FFI
  boundary instead of pretending to compile.

### Added — hardening pass 1

- Proptest failure persistence across every property suite (the
  committed differential regression file was being ignored before).
- MSRV check job (cargo check on the pinned 1.88 toolchain) — caught a
  real 1.88 regression in dhcp_differential on landing.
- Coverage gate (`--fail-under-lines 85`; measured baseline 88.6%
  lines / 71.5% branches).
- Per-PR fuzz smoke (5s/target against committed seed corpora, skipped
  for docs-only PRs).
- Doc-tests on the public grammar facades (previously zero).
- Unit coverage for every previously untested module (rx.rs, icmpv6
  options, http response, dhcp6, spec/codec, fuzz report) and the app
  surface (verbs.rs pure helpers, cli.rs grammar).

### Fixed — hardening pass 1

- NDP raw-option grid padding bug (RFC 4861 §4.6: Length counts the
  whole option; raw escapes emitted off-grid regions breaking
  roundtrip).
- A parallel-test race in the driver suite (two tests both capturing
  on `lo` grabbed each other's frames) — recv filters pin each test
  to its own traffic.
- dhcp_differential relied on match-scrutinee temporary lifetime
  extension (MSRV violation, accepted by newer rustc only).

## Tranche history

Pre-hardening development follows the tranche charters in
`docs/roadmap.md` (T1 workspace/engines through T17 IPv6 extension
headers and DHCPv6); the git history carries per-tranche summaries.
