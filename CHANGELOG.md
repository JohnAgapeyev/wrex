# Changelog

All notable changes to wrex are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); until the 1.0
tranche lands (see `docs/roadmap.md`), versions are unreleased
development tranches — entries below are grouped by hardening pass and
tranche.

## [Unreleased]

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
