# Changelog

All notable changes to wrex are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); until the 1.0
tranche lands (see `docs/roadmap.md`), versions are unreleased
development tranches — entries below are grouped by hardening pass and
tranche.

## [Unreleased]

### Added — performance differentials (informational rail)

- **`cargo xtask perf-diff`** (`xtask/src/perfdiff.rs`): wall-clock
  differentials vs the reference tools on equivalent output — the
  timing sibling of the logical differentials (which prove
  equivalence) and the criterion tripwires (which prove stability
  over time). Rows: tshark cold/text/jsonl/json over corpus-cycled
  pcaps (classic + pcapng), dig UDP + TCP against a harness-owned
  dnsmasq, curl cold 1KiB/1MiB + 100-URL keep-alive against an
  in-process HTTP/1.1 stub, nmap connect/SYN burst + connect
  defaults against a loopback listener farm. Warmup + interleaved
  reps, median + min + ours/theirs ratio, exact commands and
  attribution notes printed (the measured home of "key things they do
  that we don't"), JSON artifact under `target/perfdiff/`;
  release-profile precondition and `unshare -Urn` re-exec built in.
  Advisory forever — no gate reads the numbers (docs:
  verification.md "Performance differentials").

### Changed — performance pass 2 (direct render, data-sizes audit)

- **Direct JSON serialization** (`wrex-core/src/render.rs`): `DissectedPacket`,
  `LayerView` (fields through the shared name-rendering grammar), and `Anomaly`
  implement `Serialize` directly — the default `jsonl`/`json` paths no longer
  build a `serde_json::Value` tree (owned `String` keys per field, node
  allocs, drop walk) just to serialize it. Keys emit in the alphabetical
  order the tree form iterated in — byte-identical (all pinned-golden and
  differential suites pass). `render/jsonl`: **−79%** (966µs → 206µs per
  corpus pass); the `--spans`/`--frame` extras keep the tree form.
- **Single-buffer text rendering**: `dissect_to_text_spans` writes into one
  pre-sized `String` (no per-line `format!` allocation); `hexdump` writes
  directly (the old form allocated one `String` **per byte**); value
  rendering writes in place (no per-value `String`). `render/text`:
  **−58%** (940µs → 394µs).
- **Cumulative recv/replay** (jsonl default): 1.55ms → 560µs per corpus
  pass, **−64%** across both performance passes.
- Audited and deliberately left alone (each <3% with real API cost):
  `Value`'s 48-byte size (u128 alignment — boxing `Bytes`/`Vec`/`Cow`
  payloads would trade hot-path allocs for node size), codec-side dynamic
  key `format!` (~2% of dissect), `Registry::get` linear scans (cold,
  ~20 entries), `options_region` re-parse under the encode capacity
  estimate (early-exits on typical specs).

### Changed — performance pass 1 (allocation-profile tripwires)

Measured first (criterion tripwires + perf/callgrind/dhat attribution),
then optimized — every number below is from `cargo bench -p wrex-core`
(release profile; a runtime guard refuses dev-profile runs whose numbers
are meaningless).

- **Tripwire benches** (`benches/hotpaths.rs`): `render/{jsonl,text}`,
  `recv/jsonl` (end-to-end), `filter/matches`, `patch/setfield+scope-all`
  (the doctrine-mandated patch-engine tripwire), `retention/unknown-{1500B,
  9000B}` — the allocation-heavy hot paths were previously unbenched.
- **Encode budget** (`wrex-core/src/encode.rs`): the output buffer is sized
  up front via the `header_len` oracle (+ payload) — `BytesMut::with_capacity`
  replaces realloc-by-doubling (`RawVecInner::reserve` was **13.7% of encode
  cycles**); the deferred-`Patch` vec is engine-owned (`&mut Vec` in
  `EncodeCtx`) with the per-layer `Vec::new()`/`extend` growth removed.
  Encode: **−23%** (criterion: ~720ns → 555ns per eth+ipv4+udp+512B).
- **Zero-copy retention** (`dissect`): `IntoFrame` transfer trait — a caller
  holding a `Bytes` (the io drivers) hands it over by refcount; `frame` and
  `payload` are refcount slices, the per-packet full-frame + payload-region
  memcpys are gone (`retention/unknown-9000B`: **−30%**). Borrowed callers
  copy once up front, exactly as before.
- **`Cow<'static, str>` field keys** (`LayerView::fields`/`field_spans`,
  `LayerSpec::fields`): codecs insert their schema's `&'static str` names
  **borrowed** — the per-field `String` key allocation, key-content memcpy,
  and drop-glue teardown are deleted (dissect/corpus: **−30%**, patch:
  **−34%**). Ordering, serde, and output bytes identical (differential
  suites pass); dynamic keys (`opt.{i}.code`, `flags.syn`) stay `Owned`.
- **`format!` hoists**: sub-bit keys (`dissect`) and derived-field paths
  (`patch`) build via `schema::dotted_path` (manual `String` build), not
  the `format!` machinery (~3.5%/1.8% of their respective paths).
- **`recv`/`capture` dissect-on-demand** (`wrex/src/verbs.rs`): `--format
  raw|hex` with no `--filter`/`--tee` never dissects — the whole dissect
  cost was pure waste on that path.

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
- **HP3-b oracle-capture scenarios** (`cargo xtask corpus-capture`,
  `xtask/scenarios.rs`): one declarative harness — a veth pair split
  across two network namespaces inside the `unshare -Urn` sandbox,
  tcpdump (`--immediate-mode` — the mmap ring's block timeout never
  fires in the sandbox — and SIGTERM stops; a killed capture loses
  its userspace buffer), checksum offload disabled on both ends
  (captured-outbound veth frames otherwise carry unmaterialized
  checksum fields). Six committed foreign-lineage corpora:
  **kernel-carved v4 + v6 fragments** (the mf-bug's own corpus, the
  recorded T18a foreign-fragment deferral), ICMP echo, ARP, real
  DNS (dig × dnsmasq over UDP and TCP), kernel-TCP conversations —
  every frame sweeps the existing corpus gates. **The corpora
  demanded and delivered the two recorded correctness items**:
  (1) the **L4 checksum convention** — the pseudo-header covers the
  L4 message only, ext headers excluded (the kernel's own MLDv2
  reports through a Router-Alert hopopts disagreed with the T17a
  ext-inclusive fold by a constant; fixed on encode, verify and the
  patch walk, `ChecksumStart::UpperPacket` collapsing to `Layer`);
  (2) **fragment-carrier verify skipping** — `Facts::fragmented`
  (set by ipv4 mf/frag_off and the v6 frag codec): a single
  fragment can never verify (checksums fold over the original
  unfragmented message); the reassembled datagram verifies instead.
  The ip6ext + frag corpora regenerated under the corrected
  convention (a dev-time generator, the frag-corpus pattern).
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
