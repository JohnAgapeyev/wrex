# wrex — Roadmap

Charters only. Each tranche is frozen into an execution plan at its own
planning pass **before** any implementation; nothing on this page is a
contract, and nothing here breaks the contracts of the delivered
tranches. Numbers are landing order, not priority beyond "T(n) before
T(n+1)".

## Tranches

- **T1 — Foundation + L2–L4** — ✅ delivered. Cargo workspace + core
  engines (encode/dissect/filter/checksum), in-house eth/arp/ipv4/icmp/
  udp/tcp codecs, Linux `AF_PACKET` send/recv drivers, the `wrex` CLI
  (craft/dissect/send/recv/iface/fields/completions), per-commit CI, and
  the verification stack (proptest, differential vs etherparse + tshark,
  real-capture corpus, Miri, cargo-fuzz targets, advisory coverage).
  Post-charter additions already in the tree: generated man pages
  (`cargo xtask man`), shell completions, and registry-driven clap args
  for the craft/send field flags.
- **T2 — scan** — ✅ delivered. Sans-IO `Session` trait (event/queue
  state machine à la quinn-proto; frozen at T2 planning) in the new
  `wrex-session` crate plus the shared sans-IO runtime loop; TCP
  SYN/connect + UDP + ICMP scan orchestration over drivers in the new
  `wrex-scan` crate (probe table, retransmit state machine, reply
  matching, ICMP-unreachable quote attribution); seeded jitter via an
  in-house SplitMix64 (no `rand` dependency); `wrex scan` with
  IPv4/CIDR/range targets, port lists, a committed top-100 TCP
  default, `--rate/--interval/--jitter/--seed/--retries/--timeout/
  --concurrent` timing knobs; and the kernel-routed `RawIpDriver`
  (`AF_INET` `SOCK_RAW` + `IP_HDRINCL` TX, shared `AF_PACKET` RX).
  Post-charter additions already in the tree: the tranche-1
  `sll_pkttype` TODO resolved (receive paths skip our own outgoing
  copies), `FakeClock` microsecond resolution with a `fast_forward`
  hook for deterministic timeout delivery, and a clock-aware
  `ScriptedDriver`. Verification: state-machine walkthrough units, a
  proptest reference-model differential, seeded-schedule
  determinism properties, `fuzz_scan_session`, env-gated ground truth
  on `lo` (listener → open, unbound → closed, UDP/ICMP semantics,
  seed reproducibility, concurrent scans), all wired into per-commit
  CI.
- **T3 — DNS** — ✅ delivered. `wrex-proto-dns` (single-question
  craft, full-message dissection with compression pointers and a
  records extension to the core schema: `RecordSchema` sections with
  indexed paths `an.0.name`/`an.0.rdata` — filters and `wrex fields`
  speak them), UDP port-53 dispatch in the udp codec, `wrex query`
  (seeded raw-UDP ask session in `wrex-dns` over the frozen T2
  `Session` contract), and the verification stack additions:
  differential vs hickory-proto (in-process — the renamed
  trust-dns-proto; craft parity is byte-identical) and dig
  (subprocess against an in-test stub server), a DNS golden corpus
  (query, A/CNAME-chain/MX/TXT/AAAA replies, NXDOMAIN, truncated),
  `fuzz_dissect_dns`, and the MSRV bump to 1.88 that hickory-proto
  0.26 requires. Post-charter additions already in the tree: the
  SplitMix64 `Rng` moved to `wrex-io` (shared sans-IO vocabulary).
- **T4 — HTTP/1.1** — ✅ delivered. In-house sans-IO client session in
  the new `wrex-http` crate (httparse wire parsing + `http`-crate
  types; close-mode: one exchange per connection; content-length /
  chunked-with-trailers / read-to-close framing; 1xx skipped;
  HEAD/204/304 no-body; `--max-bytes` budget over all response bytes),
  `wrex http` (positional `[METHOD] URL` grammar, `-H/--data/--fail/
  --format text|json|raw`, deterministic ordered-header recipe JSON,
  byte-identical replay), and `wrex query --tcp` (RFC 7766 length-
  prefixed DNS, fresh connection per attempt) closing the tranche-3
  deferral. Transport: kernel TCP via the new `wrex-io` `TcpDriver`
  (optional `-i` source bind, `--source-port`, stream EOF as an empty
  frame — no CAP_NET_RAW, no kernel-RST conflict; a userspace TCP
  stack remains possible later for T6's prober). Verification: a
  boundary-sweep session suite (every split position of every framing
  mode), reqwest in-process oracle + curl subprocess differential
  (gating in the CI differential job; reqwest shares httparse lineage,
  so curl stays the independent check), `fuzz_http_session`
  (1.6M runs), and scoped Kani proofs as a new gating CI job (under a
  6GB memory ceiling): chunked-decoder panic-freedom (wrex-http,
  4s/0.3GB) and checksum folding (wrex-core, 1s/0.07GB). A dns
  decode_name proof was attempted and retired after measurement —
  the function's nested-loop unrolling and allocation-heavy body made
  every scope (exhaustive, pointer-universe, and 8-byte non-pointer)
  cost multi-GB and multi-minute solver state; the decoder stays with
  18 unit vectors (including the pointer-cap-from-every-offset sweep)
  and `fuzz_dissect_dns`. Deliberate deferrals: TLS (https → pointed
  out-of-charter error), keep-alive, chunked request bodies,
  userspace TCP.
- **T5 — capture/replay** — ✅ delivered. In-house classic pcap
  reader/writer in the new `wrex-pcap` crate (no libpcap): all four
  magic variants read — LE/BE × µs/ns — with the record timestamps the
  tranche-1 corpus reader discarded now kept; streaming LE-µs EN10MB
  writer (global header on open, snaplen truncation with `orig_len`
  preserved). `wrex capture` (AF_PACKET recv loop into `-w FILE.pcap`,
  `--count/--timeout/--filter/--promisc/--snaplen`, optional
  `--format` tee to stdout sharing recv's per-frame printers), `wrex
  replay` (offline dissect-and-print by default — jsonl default, the
  same `--format/--filter/--count` family; `-i IFACE` switches to
  verbatim wire re-send with capture-delta pacing by default and the
  T2 timing vocabulary `--rate/--interval/--seed/--jitter` as
  override, jitter seeded via the shared SplitMix64). The corpus
  reader (xtask `corpus-import`) now delegates to `wrex-pcap` (same
  CLI, same outputs). Verification: writer→reader roundtrip units +
  a 256-case proptest, BE/µs and ns/LE variant vectors, a
  truncated-record error suite, CLI offline tests (replay jsonl ==
  dissect jsonl of the same frame, `--format raw` concatenation,
  `--count`/`--filter` gating, usage exit codes, bad-pcap exit 1),
  env-gated ground truth on `lo` (capture under live traffic → valid
  pcap with wall-clock timestamps; captured pcap replayed onto `lo`
  and observed by a concurrent recv), `fuzz_pcap_reader` +
  `fuzz_pcap_roundtrip` in the smoke job, wrex-pcap in the Miri job,
  and a scoped Kani proof (record-header encode/decode roundtrip
  over symbolic u32s) in the kani job under the 6 GB ceiling. Man
  pages and completions regenerated (the verbs enumerate
  automatically). Deliberate deferrals: pcapng (read + write), BPF
  filter compilation (the wrex filter language serves), non-Ethernet
  capture linktypes, ring-buffer/rotation, raw-IP capture.
- **T6 — over-the-wire fuzzing** — ✅ delivered. In-house mutation
  engine in the new `wrex-mut` crate (tranche 6a): seeded, sans-IO,
  dissect-aware strategies — `field` (mutate one typed field value,
  re-encode with autofill so checksums re-derive), `len` (perturb a
  length field *explicitly* so autofill keeps the mutation), `flip`
  (header-biased raw bit flip), `splice` (A[..k]+B[k..] cross-over of
  two seeds), `raw` (flip/overwrite/insert/delete), and `all` (a
  seeded weighted mix); derived fields (checksums, lengths) are
  dropped when a dissection becomes a spec so re-encodes stay
  dissectable; inapplicable strategies fall through to the raw level
  so a mutant stream is always producible. `wrex mut` (seeds from
  positional hex, repeatable `-r FILE.pcap`, or raw stdin; `--strategy
  --count --seed`, `--format` with text/json/jsonl dissecting each
  mutant, `-w FILE.pcap` writing a mutated corpus the replay/fuzz
  verbs consume). Tranche 6b: the stateful recording prober in the
  new `wrex-fuzz` crate — a `Session` over the frozen T2 contract
  (baseline probe + `--rounds` mutated probes per target/port slot,
  reply matching by 4-tuple/echo id where the key derives from the
  *post-mutation* dissection, retransmissions repeat the exact
  mutated bytes, ICMP-unreachable quote attribution), one finding per
  probe (outcome + the exact probe hex, reply hex when a reply
  arrived) — a recording prober: `--baseline` collects the unmutated
  table for offline diffing; no in-run differential engine. `wrex
  fuzz` with the scan target/port grammar (tcp defaults to the
  committed top-100 list; udp requires `--ports`; icmp is a host
  sweep) and the full T2 timing vocabulary (`--rate/--interval/
  --jitter/--seed/--retries/--timeout/--concurrent`), findings as
  text/json/jsonl. Deliberate deferrals (re-deferred from T4): the
  userspace TCP stack (the prober works at L3/L4-inject level via
  RawEth/RawIp drivers — no kernel-TCP application-layer state), and
  cross-stack differential targets (findings JSONL is the offline
  diff substrate). Verification: wrex-mut units (per-strategy
  production, determinism, dissectability, len perturbation, splice
  fallback) + CLI suite (count/determinism, format family, pcap
  write→read roundtrip == printed mutants, stdin raw, usage exit
  codes), wrex-fuzz state-machine walkthrough units (probe accounting,
  reply recording with bytes, mutated-identity self-matching,
  cross-talk, retransmit-identity, tcp/icmp shapes, unreachable
  attribution, same-seed byte-identical probe streams, the
  ScriptedDriver+FakeClock runtime loop), a fuzz-CLI usage suite,
  env-gated ground truth on `lo` (a bound UDP responder → baseline
  reply findings, an unbound port → `unreachable:3` attribution,
  seed reproducibility), and `fuzz_mut_strategies` +
  `fuzz_prober_session` cargo-fuzz targets (never-panic, bounds,
  per-probe resolution, stream determinism) in the smoke job (CI list
  + xtask). Man pages and completions regenerated (the verbs enumerate
  automatically).
- **T7 — protocol expansion**: ipv6, vlan, dhcp, dissect-only profiles,
  dynamic `.so` plugin ABI revisit — each new codec follows the
  tranche-1 contract and plugs into the same wrex-test extension points.

## Standing rules (carried from the tranche-1 plan)

- Protocol extension stays a compile-time registry: a new protocol is a
  new feature-gated crate plus one `register` line — no dynamic loading
  until the T7 ABI revisit says otherwise.
- Later tranches never break the frozen contracts of earlier ones;
  anything that would, gets its own planning pass first.
- Every tranche lands with its verification story (oracles, corpora,
  fuzz surfaces) designed alongside the feature, not after it.