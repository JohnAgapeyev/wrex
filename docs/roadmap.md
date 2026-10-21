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
  `fuzz_pcap_roundtrip` in the fuzz gate (release workflow + xtask
  smoke), wrex-pcap in the Miri job,
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
  per-probe resolution, stream determinism) in the fuzz gate (the
  release workflow + the xtask smoke list). Man pages and completions
  regenerated (the verbs enumerate automatically).
- **T7 — protocol expansion**: ipv6, vlan, dhcp, the plugin ABI
  revisit — each new codec follows the tranche-1 contract and plugs
  into the same wrex-test extension points. Planned as sub-tranches:
  - **T7a — vlan** — ✅ delivered. `wrex-proto-vlan` (kind `vlan`,
    rank 15, parents `eth|vlan` for QinQ/802.1ad stacking): 4-byte
    header, `pcp` (3 bits) / `dei` (1 bit) / `vid` (12 bits) packed
    into the TCI plus the encapsulated ethertype (`type`, autofilled
    from the next layer like `eth.type`); craft always emits 0x8100,
    0x88a8 dissect-only. `eth` dispatches 0x8100/0x88a8 → `vlan`;
    `ipv4`/`arp` stack on `vlan` (parents extended, additive);
    `ethertype_name` renders `vlan.type` like `eth.type`. The CLI,
    filters (`vlan.vid=100`), `wrex fields`, man pages and
    completations enumerate automatically. Verification: codec units
    (golden TCI, autofill derivation, QinQ chains, truncation,
    >12-bit explicit vid kept), new differential stacks
    (`eth-vlan`, `eth-vlan-vlan`, `eth-vlan-ipv4-{udp,tcp,icmp}`;
    the vlan stacks' eth drops explicit `type` so the chain follows
    the spec) against etherparse + tshark (tshark's repeated `vlan`
    JSON keys collapse — tags match by value; 802.1ad outer tags
    land under `ieee8021ad`), a `vlan` golden corpus (single, QinQ,
    802.1ad, arp-in-vlan, terminal), `fuzz_dissect_vlan`, and CLI
    roundtrips in the integration suite.
  - **T7b — ipv6 + icmpv6** — ✅ delivered. Decisions recorded at the
    T7a planning pass held: kernel-routed v6 TX via AF_PACKET frame
    injection (there is no `IPV6_HDRINCL`; full v6 frames at
    ethertype 0x86dd through the existing AF_PACKET machinery rather
    than `AF_INET6` + `sendmsg` cmsgs — the new `wrex-io`
    `RawIpv6Driver` synthesizes the Ethernet header on send, bound
    `0x86dd` on receive). Core type generalization landed additively:
    `FieldKind::Ipv6` + `Value::Ipv6` (parse/render/filter/serde),
    `NetFacts` generalized to a versioned enum (V4/V6),
    `Patch::Checksum`'s pseudo-header generalized to a versioned
    `PseudoHeader` (v6: RFC 8200 §8.1 — 32-bit upper-layer length +
    zero-padded next-header), and `auto_start` maps `b>>4 == 6` to
    `ipv6`. New codecs: `wrex-proto-ip6` (kind `ipv6`, rank 20,
    parents `eth|vlan`; version/traffic-class/flow-label word,
    `payload_len` backpatched over the post-header bytes,
    next-header dispatch to icmpv6/tcp/udp) and `wrex-proto-icmpv6`
    (kind `icmpv6`, rank 30, parent `ipv6`; echo 128/129 with id/seq,
    full craft for NDP — RS (133), RA (134: cur-hop-limit, [m,o]
    flags, router-lifetime, reachable/retrans timers), NS/NA
    (135/136: [r,s,o] flags + target) — plus an dissect-only `opt`
    record section for NDP option TLVs (SLLA/TLLA → `opt.0.addr`,
    per the dns record-section pattern), checksum always over the v6
    pseudo-header (proto 58)). `udp`/`tcp` stack on `ipv6` additively
    (family-aware pseudo-header from the generalized facts);
    `eth`/`vlan` dispatch `0x86dd ⇄ ipv6`; dns AAAA rdata is typed
    ipv6 (closing the tranche-3 deferral). `wrex scan` and
    `wrex fuzz` accept IPv6 targets (addresses, CIDR `/len` ≤ 128,
    full-address START-END ranges; no v6 tail shorthand), one family
    per scan (mixed lists are a usage error), the four mode names
    unchanged (icmp over v6 targets speaks icmpv6), reply keys and
    ICMPv6-unreachable attribution family-aware — type 1 code 4 →
    closed (the RFC 4443 §3.1 port-unreachable code; an initial
    v4-style code-3 mapping was corrected post-charter when the env-
    gated `lo` ground truth first ran on CI), other codes → filtered. `wrex query`/`http` over v6
    remain out of the T7b charter (the `--server`/URL verbs pick v4
    iface addresses only). The CLI flags enumerate automatically
    (`--ipv6-*` with `ip6`/`v6` aliases, `--icmpv6-*`); filters gain
    ipv6 `=`/`!=` with CIDR. Verification: codec units (goldens, NDP
    shapes + option record sections, flow-word masking, checksums
    over the v6 pseudo-header via an independent RFC 8200 folding),
    scan session units (v6 syn open/closed + RST follow-up, v6 udp
    unreachable attribution + cross-talk quotes, v6 icmpv6 echo
    alive/dead), target-grammar units (v6 CIDR/ranges, mixed-family
    rejection, serde), new differential stacks
    `eth-ipv6-{udp,tcp,icmpv6}` + `eth-vlan-ipv6-*` vs etherparse
    (Ipv6 slice) + tshark (`ipv6`/`icmpv6` layers), `ipv6` +
    `icmpv6` handcrafted golden corpora, `fuzz_dissect_ipv6` +
    `fuzz_dissect_icmpv6` in the fuzz gate, a scoped Kani proof (v6
    pseudo-header folding under the 6 GB ceiling), env-gated ground
    truth on `lo` (v6 syn open/closed against a bound TCP6 listener,
    v6 udp closed via kernel ICMPv6 unreach, `::1` icmpv6 alive, seed
    reproducibility), Miri coverage for both new crates, man pages +
    completions regenerated. Deliberate deferrals: IPv6 extension
    headers, MLD, off-link next-hop/NDP resolution for the v6 driver
    (frames inject with the interface MAC; the `lo`/on-link contract
    only), NDP option *crafting* (options are dissect-only records),
    `query --server`/`http` URL v6 targets, v6 tail-shorthand ranges.
  - **T7c — dhcp** — ✅ delivered. `wrex-proto-dhcp` (kind `dhcp`,
    rank 40, parent udp): the full RFC 2131 fixed header is craftable
    (op/htype/hlen/hops, xid, secs, flags [broadcast] → 0x8000,
    ciaddr/yiaddr/siaddr/giaddr, chaddr (16-byte zero-padded), sname/
    file (NUL-padded to 64/128, dissection trims at the first NUL),
    cookie — autofill `0x63825363`). `msg_type` is the hoisted
    option 53 (the dns opcode/rcode precedent): craft accepts
    `discover|…|inform` or 1–8 and writes the TLV, dissection hoists
    it back so filters work regardless of option order (`msg_type` +
    `type:` in the options grammar is a mutual-exclusion usage error).
    The options region is craftable through the `options` list
    grammar — declared `FieldKind::Str` so the grammar is CLI-reachable
    via `--dhcp-options` (fixing the tranche-1 ip/tcp gotcha where a
    Bytes kind blocks the grammar at the value parser): `type:`,
    `mask:`, `routers:IP…`, `dns:IP…`, `host:`, `domain:`,
    `req_ip:`, `lease:`, `renew:`, `rebind:`, `server:`,
    `param_req:N…`, `max_msg:`, `client_id:HEX`, `pad`, and the raw
    `hex:CODE:HEX` escape, on the ipv4/tcp pending-continuation
    architecture (bare addresses/codes continue the previous option);
    craft always appends the `end` (255) marker and raw `Value::Bytes`
    regions are accepted too. Dissection renders every option as an
    indexed record of the dissect-only `opt` section (the dns an/ns/ar
    pattern) — `opt.N.code`, `opt.N.len`, `opt.N.value` (raw hex, the
    wire truth) plus a typed subset per code: `ip` (Ipv4: subnet
    mask/requested ip/server id; first address of routers/dns), `num`
    (Int: message type/lease/renewal/rebinding/max message size),
    `text` (Str: host/domain) — filters speak the typed paths (no
    dns-rdata filter asymmetry). Pad (0) options are skipped, `end`
    stops the walk (post-end bytes stay payload), an overrunning
    option stops with a never-fatal anomaly. A wrong magic cookie is a
    never-fatal `dhcp.cookie` anomaly and stops the layer at the fixed
    header (BOOTP legacy — vend fields stay payload). `udp` dispatches
    ports 67/68 into `dhcp` (the tranche-3 port-53 pattern; the
    unregistered kind degrades to the engine's synthetic `unknown`
    layer, never fatal). The CLI flags enumerate automatically
    (`--dhcp-*`; `msg_type` keeps its underscore like `--tcp-data_off`).
    Verification: codec units (golden header, sname/file padding +
    NUL trimming, msg-type hoist + conflict guard, grammar records
    order/typing, post-end payload, bad-cookie BOOTP, overrun anomaly,
    truncation), options-grammar units (singles, comma continuations,
    errors, `scan_msg_type` TLV walk), udp dispatch units (both ports,
    both sides, unregistered degradation — in-crate stubs keep proto
    isolation), the in-process `dhcproto 0.15` oracle in `wrex-test`
    (`dhcp_oracle`, the hickory pattern; MSRV 1.87 fits the 1.88
    floor, no bump; both-sides-parse; dhcproto's sname/file keep the
    NUL terminator — normalized), a dedicated both-direction
    differential (`tests/dhcp_differential.rs`, 256 cases: wrex craft
    → dhcproto parse, dhcproto encode → wrex dissect; craft parity is
    semantic, not byte-identical — dhcproto's BTreeMap encodes options
    sorted by code, the wrex grammar preserves order), new differential
    stacks `eth-ipv4-udp-dhcp` + `eth-vlan-ipv4-udp-dhcp` (the first
    fixed-port stacks — a `udp_for_dhcp()` wrapper pins 68→67; the
    generic differential's name-based `options` skip applies as-is)
    against etherparse + tshark, a handcrafted `dhcp` golden corpus
    (DISCOVER/OFFER/REQUEST/ACK/NAK/RELEASE + a bad-cookie BOOTP
    frame), the tshark map's `dhcp` block (fixed header; sname/file
    needed the missing `Value::Str` arm in `cmp_str` — dhcp is its
    first Str field; options stay with dhcproto: tshark's repeated
    `dhcp.option.type` JSON keys collapse, the vlan-tag problem),
    `fuzz_dissect_dhcp` in the fuzz gate (release workflow + xtask
    smoke), wrex-proto-dhcp in the Miri job, a CLI roundtrip test
    (craft → dissect json → opt records, `wrex fields`, filters on the
    hoist and typed records, the BOOTP-legacy path), and man pages +
    completions regenerated. Deliberate deferrals: DHCPv6 (546/547 —
    a different protocol; the tranche-7c charter is v4-only),
    CLI-settable indexed option records (`opt` stays dissect-only),
    deeper option typing beyond the committed grammar surface (raw
    `hex:CODE:HEX` covers the rest), relay/sname-overload semantics.
  - **T7d — plugin ABI revisit** — ✅ resolved by decision
    ([ADR 1](adr/0001-compile-time-registry.md)): the registry stays
    compile-time; no dynamic `.so` loading. "Dissect-only profiles"
    are dropped from the roadmap (no protocol needs the toggle;
    dns record sections already carry the dissect-only surface).
- **T8 — TLS + pcapng** — ✅ delivered (chartered at the T8 planning
  pass as two sub-tranches; T8a is TLS, T8b the pcapng reader/writer
  — both additive):
  - **T8a — TLS** — ✅ delivered. The rustls engine behind a new
    `wrex-tls` driver adapter — a `TlsDriver` that **composes** the
    kernel `TcpDriver` with a rustls `ClientConnection` under the frozen
    `Driver` contract (the same stream conventions the T4/T8 sessions
    already speak: whatever plaintext arrives before the deadline as
    one chunk, orderly `close_notify` as an empty frame, io/TLS errors
    — including certificate verification failures — surfaced as
    runtime errors; handshake driven lazily inside the first
    send/recv pump under the caller's deadline) — extending the
    hickory/dhcproto/reqwest oracle lineage to crypto: the engine is
    rustls 0.23 (`ring` provider, no aws-lc default — MSRV 1.71 holds
    under the 1.88 floor, no bump), never a hand-rolled stack. Roots:
    system store via `rustls-native-certs` plus `--tls-ca FILE`
    additions (PEM: every CERTIFICATE block via `rustls-pemfile`, else
    raw DER) that **complement** the system roots; `--tls-insecure`
    swaps in a `rustls::client::danger` accept-any verifier (safe
    code via the `dangerous()` builder, `#![forbid(unsafe_code)]`
    intact in the crate; the danger is semantic, documented at every
    surface). `wrex http https://…` (SNI from the URL host — an IP
    literal matches the cert's IP SAN; default port 443) with the
    retry/render/`--fail`/budget paths byte-identical to the plain
    driver (only the driver differs); `wrex query --tls` is DNS-over-
    TLS (RFC 7858): implies the TCP transport, fresh TLS connection
    per attempt, default server port 853, server name from `--server`.
    `wrex-http`'s `https` pointed-error gate is gone (the T4 deferral
    closed): `build`/`serialize` accept `http`/`https` — serialization
    stays transport-agnostic. The recipe JSON grows additive
    `tls_insecure` (default false) / `tls_ca` (path) fields mirroring
    `retries`/`timeout_ms`/`max_bytes` (old recipes parse
    byte-identically, recipe wins over CLI flags). Close mode is
    unchanged: one exchange per (TLS) connection, `Connection: close`
    on the wire. ALPN: none — plain https/1.1, no h2. Verification:
    in-crate loopback units over a rustls `ServerConnection` in a std
    thread (self-signed rcgen cert; full GET exchange through
    `TlsDriver` + `HttpClientSession` + the runtime loop; `close_notify`
    → empty-frame EOF; insecure accepts the self-signed cert; `ca_der`
    and PEM/DER `load_ca_file` trust it; verification failure surfaces
    as a runtime error), the shared stub server promoted into
    `wrex-test` (`tls_stub`, HTTP + RFC 7766 length-prefixed + canned
    DNS-reply shapes), CLI lo integration (plain kernel sockets, no
    capabilities: `http https://… --tls-insecure` end-to-end with
    `--format json`, `--fail` on 404, `--tls-ca` PEM verification, the
    recipe `tls_insecure` knob, `query --tls` against a TLS-wrapped
    DNS stub) and the reqwest (`rustls-tls`, dev-only) in-process
    differential over the same stub (status, framing-sensitive body,
    headers of interest). Deliberate deferrals: mTLS/client
    certificates, session resumption/0-RTT, ALPN/h2, keep-alive
    (persists as the T4 deferral — one exchange per connection),
    system-store override (`--tls-ca` complements, never replaces).
    Man pages + completions regenerated (the verbs enumerate
    automatically); wrex-tls stays OUT of the Miri job (rustls + TCP
    sockets are not Miri-safe) and adds no fuzz targets (rustls
    carries its own; the adapter is thin).

## Standing rules (carried from the tranche-1 plan)

- Protocol extension stays a compile-time registry: a new protocol is a
    new feature-gated crate plus one `register` line — no dynamic loading
    ([ADR 1](adr/0001-compile-time-registry.md) resolved the T7 revisit).
- Later tranches never break the frozen contracts of earlier ones;
    anything that would, gets its own planning pass first.
- Every tranche lands with its verification story (oracles, corpora,
    fuzz surfaces) designed alongside the feature, not after it.
  - **T8b — pcapng** — ✅ delivered. `wrex-pcap` grows a pcapng reader
  - **T8a — TLS** — ✅ delivered. The rustls engine behind a new
    + a streaming `PcapngWriter` (the T5 `PcapWriter` shape: SHB +
    one EN10MB IDB on open, snaplen 65535, no options — so the spec
    default resolution applies and the EPB timestamps are absolute
    epoch µs split into high/low words; snaplen truncation with
    `orig_len` kept, 4-byte padding). Read auto-detects on the
    byte-order-agnostic SHB type (0x0A0D0D0A both ways) with the
    byte-order magic inside picking LE/BE; both tsresols read
    (`if_tsresol` 9 → ns, 6 and any other value — decimal
    resolutions included — → the never-fatal µs default; only
    power-of-2 resolutions supported), unknown blocks skipped
    honoring the spec's mandatory-skip semantics (the block-type LSB
    picks "skip" vs "skip or abort"; a reader skips both — unknown
    mandatory blocks never abort), the single-interface contract
    tolerates nonzero interface ids with the LAST IDB winning, EPBs
    before any IDB on the spec defaults, and truncated blocks → the
    new `TruncatedBlock` (the `TruncatedRecord` spirit); same
    `PcapFile` shape, additive `pcapng` flag, classic files
    byte-identical. `wrex capture --pcapng` picks the new writer;
    `wrex replay`, `wrex mut -r` and `xtask corpus-import` share the
    reader and accept pcapng files automatically. Verification:
    writer→reader roundtrip units + the 256-case proptest extended to
    the pcapng writer, BE + ns + decimal-res + no-IDB + last-IDB
    handcrafted vectors, an unknown-block-between-records vector, a
    truncated-block suite (TooShort/BadMagic/`TruncatedBlock`),
    `fuzz_pcapng_reader` + `fuzz_pcapng_roundtrip` in the fuzz gate,
    a Kani EPB-fields roundtrip proof in the kani job, and CLI
    offline tests (replay jsonl == dissect jsonl of the same frame,
    `--format raw` concatenation, `--count`/`--filter` gating, `mut
    -r` seeding). Man pages + completions regenerated. Deliberate
    deferrals: writing multiple interfaces, IDB/EPB options
    (`if_tsresol` on write, `epb_flags`), Simple Packet Blocks,
    compression, multi-section files.