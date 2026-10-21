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
  - **T8b — pcapng** — ✅ delivered. `wrex-pcap` grows a pcapng reader
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
- **T9 — HTTP completeness + application-layer fuzzing** — ✅
  delivered (chartered at the T9 planning pass as two sub-tranches,
  both additive; T9a lands first because T9b's transport comes from
  it):
  - **T9a — keep-alive + chunked request bodies** — ✅ delivered.
    The T4 deferral closed. `HttpClientSession` grows an **ordered
    request queue** over the frozen `Session` contract (the same
    state machine; `new` keeps the close-mode T4 shape, byte-identical
    wire): every request but the last serializes
    `Connection: keep-alive`, the last announces close; the *response*
    decides reuse — an explicit `Connection: close`, HTTP/1.0, or
    until-close framing ends the queue — and a mid-queue transport
    failure resolves the current exchange (Truncated/Timeout/…) with
    the unsent remainder as the new `HttpOutcome::Closed`. Chunked
    *request* bodies replace the T4 pointed rejection:
    `body_framing: "chunked"` + a **fixed** `chunk_size` (default
    4096, never size-adaptive) keeps serialization deterministic, and
    an explicit `Transfer-Encoding` header stays a pointed conflict
    error (the knob owns it). `wrex http [METHOD] URL [URL...]` (a
    URL-looking first token ⇒ GET + a URL list; `-H/--data` apply to
    every URL) and the recipe file accept a single object
    (byte-identical parse, old recipes untouched), a top-level array,
    or `{"requests": [...]}` — one keep-alive connection, in order;
    `--format json` wraps a queue in an array (a lone response keeps
    the T4 object), `--fail` prints then exits 1 on any 4xx/5xx.
    Verification: session units (queue over one scripted connection,
    close/until-close/EOF end the queue, per-exchange budget+deadline
    reset), a queue **boundary sweep** at every split position of
    every framing mode, chunked-TX golden units (chunk split, empty
    body, TE conflict), recipe units (single/array/requests-key,
    framing knobs), and CLI suites against plain-socket stubs: a
    connection-counting keep-alive stub (two URLs → one connection,
    both bodies in order), a recipe-array queue, and a recording stub
    asserting the chunked request wire bytes.
  - **T9b — application-layer fuzzing over kernel transport** — ✅
    delivered. The T6 orchestration gap closed *without* the
    twice-deferred userspace TCP stack (it stays deferred: kernel
    transport covers application-layer mutation; only mutating TCP
    state *and* continuing the exchange would need it). `wrex fuzz
    --mode http|dns`: `ProbeMode` grows the app variants (default
    ports 80/53; no codecs needed, no `-i`, plain sockets — no
    CAP_NET_RAW), and the new sans-IO `AppSession` (`wrex-fuzz` crate)
    is the probe unit: **one fresh kernel `TcpDriver` connection per
    probe** (mirroring `query --tcp`), send the baseline or mutated
    *request* bytes (`wrex-mut` strategies over the serialized seed —
    an ASCII/length-prefixed seed never dissects, so the dissect-aware
    strategies fall through to the raw level, the T6 rule), read the
    response stream until orderly EOF (empty frame) under a 64 MiB
    budget, one `Finding` per probe (outcome + exact probe hex +
    response bytes, `proto` http/dns). The dns seed is one RFC 7766
    length-prefixed A query (wrex-dns query bytes); the http seed one
    `GET /` (wrex-http serialize). Retries repeat the exact mutated
    bytes on fresh connections; connect refusal is silence; pacing
    rides the T2 vocabulary (seeded jitter, sleep between probes).
    v6 targets are a pointed usage error (the kernel `TcpDriver` is
    v4, the T4 contract). Verification: `AppSession` units (EOF
    collection, timeout silence, budget cap, the ScriptedDriver
    runtime loop), config units (mode parse, app port defaults), CLI
    ground truth on `lo` with plain sockets (a bound TCP responder →
    baseline + rounds of `reply` findings with probe+reply hex, one
    connection per probe, the baseline a well-formed GET; a dead port
    → silence findings; same-seed jsonl byte-identical), v6/format
    usage errors, and `fuzz_app_session` in the fuzz gate (release
    workflow + xtask smoke list). Man pages + completions regenerated.
    Deliberate deferrals: the userspace TCP stack (re-deferred with
    the above rationale), http-head-aware `field` strategies (raw
    level covers), TLS-wrapped app probes (the T8a adapter composes
    the same stream contract; wiring is future work), v6 app targets.

- **T10 — IPv6 parity closure** — ✅ delivered (chartered at the T10
  planning pass as two sub-tranches, both additive; T10a landed first
  because T10b's resolution rides the same driver plumbing):
  - **T10a — v6 application transport** — ✅ delivered. The T7b
    application-verb deferral closed: the kernel `TcpDriver` speaks
    both families (`AF_INET`/`AF_INET6` via one `sockaddr_storage`
    filler — the same stream conventions: EOF as an empty frame, `-i`
    source bind and `--source-port` carried per family, a cross-family
    bind a pointed error), so `wrex query --server <v6>` (raw UDP via
    the `RawIpv6Driver`, `--tcp`, and `--tls` DoT — rustls is
    family-agnostic, only the socket differs), `wrex http
    http://[2001:db8::1]/` (bracketed literals per RFC 3986; SNI from
    the URL host with brackets stripped — an IP literal matches the
    cert's IP SAN, the T8a rule), and `wrex fuzz --mode http|dns` v6
    targets all speak v6. The `DnsSession`/`QueryConfig` generalized
    family-additively (`server`/`src` became `IpAddr`; the query
    builds `[ipv6,udp,dns]` and reply matching keys `ipv6.dst`; the
    DNS-over-TCP registry gate is family-aware; v4 wire stayed
    byte-identical). `-i` picks the iface address of the target's
    family (one family per raw-UDP run, the scan precedent). The
    https recipe/CLI `Host` keeps brackets (RFC 9110). Verification:
    driver units on `::1` (echo/EOF, refused→io-error, v4-mapped
    `sockaddr` layout, family-mismatch gate), `DnsSession` v6 units
    (query shape, v6-rooted reply resolution, v4↔v6 cross-talk),
    CLI suites (`http http://[::1]/` against a `::1` stub asserting a
    v6 peer, `query --server ::1` grammar + `--tcp` runtime-vs-usage
    gates, `fuzz --mode http ::1` now a findings success), env-gated
    ground truth on `lo` (`query -i lo --server ::1` end-to-end against
    a bound `::1` UDP stub), and the man pages regenerated
    (wrex-query(1), wrex-fuzz(1)). Deliberate deferrals: IPv6
    extension headers/MLD (codec tranche), DHCPv6, userspace TCP
    (fourth deferral, same rationale), ALPN/h2, mTLS, v6 zone-ids in
    URL targets.
  - **T10b — NDP / off-link next-hop resolution for the raw v6
    drivers** — ✅ delivered. The T7b `RawIpv6Driver` on-link contract
    closed: kernel route lookup (`/proc/net/ipv6_route` longest-prefix
    match per egress iface, read once at driver open) picks the next
    hop; an on-link or gateway neighbor resolves through a small NDP
    cache (one multicast NS — solicited-node address, SLLA carried —
    then a bounded 1s NA wait), then the frame injects with the
    resolved Ethernet next-hop MAC. The NS/NA wire bytes are
    hand-rolled in `wrex-io::ndp` (the io crate keeps no codec
    dependencies; the checksum is an independent RFC 8200 §8.1 fold).
    Local (`RTF_LOCAL`) and multicast destinations keep the T7b
    iface-MAC behavior — `lo` never resolves NDP, so every CI path is
    unchanged — an unresolved neighbor falls back to the iface MAC
    (never fatal), and the kernel's own NA reply is accepted as an
    `PACKET_OUTGOING` copy during resolution. `wrex scan`/`wrex fuzz`
    v6 raw modes gain off-link reachability through the driver, no
    session changes. Verification: `ndp` units (route parsing, LPM,
    hex/mask parsing, solicited-node + multicast MACs, NS goldens
    with independently folded checksums, NA round-trips, cache
    hit/miss/fallback/gateway-resolution state walkthroughs).
    Deliberate deferrals: NDP option *crafting* in the icmpv6 codec
    (`opt` stays a dissect-only record — the driver hand-rolls its
    SLLA), NDP probe fuzzing (the cache is best-effort
    infrastructure), route re-reads on drift (read once at open),
    retransmitted NS beyond the single bounded attempt.

- **T11 — lossless dissection + span-patch engine (byte-fidelity
  contract)** — 🌤 T11a ✅, T11b-α ✅ and T11b-β ✅ delivered
  (frame retention + engine core + full codec population); γ
  (mut/CLI integration) chartered (settled at the T11 planning pass
  as sub-tranches; the design unifies around the encode engine's
  existing deferred-`Patch` derived-field resolution, walked in a
  second direction):
  - **T11a — frame retention + verbatim reassembly** — ✅ delivered.
    `DissectedPacket` retains the original input (`frame: Bytes`);
    every layer span and the payload tail resolve against it, and
    `DissectedPacket::reassemble` splices them back — **zero edits ⇒
    byte-identical by construction**, for any input dissection accepts,
    malformed included: no field is ever re-derived on the path (wrong
    checksums, compressed names, trailing bytes all survive verbatim).
    The coverage invariant (layer spans ordered, non-overlapping,
    payload tail) is debug-asserted in `reassemble`; the craft/spec
    encode path stays **semantic** (re-derived checksums, decompressed
    names) — that is the correct behavior for crafting and it does not
    change. No CLI change. Verification: `tests/reassemble.rs` — every
    stack strategy (encode → dissect → reassemble == encoded, 256
    cases), every corpus frame (golden + captured traffic,
    dissect(auto) → reassemble == frame), and a deliberately wrong
    explicit checksum (anomaly carried, bytes preserved — the
    `preserve`-semantics contract test). Deliberate deferrals:
    `frame` in the dissect JSON output (`--spans` rides T11b),
    span-carrying pcapng options.
  - **T11b — the span-patch engine** — 🌤 α delivered (the engine
    core + L2–L4 population); β (dns/dhcp spans) and γ (mut/CLI
    integration) chartered. Buffer + edits + caller-selected
    consistency, on the retained frame:
    - **α — engine core + L2–L4 population** — ✅ delivered. The
      span taxonomy landed as designed: `FieldSpan` is a **closed
      geometry enum** (`Bytes` / `Bits{container, shift, width}` /
      `ReEncode` / `None`) — semantics stay in the schema
      single-sourced; `LayerView.field_spans` is the settled
      **parallel map**, and presence is **total**: every dissected
      field key resolves (a real span or `None`-by-policy — dynamic
      regions: ipv4/tcp `options`, dns/dhcp until their slices);
      absence is a gate failure, never a convention. Sub-bit paths
      (`flags.syn`) derive from `FieldKind::FlagSet` bit names,
      MSB-first inside the aggregate's own window (conditional
      aggregates — icmpv6 `ndp.*` — skip when unparsed). Layouts are
      **schema-side declarations** delivered as `Codec::layouts()` /
      `Codec::derived()` default trait methods (test mocks and
      dynamic codecs inherit empty): eth, vlan (TCI bit windows),
      arp, ipv4 (ver/ihl, flags/frag_off bit windows), ipv6 (the
      flow word), icmp, icmpv6 (NDP windows), udp, tcp (data_off
      nibble) — nine codecs. The engine (`wrex-core::patch`): an
      ordered **edit list** (`SetField` by dissected path,
      `Insert`, `Delete`), a **representability + overlap pre-pass**
      over the whole set (never partially applied, never
      last-write-wins), splice application (`Bytes` slicing,
      zero-copy outside edited regions; `Bits` edits masked-write
      the container), then the **wire→wire consistency walk**: a
      fresh dissection of the spliced frame re-resolves spans in
      new coordinates, and the caller-selected **scope** — per
      derived field with layer shorthand (`"udp.*"`), default =
      all — drives the declarative `Derived` specs (`Length`,
      `Checksum` over `ChecksumEnd::{Frame, Layer}` with
      `PseudoSource::{None, FromFacts}` from the dissected net
      facts) through the same RFC 1071 fold the encode side uses
      (the checksum's own bytes zero during the fold, the encode
      placeholder rule mirrored). Edits decide bytes; scope decides
      recomputation; an edit on a derived field its scope also
      selects is a pointed conflict. Scope-selected recomputation
      applies regardless of edit presence — `patch(p, [], Scope::all)`
      *is* the normalize verb, deliberately; `Scope::none` + zero
      edits is byte-identity (the T11a degenerate; replay/fuzz
      retransmit ride it). `DissectedPacket` grew `facts`
      (pseudo-header provenance, SDK surface). No CLI change.
      Verification: core mock units (scope archetypes, bit masking,
      pointed errors, determinism, the empty-edit degenerates) and
      `tests/patch_engine.rs` over the real registry — the
      **population gate** (total presence on every corpus frame +
      FlagSet subpaths), real patches with re-dissection ground
      truth (scope all ⇒ zero anomalies; scope none ⇒ stale
      checksums carried unhealed; insert/delete ⇒ lengths and
      checksums recomputed; udp.checksum edit under outer-only
      scope lands and only udp goes stale; dns ⇒ `UnsupportedPath`
      pointed), and vlan bit-window patching through the real
      codec. Deliberate deferrals: dns/dhcp spans (β), record
      sections, `ReEncode` patch application (the variant exists;
      applying one is a pointed deferral error), the `wrex-mut`
      edit-set integration and `dissect --spans` (γ).
    - **β — dns + dhcp population** — ✅ delivered. The four design
      decisions settled at the planning pass: (1) dns `flags` is
      **scattered** (qr=bit15, aa=10, tc=9, rd=8, ra=7 of one word)
      — the aggregate carries `None` (not one contiguous window) and
      each subbit gets its real single-bit window, codec-side; (2)
      count fields are **not** `Derived` targets — section-count
      recomputation is ill-defined under desync (the dissector
      trusts the count) and the add-a-record workflow patches the
      count explicitly, caller-decided; (3) names are
      **span-if-uncompressed** — `decode_name` grew a
      compressed-pointer return (the internal jump counter exposed),
      pointer-resolved names carry `None` + the pointed-error
      policy, uncompressed names get real spans (same-width
      overwrites legal; length changes ride Insert/Delete); (4)
      `ReEncode` spans are **recorded now, application stays the
      codec-hook deferral** (a new `Layout::ReEncode` declares
      dhcp sname/file). Engine: `populate_field_spans` became a
      **merge** — codec-provided parse-time entries win, the static
      layouts table fills the still-missing keys, sub-bit derivation
      fires only for layout-derived aggregates (codec-side subbits
      win), `None`-fallback preserves total presence. dns:
      codec-side spans for `qd.N.*`/`an|ns|ar.N.*` (type/class/ttl/
      rdata at the parse cursor; names per policy 3; `rdata`
      spans its region) + static header layouts (id, counts,
      opcode/rcode bit windows). dhcp: static layouts for the whole
      240-byte header incl. `chaddr`/`cookie` and the `ReEncode`
      sname/file; codec-side `opt.N.code/len/value` + typed
      `ip/num/text` subregions; the hoisted `msg_type` spans its
      **option-53 source** — patching it writes the right TLV.
      Verification: the golden **add-a-record workflow** (one edit
      set on a synthetic reply with a compression-pointer answer:
      Insert a hand-built A record + SetField `ancount` explicitly
      — no scope conflict, re-dissection fully consistent, the
      pointer-compressed answer still resolving), the
      pointer-name pointed error, the scattered-flags masked write
      (opcode/rcode untouched), dhcp hoisted/msg_type patches and
      the sname ReEncode deferral on the corpus goldens, the
      population gate over every corpus frame (total presence,
      record sections included), and the hickory/dhcproto
      differentials + reassemble gates unchanged.
      Deliberate deferrals: `Derived::Count` (revisit if a
      scope-managed count workflow appears), ReEncode *application*
      (the codec re-encode hook), rdata name patches through
      compression pointers.
    - **γ — `wrex-mut` + CLI integration** — chartered. Strategies
      emit **edit sets** applied through the engine under `preserve`;
      the recorded one-time re-baseline (untouched invalidities stop
      being healed) lands here; strategies that cannot represent an
      edit fall through per the T6 rule. `dissect --spans` emits the
      taxonomy; man pages + completions regenerate.
- **T12 — offline findings differential** — chartered. The natural
  completion of the T6/T9 recording-prober design: a small offline verb
  diffing two findings JSONL files (baseline vs mutated run, or two
  targets against the same probe corpus) into a structured report
  (per-probe outcome deltas, reply-presence changes, divergent bytes).
  No new codecs, no new drivers, rides existing formats — cheap, and
  ranked ahead of the BGP/SMB protocol tranches for that reason.

## Standing rules (carried from the tranche-1 plan)

- Protocol extension stays a compile-time registry: a new protocol is a
    new feature-gated crate plus one `register` line — no dynamic loading
    ([ADR 1](adr/0001-compile-time-registry.md) resolved the T7 revisit).
- **Codec selection follows [ADR 2](adr/0002-protocol-selection.md)**:
    own the wire only where byte control over that protocol is central
    and adapting a library costs as much as the subset; otherwise reuse
    *behind the registry contract*, with a different-implementation
    oracle (the inversion rule — never diff against the thing wrapped).
    Dispositions recorded at each tranche's planning pass (BGP, SMB2/3,
    HTTP/2, HTTP/3 carry advisory dispositions there already).
- **Stability is a 1.0 event, not a now-tax.** wrex is SDK-bound — the
    crate APIs (core dissect model, `Session`, `Driver`, codec
    surfaces) are assumed-public-in-waiting, but pre-1.0 nothing is
    frozen: breaking changes are free while nobody depends on them.
    Each tranche designs public shapes with "would we freeze this?" as
    a tie-breaker, not a constraint; API review, deprecation policy,
    docs.rs and changelogs arrive with the 1.0 tranche (triggered by
    first crates.io publish or first external embedder, whichever
    comes first).
- The **userspace TCP stack** stays deferred until a tranche needs to
    mutate TCP state itself *and* continue the exchange (kernel
    transport covers application-layer mutation; the T9b rationale).
    When chartered it is a `wrex-io` driver under the frozen `Driver`
    contract, **reuse-first** (smoltcp is the candidate — ADR 2's rule
    with an obvious answer), and the transport-capability honesty
    stays: kernel `TcpDriver` (byte-stream control) and a userspace
    stack (segment control) are distinct, never equivalent capabilities.
- **TLS-protocol fuzzing** (malformed-but-authenticated records; needs
    session keys) is a separate specialized capability — never a
    prerequisite for HTTPS crafting, never scope-crept into the
    T8a rustls delegation ([ADR 2](adr/0002-protocol-selection.md)
    carries the note).
- Later tranches never break the frozen contracts of earlier ones;
    anything that would, gets its own planning pass first.
- Every tranche lands with its verification story (oracles, corpora,
    fuzz surfaces) designed alongside the feature, not after it.
- **Miri and the full fuzz matrix run in the extended-verification
    gate, not per-commit CI** (moved at tranche 11b-β: the codec
    population grew Miri past ~11 minutes). Release tags + manual
    dispatch (`.github/workflows/fuzz.yml`); `cargo xtask verify
    --with-miri` / `--with-fuzz` are the local mirrors. Per-commit CI
    keeps fmt/clippy, the unit + proptest + reference-model suites,
    the differentials, Kani, coverage, audit, and the env-gated
    driver tests.