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
  contract)** — ✅ delivered (T11a, T11b-α, T11b-β and T11b-γ: frame
  retention + engine core + full codec population + mut/CLI
  integration; settled at the T11 planning pass as sub-tranches; the
  design unifies around the encode engine's existing deferred-`Patch`
  derived-field resolution, walked in a second direction):
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
  - **T11b — the span-patch engine** — ✅ delivered (α engine core +
    L2–L4 population, β dns/dhcp spans, γ mut/CLI integration). Buffer
    + edits + caller-selected consistency, on the retained frame:
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
    - **γ — `wrex-mut` + CLI integration** — ✅ delivered. The
      field/len strategies emit **edit sets**: dissect → pick one
      patchable field (span-`Bytes`/`Bits` candidates only; dynamic
      regions, pointer-resolved names and `ReEncode` slices fall
      through per the T6 rule) → mutate the typed value (the
      unchanged `mutate_value`) → serialize it to the field's wire
      bytes (`wrex_core::encode::serialize_field_value`, a new
      schema-driven single-value serializer — `Bytes` spans want their
      exact length, `Bits` windows `ceil(width/8)` BE bytes, FlagSet
      aggregates pack through the `bit_names` MSB-first unit
      convention) → `Edit::SetField` through the engine under
      **preserve** (`Scope::none`: nothing recomputes — the T11a
      contract now on the mutation path). flip/splice/raw keep direct
      byte surgery (byte-level by definition; a `Scope::none` engine
      pass would be a byte-identical passthrough). The recorded
      **one-time re-baseline** landed: per-seed mutant streams change
      (rng consumption order; same-seed determinism holds), and the
      T6-era expectations that assumed autofill healing were swept —
      the field strategy now *carries* seed invalidities (wrong
      checksums ride along unhealed; new preserve-semantics units).
      `dissect --spans` emits the taxonomy (opt-in, additive: per-layer
      `spans` maps + `payload_span` in json/jsonl, a `spans:` text
      section; default output byte-identical), with a CLI
      total-presence assertion over the golden frame. Man pages +
      completions regenerated (`wrex-diff(1)` included).
- **T12 — offline findings differential** — ✅ delivered. The natural
  completion of the T6/T9 recording-prober design: `wrex diff
  BASELINE.jsonl MUTATED.jsonl`, a small offline verb diffing two
  findings JSONL files (baseline vs mutated run, or two targets
  against the same probe corpus) into a structured report. Findings
  pair by probe identity — `(target, port, proto, round)`, `strategy`
  carried never matched — index-wise in file order (duplicates never
  cross); equal pairs are silent; entries carry outcome deltas,
  reply-presence changes (`added`/`removed`), divergent reply bytes and
  attempt-count changes (`rtt` is wall-clock noise, ignored; a
  recorded decision). One-sided probes render with their probe hex.
  Pure offline: `wrex-fuzz::diff` (an owned-string `FindingRecord`
  deserialization mirror of `Finding`, gated by a field-for-field
  parity unit; `Outcome` grew `Deserialize`), no codecs/drivers/
  sockets; any completed diff exits 0 (the report is data — the scan
  precedent), malformed lines exit 2 pointing at file:line. Formats:
  text (default) / json (array) / jsonl. No new codecs, no new
  drivers, rides existing formats. Verification: diff units (drift
  gate, blank-line skipping, pointed malformed-line errors, pairing
  under duplicate keys, one-sided ordering, equal-pair silence) and a
  CLI suite (text/json/jsonl shapes, raw/hex usage rejection,
  unreadable-file exit 1). Man pages + completions regenerated.
- **T13 — span-patch completion + TLS-wrapped app probes** — ✅
  delivered (chartered at the T13 planning pass as two sub-tranches,
  both additive; T13a closes the T11b-β recorded deferral list — the
  engine's own holes, not trigger-gated — and T13b closes the T9b
  TLS-wrapped-probes deferral by composing the T8a adapter):
  - **T13a — ReEncode application + dns compression-pointer
    patching** — ✅ delivered. After T13a **every dissected field key
    is patchable**. The engine's `FieldSpan::ReEncode` arm (was: a
    pointed deferral) routes through a new default-trait `Codec::
    reencode(field, value, region)` hook — the codec owns the region's
    encoding and returns the full `region.len()`-byte replacement
    (the engine enforces the width); `None` (the default, inherited by
    mocks and dynamic codecs) stays the pointed `UnsupportedPath`, a
    `Some(Err)` is the new pointed `PatchError::ReEncodeFailed`.
    **dhcp `sname`/`file`**: value + NUL padding to the region width
    (the craft-time rule re-used); over-length and embedded-NUL values
    are pointed rejections (dissection trims at the first NUL — an
    embedded NUL would render inconsistently). **dns names**:
    `decode_name` grew a final-pointer-target return (the target of
    the *last* jump — the walk from there never jumps again), and
    pointer-resolved names (was `FieldSpan::None`, the T11b-β
    policy) re-attach as `ReEncode` over the **pointer target's**
    extent: a patch rewrites the shared target in place, same-width,
    with the value validated as a complete uncompressed wire name
    (a garbage region at a shared target would corrupt every alias);
    aliases through the pointer see the change (the alias-safety
    gate — a unit asserts a shared-target patch is visible through
    both paths after re-dissection); length changes ride Insert/Delete
    at the caller (the T11b-β policy, unchanged). `Derived::Count` is
    re-affirmed deferred (the 11b-β decision stands). The `wrex-mut`
    field strategy keeps its `ReEncode` exclusion **deliberately**
    (decided at execution): the hook's value encoding is
    codec-specific (dhcp pads presentation bytes, dns wants wire
    labels at the target), which `serialize_field_value` cannot
    speak generically — the engine API and tests carry those patches.
    No CLI change (`dissect --spans` renders the taxonomy; only the
    variant's semantics filled in). Verification: engine mock units
    (hook application/padding, pointed rejections, the default-`None`
    deferral), name units (plain/pointer/chained final-target
    exposure), `tests/patch_engine.rs` — the 11b-β dns/dhcp
    pointed-deferral assertions flipped to application semantics
    (same-width rewrite-at-the-target with the alias assertion, the
    pointer bytes untouched, over-length/malformed rejections, dhcp
    sname NUL-padding byte-verified + re-dissection roundtrip), the
    population gate and differentials unchanged.
  - **T13b — TLS-wrapped app probes** — ✅ delivered. The T9b deferral
    closed: `wrex fuzz --mode http|dns --tls` composes the T8a
    `TlsDriver` into the app-mode probe table — the `AppSession`
    contract is untouched (transport-agnostic by construction), only
    the verb's per-probe connection factory swaps `TcpDriver` for the
    rustls adapter (`Box<dyn Driver>`, the query-verb pattern). One
    fresh TLS connection per probe (the T9b rule transposed; retries
    repeat the exact mutated bytes on fresh connections); the
    handshake rides lazily inside the first send/recv pump under the
    probe deadline (the T8a convention); a connect or verification
    failure spends the attempt as a **silence finding** — data, exit 0,
    never a crash. `--tls` config-gates to the app modes (a raw mode
    is a pointed usage error: L3/L4 injection has no stream) and
    picks the TLS-registered default ports (http 443, dns DoT/RFC
    7858 853; explicit `--ports` overrides); `--tls-ca FILE`
    complements the system roots and `--tls-insecure` accepts any
    certificate (both carried through the `TlsKnobs` shared config,
    SNI/server name from the target IP); the http seed URL speaks
    `https://` under `--tls` (serialization accepted both schemes
    since T8a). Verification: config units (mode+tls gating, port
    defaults), CLI suites against `wrex-test::tls_stub` (http
    baseline+rounds findings with probe+reply hex over fresh TLS
    connections, `--tls-ca` PEM verification end-to-end, untrusted
    cert → silence findings exit 0, dns DoT canned-reply findings,
    same-seed identity+probe-byte determinism with wall-clock `rtt`
    normalized out — T12's recorded noise decision), and the
    `--tls`-on-raw-mode usage errors. Man pages + completions
    regenerated (`wrex-fuzz(1)`). Deliberate deferrals: TLS-protocol
    fuzzing (the standing rule — session keys, a separate specialized
    capability), v6 TLS stubs in the CLI suite (the stub binds
    `127.0.0.1`; the driver is family-agnostic, only the stub is v4),
    `--tls-insecure`/`--tls-ca` without `--tls` (inert, not errors).

- **T14 — `wrex patch`** — ✅ delivered (chartered at the T14 planning
  pass): the CLI door into the T11–T13 span-patch engine — the
  deterministic-edit counterpart to `wrex mut`'s random field strategy,
  closing the "engine is SDK-only" gap; every piece it rides was
  already delivered and verified. `wrex patch [FRAMES…] [-r
  FILE.pcap] --set path=value… --insert AT:HEX --delete AT:LEN
  [--scope SEL[,…]|--no-recompute] [--index N[-M][,…]] [--filter EXPR]
  [--format FMT] [-w FILE.pcap] [--pcapng]`. Seeds: positional hex,
  `-r` classic (all four magics) or pcapng (auto-detected) records,
  and/or raw stdin — the mut grammar verbatim, kept as one ordered
  stream. The whole edit grammar validates **upfront** against the
  registry schema (`wrex::edit`, the spec.rs lineage): unknown
  layers/fields, bad value spelling, `--index`/`--scope` grammar and
  the edit/scope conflict (fully static — schema + scope — so the
  engine's `EditScopeConflict` never surprises mid-stream) are usage
  errors, exit 2 before any file is read; frame-level facts (the path
  missing from THIS frame, span width, bounds, re-encode rejections)
  are pointed runtime errors, exit 1, naming the frame. `--set` values
  parse through the pinned field grammar and serialize through
  `serialize_field_value` at the span's width (the mut field
  strategy's serializer; over-wide bit-window values mask, the craft
  rule; flag subpaths take the boolean grammar). The **`wire:HEX`
  escape** hands a region raw bytes when the typed grammar cannot
  speak the encoding — and it is required where a **string-typed
  field sits over a raw span**: typed Str values there are refused
  pointedly (the T13a mut-exclusion rule held on the verb — dns
  names are label-encoded, dns type/class are u16s behind name
  presentations; nothing writes presentation bytes silently), while
  string-typed `ReEncode` regions stay typed (the codec hook owns the
  encoding: dhcp `sname`/`file` NUL-pad their text, dhcp `msg_type`'s
  1-byte TLV wants `wire:08`). Scope: default `Scope::all` (minimal
  edits, whole frame consistent — the engine's zero-edit degenerate
  IS the normalize verb, deliberately), `--no-recompute` = preserve
  semantics (the mut field rule transposed), `--scope udp.*[,…]` =
  selective; both knobs together is a usage error. Corpus mode:
  `--index` (1-based ordinals, `N-M` ranges — the scan port grammar)
  and `--filter` (the recv filter engine, schema-validated at startup)
  select **which frames get patched** (both given = intersection;
  unlike replay's `--filter` nothing is dropped — it selects);
  unselected frames pass through **byte-identical** with their
  capture timestamps and `orig_len` annotations kept (an additive
  `write_record_orig` on both pcap writers, the T5/T8b `write_record`
  delegating unchanged), a selected frame missing a path is the
  pointed runtime error. stdout carries the whole stream (patched +
  passthrough) per `--format` (hex default, raw, text/json/jsonl
  dissections of the output frames); `-w` writes the same stream as a
  pcap (classic default, `--pcapng` the T8b writer — the capture
  verb's sink lifted into a shared `FrameWriter`). Composition over
  new verbs: `patch -w → replay -i → diff` is the end-to-end story
  (patch stays offline, the T12 precedent); a `--send` composite is
  deliberately not built. The **T11a deferral closes in the same
  pass**: `dissect --frame` emits the retained input frame as hex
  (a top-level `frame` key in json/jsonl, a `frame (N bytes): <hex>`
  line in text; default output byte-identical — the `--spans`
  additive rule). No new crate, no new codec. **Engine fix the sweep
  caught (pre-existing T11b-α bug)**: `Derived::Length` hard-coded
  "frame end − layer start", which writes **52 for a 12-byte v6
  payload** on `ipv6.payload_len` (RFC 8200 counts payload only, from
  the header END; the encode side was always correct — it carries a
  per-codec `base`). `Derived::Length` gained an additive
  `LengthBase::{LayerStart, LayerEnd}` discriminator (ipv4
  `total_len`/udp `length` stay LayerStart; the corpus sweep caught it
  as a normalize that re-dissected truncated — the fixed-point test
  pins the fix). Deliberate deferrals: presentation-to-wire sugar for
  Str-over-raw-span fields (dns name/type/class wire encoders —
  `wire:HEX` covers T14), JSON edit-list files and per-frame edit
  scripts (the flags cover), record-section sugar ("append an A
  record" — the engine accepts the edit set, sugar is caller work),
  `mut` ReEncode strategies (the T13a decision stands), `--snaplen` on
  write, a `--send` composite, `Derived::Count` (re-affirmed), BPF.
  Verification: `tests/patch_cli.rs` (black-box, assert_cmd — typed
  edits + re-dissection ground truth, bit-window masking through a
  vlan golden, flag subpaths/aggregates, insert/delete shape
  consistency, scope selective/conflict/grammar, index/filter
  selection with passthrough byte-identity + timestamp preservation,
  truncated-record `orig_len` passthrough, `-w`/`--pcapng` roundtrips
  == stdout, stdin seeds, the wire:/ReEncode dhcp workflows, usage
  exit 2 vs runtime exit 1 mapping, the identity + normalize
  degenerates, `dissect --frame` opt-in/default-identity);
  `tests/patch_sweep.rs` (engine + verb-library level) — the corpus
  **identity sweep** (every first-of-kind layer, every span-Bytes
  field: a self-value `--set` through the real grammar under
  `Scope::none` reproduces the input exactly; Str-over-raw-span
  fields assert the pointed refusal instead — the QinQ corpus also
  pinned the engine's documented first-layer-of-a-kind addressing),
  the **normalize fixed point** (zero edits + `Scope::all` on every
  anomaly-free corpus frame: anomaly-free out, idempotent — the test
  that caught the v6 length bug), a never-panic proptest over random
  edit sets on corpus frames (resolve-or-pointed-error, outputs
  re-dissect), and the patched-frame **tshark differential**
  (independent lineage, ADR 2's inversion rule: a real field edit,
  payload insert/delete, and the vlan insert/delete workflows —
  wrex's zero-anomaly re-dissection is the checksum ground truth);
  edit-grammar units in `wrex::edit` (static errors, the conflict
  pre-check, typed widths, scope/index parsers, re-encode value
  bytes); `write_record_orig` roundtrip units in wrex-pcap; the
  population gate and the T11/T13 patch-engine suites unchanged
  under the `LengthBase` fix. No new fuzz targets (the engine is
  `fuzz_mut_strategies`' territory; the verb adds one proptest
  instead), no Miri changes (patch_cli is a spawning suite, file-level
  ignored; the sweep's tshark test is test-level ignored), no Kani
  changes. Man pages + completions regenerate (`wrex-patch(1)` — the
  verbs enumerate automatically).

- **T15 — HTTP/2** — ✅ delivered (chartered at the T15 planning pass;
  ADR 2 dispositions recorded there: the binary framing layer and
  HPACK are **owned** — byte control over the wire is the point — and
  the session semantics are an owned sans-IO state machine, the
  T2/T4/T9 pattern; TLS stays delegated to rustls via the T8a adapter,
  which now negotiates ALPN). Four sub-tranches, both additive; the
  `Session` contract is untouched (`SessionAction` stays `Send`
  only — the session decides frame ordering; concurrency is internal
  state):
  - **T15a — ALPN groundwork** — ✅ delivered. `wrex_tls::TlsConfig`
    grows `alpn_protocols` (offered in the caller's order; empty — the
    default since 8a — negotiates nothing, plain https/1.1 semantics).
    The negotiated protocol is exposed on the driver:
    `TlsDriver::alpn_protocol()` plus `complete_handshake(deadline)`
    — drives the handshake to completion without sending application
    data (a deadline miss is `Err(TimedOut)`, retry-grade;
    transport/verification failures are runtime errors, exit 1) so
    ALPN-picked sessions can choose their wire protocol before the
    first byte. **Auto-downgrade** (the planning decision): `wrex http
    --http-version 2` offers `h2` then `http/1.1`; a server that
    declines h2 prints a pointed note and falls back to the 1.1
    session on the same TLS connection.
  - **T15b — the framing layer (own)** — ✅ delivered. New `wrex-h2`
    crate, pure and sans-IO (`chunked.rs` lineage): the 9-octet frame
    header codec (24-bit length, 8-bit type, 8-bit flags, R + 31-bit
    stream id, reserved bit masked in both directions), the committed
    frame-type set (DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS,
    PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION) with
    per-type flag grammar + shape validation (never fatal, pointed),
    settings payloads, padding stripping, and the connection preface
    (server preface = SETTINGS, enforced).
  - **T15c — HPACK (own)** — ✅ delivered. Full **decode** grammar
    (RFC 7541 §6: indexed, literal with/without indexing,
    never-indexed, dynamic-table size updates) with the dynamic table
    (entry size = name+value+32, §4.3/§4.4 eviction, SETTINGS-driven
    caps) and the static Huffman code (appendix B, generated from the
    RFC table and verified at generation: bits == hex == len per row —
    bit-serial decode with the EOS-padding rule). **Encode is
    deliberately literal-only**: indexed representations for exact
    static matches, literal-without-indexing otherwise, never Huffman —
    deterministic recipe bytes, no dynamic-table state on the send
    side (Huffman *encode* and incremental indexing are recorded
    deferrals).
  - **T15d — the sans-IO client session (own, concurrent streams)** —
    ✅ delivered. `wrex_h2::H2Session: Session` (output =
    `wrex_http::HttpOutcome` — the 1.1 verb paths render/retry it
    unchanged): preface + SETTINGS burst, N **concurrent** streams
    opened in request order (odd ids, a `MAX_STREAMS` budget),
    interleaved DATA subject to **both** connection and per-stream
    window accounting (SETTINGS INITIAL_WINDOW_SIZE deltas,
    MAX_FRAME_SIZE honored, WINDOW_UPDATEs unblock), HEADERS/
    CONTINUATION fragmentation (END_STREAM rides the first fragment),
    response assembly (`:status` pseudo-header → `HttpResponse`,
    HTTP/2 version, reason from the status code), PING ACKs, and
    pointed outcomes for RST_STREAM (stream reset), GOAWAY (everything
    past last-stream-id truncates), budget breaches (TooLarge +
    CANCEL), protocol/HPACK errors, per-stream deadlines and the
    stream-EOF empty-frame convention (the T4 rule, transposed).
  - **T15e — CLI + verification** — ✅ delivered. `wrex http
    --http-version 1.1|2` (recipe `http_version` knob, recipe wins
    over the flag; h2 requires https + ALPN — h2c/prior-knowledge is a
    deferral; mixed versions in one queue are a usage error) and the
    recipe JSON grows the additive `http_version` field (old recipes
    parse byte-identically). Verification: RFC 7541 appendix C
    known-answer vectors (C.1 integers, C.2 literals/indexed, the
    C.3/C.4 request sequences, the C.5/C.6 response sequences with
    dynamic-table eviction and Huffman strings) as the spec-derived
    oracle (the inversion rule for owned codecs), frame-header shape
    vectors, session walkthrough units (concurrent out-of-order
    replies, window gating + WINDOW_UPDATE unblock, SETTINGS-driven
    window/frame-size deltas, continuation fragments, EOF/RST/GOAWAY/
    budget/timeout mappings, determinism), the new in-test
    rustls+ALPN h2 stub (`wrex_test::h2_stub` — server-side h2
    hand-rolled from fixed bytes, never the wrex-h2 encoder, so the
    harness never self-confirms), CLI ground truth (h2 end-to-end,
    two URLs → one connection → two concurrent streams, the ALPN
    auto-downgrade note, recipe knobs, usage exit 2 gates),
    `fuzz_h2_frame_decoder` + `fuzz_hpack` + `fuzz_h2_session` in the
    fuzz gate (release workflow + xtask smoke list), wrex-h2 in the
    Miri job, and wrex-tls ALPN negotiation tests. **Pre-existing bug
    the T15 suite caught (T9a)**: a positional URL list only
    auto-implied GET when the first token started `http://` — an
    `https://` list fell into the METHOD slot (fixed additively, both
    schemes). **A deliberate deviation from the charter sketch**: no
    new Kani harness for wrex-h2 (the frame codec is fuzz + RFC-vector
    territory; a header-roundtrip proof adds gate time for little
    coverage — the T4 chunked proof stays the Kani pattern for framing
    codecs). **Deliberate deferrals**: Huffman encode, HPACK
    incremental indexing on send, h2c/prior-knowledge cleartext,
    extended CONNECT, server push (never enabled), the HTTP/2 server
    role, SETTINGS_MAX_CONCURRENT_STREAMS-driven stream queueing
    (all streams open at once under the `MAX_STREAMS` budget), and
    TLS-protocol fuzzing (the standing rule). Man pages +
    completions regenerated (`wrex-http(1)`).

- **T16 — HTTP/2 send-side completion** — ✅ delivered (chartered at
  the T16 planning pass as two sub-tranches, both additive; the owned
  framing/session machinery from T15 is reused as-is, so ADR 2's
  ownership question stays settled — this closes T15's own recorded
  encode deferrals):
  - **T16a — HPACK encode completion** — ✅ delivered. `wrex-h2::hpack`
    grows the send-side **`HpackEncoder`** behind a two-value
    **`HpackEncodePolicy`**: `Indexed` (the new default — exact matches
    go out indexed, static **or** the send-side dynamic table; misses
    are literal-**with**-incremental-indexing (§6.2.1) with §4.3/§4.4
    eviction under the cap — entry size name+value+32 — and a §6.3
    size update leading the next block after a cap shrink; strings are
    Huffman-coded **when strictly shorter**, the fixed deterministic
    rule, no ratio heuristic) and `Literal` (the T15 wire verbatim —
    `encode_header_block` unchanged, the replay-parity knob).
    `wrex-h2::huffman` grows the **encode** side (appendix B table in
    reverse, MSB-first, EOS-prefix padding) closing the T15 deferral;
    both policies Huffman — the rule is per-string, not per-policy.
    The session owns **one encoder per connection** (the dynamic table
    persists across concurrent streams, so index reuse is
    stream-ordered); `encode_request_headers` threads it, and the
    peer's SETTINGS_HEADER_TABLE_SIZE applies to both sides of the
    context. `H2Session::new` delegates to the new `with_policy`; the
    recipe JSON grows the additive `hpack` field (`indexed`|`literal`,
    default `indexed`, recipe wins over `--hpack`; old recipes parse
    byte-identically).
  - **T16b — h2c / prior-knowledge cleartext** — ✅ delivered. The T15
    h2c deferral closed the honest way: **prior knowledge only** (RFC
    9113 §3.4) — `wrex http --http-version 2 http://…` speaks the
    client preface straight over the kernel `TcpDriver`, no TLS, no
    ALPN, and **no `Upgrade:` dance** (the 101-switch path stays a
    pointed usage error by omission). `H2Session` is untouched —
    transport-agnostic by construction (the T9b pattern); only the
    verb's transport pick differs. `https://` + 2 keeps the T15 ALPN
    rule (h2 offered, auto-downgrade note on decline).
  - Verification: Huffman **encode known-answer vectors** from RFC
    7541 appendix C.4 (`www.example.com`, `no-cache`,
    `custom-key`/`custom-value`, C.6.2 `307`) plus the every-byte
    0..=255 decode(encode(x)) == x roundtrip and the
    strictly-shorter gate; the **Indexed encoder reproduces the
    C.4.1/C.4.2/C.4.3 request sequences byte-for-byte** (the
    inversion rule for owned codecs — the spec's own bytes are the
    oracle; the decoder-side C.3/C.4/C.5/C.6 vectors already in-tree
    stay), send-side eviction/§4.4-oversize/size-update walkthroughs,
    the **T15 byte-identity pin** (`Literal` == `encode_header_block`,
    no state, replayed byte-identical), cross-stream table-reuse +
    determinism units (same sequence ⇒ byte-identical blocks
    round-for-round), and stateful-pairing roundtrips under both
    policies; `fuzz_hpack` extended over the encoder (never-panic,
    both-policy roundtrips through one peer context, replay
    determinism); the `wrex_test::h2_stub` frame loop genericized over
    `Read + Write` with a new cleartext **`spawn_h2c`** (prior
    knowledge, no TLS, no certificate — never the wrex-h2 encoder, so
    the harness never self-confirms); CLI ground truth — h2c
    end-to-end (`--format json`), two URLs → one cleartext connection →
    two concurrent streams, the `--hpack`/recipe knob riding both
    policies end-to-end, recipe-wins precedence, and the usage gates
    (bad `--hpack` exit 2, 1.1+`--hpack` inert). Man pages +
    completions regenerated (`wrex-http(1)` — the flags enumerate
    automatically). Deliberate deferrals: the `Upgrade: h2c`/101 path
    (prior knowledge only), Huffman *ratios* (strictly-shorter is the
    whole rule), HPACK never-indexed sending (a client-side privacy
    hint, not a wire need), extended CONNECT, server push (never
    enabled — the T15 disposition), the HTTP/2 server role,
    SETTINGS_MAX_CONCURRENT_STREAMS-driven stream queueing (the
    `MAX_STREAMS` budget stands), CONTINUATION **on send** (headers fit
    one frame in the CLI grammar), and cross-queue encoder reuse (one
    connection, one encoder, by construction).

- **T17 — IPv6 codec completion + registry dependency retrofit** — in
  flight (chartered at the T17 planning pass as four sub-tranches:
  T17-0 lands the [ADR 3](adr/0003-codec-dependency-direction.md)
  retrofit that the v6 codec work rides, then the codec tranches
  follow in order a → b → c, b and c independent of each other; wire
  behavior of the default build is byte-identical throughout):
  - **T17-0 — registry dependency-direction retrofit (ADR 3)** — ✅
    delivered. The registry's two string relations split by their
    true dependency semantics. **Requires** (parents) became real
    Cargo deps: every codec crate now depends on the crates
    implementing its `parents` (vlan→eth; arp/ip/ip6→eth,vlan;
    icmp→ip; icmpv6→ip6; udp/tcp→ip,ip6; dns/dhcp→udp — a DAG at
    crate granularity), children's `parents` arrays reference the
    parent crates' new `pub const KIND` (the kind vocabulary is
    compile-checked; it can no longer drift), and each crate grew a
    `register(&mut Registry)` closure — self first (dedup-guarded via
    `Registry::get`; **no wrex-core change**), then the parents' — so
    any feature selection is parent-complete by construction.
    **Enhances** (dispatch-into-children) stays registry strings:
    that edge cycles (udp⇄dns/dhcp — the tranche-7c in-crate stubs
    remain for absent-kind tests), and parent-without-child is the
    *meaningful* lean build (ipv6 without extension headers is
    exactly the pre-T17 degradation, preserved deliberately).
    `wrex::standard()` keeps its fixed cfg line order calling the
    closures — the default build's registration order (and with it
    `wrex fields`, man pages, completions, the "(registered: …)"
    errors) is byte-identical — while a lone `--features proto-dns`
    now registers the whole working stack (dns, udp, ipv4, ipv6,
    eth, vlan) and `--no-default-features` builds the honest empty
    registry: the child-without-parent footgun (eleven orthogonal
    features, no closure — a lone proto-dns build used to register a
    DNS codec over nothing, half-working chains and pointed errors)
    is dead at both the graph and the documented seam. The raw
    `Registry::register(&CODEC)` stays for bespoke/test registries
    (fuzz targets, wrex-scan's scan-shaped test registries);
    first-layer-anywhere craft is unchanged (deps guarantee
    presence, not stacking). Deliberate deferrals: per-parent
    optional deps (a hypothetical v4-only embedder — the 1.0-event
    rule), core-level parent-presence validation (presence by
    construction, not policing). Verification:
    `tests/registry_composition.rs` — the feature-agnostic
    no-dangling invariant (every registered kind's parents present,
    under whatever feature set the build made), per-crate closure
    tests (all 11: full-chain presence + idempotence — a second
    `register()` adds nothing), the all-codecs registration-order
    pin; **new child-side integration tests**, the ADR 3 win — each
    codec crate dissects a crafted parent→child frame through the
    real chain (eth→{vlan,arp,ipv4,ipv6}, ipv4→{icmp,udp,tcp},
    ipv6→{icmpv6,udp,tcp}, udp→{dns,dhcp}; previously impossible
    without stand-ins, this is the drift-kill for the string
    dispatch tables; the trailing `unknown` layers in the terminal-
    parent cases are the engine's honest no-inner-layer behavior,
    asserted as such); the CI `lean-build` job runs runtime smokes
    against the genuinely-lean binaries (a lone proto-dns build
    registers exactly its six-kind closure; the empty build
    registers nothing — the `wrex-test` dev-dep unifies all codec
    features on in cargo-test builds, so lean verification is
    runtime, not cargo-test); the udp crate's stand-in comments
    rewritten for the ADR 3 reality. Existing suites unchanged —
    differentials, fuzz-target registries, scan test registries,
    and man pages + completions byte-identical (`cargo xtask man`
    diff clean); a pre-existing fuzz-crate warning (unused
    `SessionAction` import) swept in passing. ADR 2 disposition on
    the whole tranche: **owned** (byte control over v6 header chains
    is mutation-central); the oracle lineage rides etherparse (ext
    headers), tshark, and dhcproto 0.15 in-process — it carries
    `dhcproto::v6`, so the DHCPv6 differential reuses the in-tree
    dependency (no MSRV bump).
  - **T17a — IPv6 extension headers** — in flight: **the core
    delivered** (the crate, the checksum seam, the wiring, units,
    child-side integration tests, the fuzz target, the gate lists);
    the differential-oracle arms + corpus + the Kani candidate are
    the recorded verification tail, next in order (the T11 α/β/γ
    sub-slice precedent). What landed: new `wrex-proto-ip6ext` crate,
    **the first crate shaped by ADR 3 from day one** (dep on
    `wrex-proto-ip6`, parents via KIND consts, a `register()` fn,
    feature `proto-ip6ext`) — and the **first multi-kind crate,
    deliberately** (rejected: folding into
    `wrex-proto-ip6` — churns a delivered T7b contract crate for
    zero gain, ip6's only edit stays the additive dispatch-map row;
    and seven crates — chain-shaped tests are inherently cross-kind,
    and sibling dev-deps cycle, stub-inversion, or a test shell above
    all seven recreate the family crate worse; five non-terminal
    kinds also share one private next_header→kind table and
    hopopts/dstopts are the same header shape). Seven kinds, rank 25,
    parents `ipv6|hopopts|routing|frag|dstopts|ah` (chains + self-
    stack, the QinQ precedent; `dstopts` twice per RFC 8200 ordering):
    `hopopts` (0) / `dstopts` (60) — `next_header` (autofilled, the
    `eth.type` rule), `len` (hdr_ext_len, 8-octet units), raw
    `options` region (TLV typing deferred); `routing` (43) —
    `next_header`, `len`, `type`, `segs_left`, raw `segments` region;
    `frag` (44) — `next_header`, `offset` (13 bits) + `m` (1 bit) as
    `Bits` windows (the ipv4 flags/frag_off pattern), `ident`,
    dissect-only view (no reassembly); `ah` (51) — `next_header`,
    `len` (4-octet units), `spi`, `seq`, raw `icv` region, **no
    integrity verification** (the standing TLS rule transposed);
    `esp` (50) — dissect-only `spi`/`seq`, terminal (encrypted
    payload stays payload); `nonext` (59) — a zero-extent terminal
    marker layer (the one engine-risk design point: zero-length
    spans in the reassemble/coverage invariants — planning decides
    with the invariant tests in view; fallback is a 59 dispatch note
    without a kind). `tcp`/`udp`/`icmpv6` grow the ext kinds in
    their parents additively; `ipv6.next_header` dispatch grows
    0/43/44/50/51/59/60 (was: → synthesized `unknown`); each ext
    kind dispatches its own `next_header` identically; Mobility/HIP/
    Shim6 stay deliberately undispatched. Quantized lengths:
    `Derived::Length` grows an additive `LengthUnits::{Bytes,
    Octlets4, Octlets8}` discriminator (the −2/−1 bias, the T14
    `LengthBase` pattern) and the T14 normalize fixed-point test
    extends over it. Span-patch: layouts for all seven kinds; raw
    regions take `wire:HEX`; population gate extends; inserting an
    ext header is an edit set with `ipv6.next_header` caller-set
    (the add-a-record workflow). Verification: codec units (goldens
    per kind, chains, fragment offset/M masking, AH bias, ESP
    terminal, nonext zero-extent, truncation), differential stacks
    `eth-ipv6-{hopopts,routing,frag,dstopts,ah}-{tcp,udp,icmpv6}` +
    `eth-vlan-ipv6-hopopts-*` vs etherparse (Ipv6Extensions/RawExt +
    Fragment + Auth slices; ESP stops at etherparse — tshark carries
    that arm) + tshark (the repeated-JSON-key caveat recurs), a
    handcrafted `ip6ext` golden corpus, `fuzz_dissect_ip6ext` in the
    fuzz gate, the crate joins the Miri job, a scoped Kani
    *candidate* on the quantized-length fold (measure first — the T4
    dns-proof retirement precedent), a child-side integration test
    through the real ipv6 codec, raw v6 probes with ext chains over
    the unchanged `RawIpv6Driver`. **Planning decisions resolved at execution**
    (beyond the charter): `nonext` is a REAL zero-extent kind (the
    dissect loop's `Layer` arm and `reassemble`'s coverage invariant
    both accept `start == end` spans — pinned by units;
    `ReadOutcome::Empty` materializes nothing, so it is never used);
    `frag` chains into next_header only at `offset == 0` (a
    non-initial fragment carries no upper header — `offset > 0` is
    terminal, the fragment bytes stay payload); `esp` is CRAFTABLE
    (the 8-byte spi/seq header + the caller's ciphertext as payload
    — "dissect-only" meant no further parsing); the options-style
    regions zero-pad to the 8-octet grid on craft (the dhcp sname
    precedent) with `len` autofill exact and explicit kept; AH's
    `icv` stays verbatim (never padded — it is the actual ICV);
    off-grid patch recomputation is the new pointed
    `PatchError::LengthNotQuantized` (never a silent truncation).
    **The seam planning discovered — resolved for full correctness,
    additively**: RFC 8200 §8.1 makes the L4 checksum cover the ext
    headers, so `Facts` grew `upper_start` (recorded by ipv4/ipv6 at
    write AND read — equals the L4 layer's own start on every
    ext-free stack, so pre-17a wire bytes are byte-identical), the
    L4 encode checksum defers accumulate from it, `DecodeCtx` grew
    `frame: &[u8]` (a `with_frame` engine constructor; `new()` keeps
    the empty frame so in-crate codec unit tests stay source- and
    behavior-compatible) so the dissect-side verify reads the range
    through the lookback — no verify-skip, no deferral — and
    `Derived::Checksum` grew an additive
    `ChecksumStart::{Layer, UpperPacket}` (the patch walk heals L4
    checksums over edited ext bytes; `Derived::Length` grew
    `LengthUnits::{Bytes, Octlets4, Octlets8}` with the −2/−1
    biases). Verification landed: codec units (the full in-crate
    RFC 8200 chain eth→ipv6→hopopts→dstopts→routing→frag→nonext
    through the real codecs, zero anomalies, T11a reassemble
    byte-identity; hopopts golden; routing len autofill/explicit;
    frag offset-0-chains/offset>0-terminal goldens; AH len bias +
    below-minimum never-fatal; esp terminal craft; nonext
    zero-extent reassemble; the quantized-length patch — normalize
    fixed point, 8-byte insert recompute, off-grid pointed error),
    child-side integration tests in the L4 crates (udp:
    [ipv6, hopopts, udp] with the wire checksum matching an
    independent RFC 8200 fold over the ext bytes and the dissect
    verify anomaly-free; tcp/icmpv6 ext-chain craft→dissect
    anomaly-free — the in-crate chain tests end at `nonext` because
    tcp/udp are children, uncreatable without a cycle), the fuzz
    target `fuzz_dissect_ip6ext` (start picked from the first byte
    over the seven kinds) in the fuzz gate list + the crate in both
    Miri lists, the composition suite grown (the ip6ext closure; the
    udp/tcp/icmpv6/dns/dhcp closures extend through udp's new
    parents — the lean CI proto-dns expected closure 6 → 13 kinds),
    `wrex fields`/man pages/completions regenerated, full workspace
    suite green (78 suites), clippy/fmt clean. **Verification tail, first
    slice delivered**: the `ip6ext` golden corpus (7 frames —
    hopopts/icmpv6, dstopts-twice/tcp, RH-style routing/udp,
    frag-offset-0/tcp, AH+ICV/icmpv6, esp+payload, nonext; zero
    anomalies, CLI-generated expected.json) — and the gates over it
    (population, identity sweep, normalize fixed point) **caught two
    real engine gaps, both fixed additively**: (1) the ext `len`
    fields count **their own span**, which frame-end `LengthBase`
    arithmetic cannot express — the dstopts-twice normalize proved it;
    `LengthBase` grew the `Span` variant (layer end − layer start);
    and (2) the pseudo-header under an ext chain folded with the
    ipv6 `next_header` (0 = hopopts) instead of the RFC 8200 §8.1
    *terminal* upper-layer protocol — the ext codecs now thread the
    final proto through the net facts (the L4 dissect verifies always
    hardcoded theirs; the patch walk's FromFacts path needed the
    threaded value). Also swept: `serialize_field_value`'s 16-byte
    ceiling was a *numeric* constraint that wrongly refused 20+ byte
    Bytes-kind spans (routing.segments — now Bytes kinds bypass it),
    and the self-referential ext-`len` insert workflow is pinned as
    the explicit-len-under-preserve two-step (the dissector trusts
    len, so a stale len cannot grow its own span — count-style
    fields are caller-decided, the add-a-record precedent);
    `LengthNotQuantized` is pinned by a wrex-core mock over a
    synthetic non-grid span (unreachable through the family's own
    dissectors — grid-aligned by construction). **Remaining tail
    (next in order)**: the differential stacks + etherparse ext arms
    (Ipv6Extensions slices; esp is tshark-only — etherparse stops at
    esp) + tshark map blocks, the Kani candidate on the
    quantized-length fold (measure first — the T4 dns-proof
    retirement precedent), and the env-gated `lo`
    echo-through-hopopts ground truth. Deliberate deferrals: fragment
    reassembly, hopopts/dstopts option typing (Router Alert/Jumbo/
    PadN sugar — the MLD goldens hand-hex the RA option), routing
    type-2 typed segments, Mobility/HIP/Shim6, ESP plaintext (crypto,
    the standing rule), 6LoWPAN/NHC.
  - **T17b — icmpv6 completion: MLD + NDP option crafting** —
    chartered, not yet landed. The icmpv6 codec grows in place (its
    ADR-3 dep on ip6 landed with T17-0). **MLD**, the `ndp.*`
    conditional-fields pattern keyed on type: MLDv1 (RFC 2710)
    query **130** (max_resp rides the code field, 1/10s units;
    `mld.addr`), report **131**, done **132**; MLDv2 (RFC 3810)
    query = 130 discriminated by body length (grows `mld.flags [s]`,
    `mld.qrv`, `mld.qqic`, `mld.nsrcs` autofilled over the raw
    sources region), report **143** with multicast-address records
    as an indexed record section (`mcast.N.type/addr/nsrcs` + sources
    — the dns/dhcp/opt pattern). Craft: v1 shapes + the v2 query
    fully typed; the v2 report rides the same list grammar as the
    NDP options (`--icmpv6-mld "exclude:ff02::1,…"`) — one grammar
    architecture instantiated twice. Hop-limit-1/router-alert wire
    conventions are caller stack work, not codec enforcement. **NDP
    option crafting** — the T7b/T10b deferral closed: the
    dissect-only `opt` section grows a write-side list grammar
    (`--icmpv6-opt`, the dhcp options-grammar architecture):
    `slla:MAC`, `tlla:MAC`, `mtu:N`, `prefix:LEN,IP[,valid,preferred]
    [,l][,a]` (the PI option — dissection grows typed `opt.N.*`
    subpaths), `raw:TYPE:HEX`; craft appends after the NDP body,
    order preserved. The `wrex-io::ndp` hand-rolled SLLA **stays
    hand-rolled** (the recorded T10b architecture — the io crate
    keeps no codec dependencies), and the NS-with-SLLA golden
    byte-compares the codec's craft against the driver's bytes —
    two in-tree lineages of the same wire bytes, an internal
    inversion-rule cross-check. Verification: codec units (v1/v2
    shapes, record dissection, PI plastering, grammar order/errors,
    the NS-SLLA byte-identity, checksums unchanged over the v6
    pseudo-header), the icmpv6 golden corpus grows, `fuzz_dissect_
    icmpv6` extends. Deliberate deferrals: MLD probing (scan/fuzz
    mode — the T10b NDP-probe precedent), NDP cache policy changes,
    `opt` sections on echo messages.
  - **T17c — DHCPv6** — chartered, not yet landed. New
    `wrex-proto-dhcp6` crate, ADR-3-shaped (dep on
    `wrex-proto-udp`, `register()` fn, feature `proto-dhcp6`): kind
    `dhcp6`, rank 40, parent `udp`; the RFC 8415 fixed header is 4
    bytes — `msg_type` (1–13; named grammar solicit|advertise|
    request|reply|release|decline|reconfigure|info_req|renew|rebind|
    relay_forward|relay_reply + raw) + `trans_id` (3 bytes) —
    everything else is options. `udp` dispatches 546/547 both sides
    (the 67/68 pattern; unregistered degradation never fatal). The
    options region (u16 code, u16 len) is craftable through the
    list grammar (`--dhcp6-options`, the dhcp/ip/tcp pending-
    continuation architecture): `client_id:HEX`/`server_id:HEX`
    (DUIDs raw — structured typing deferred), `ia_na:IAID[,t1,t2]`
    with `ia_addr:IP[,preferred,valid]` continuation (the fixed-part
    lifetimes), `oro:N…`, `dns:IP…` (23), `domain:` (24), `elapsed:N`,
    `rapid` (14), `hex:CODE:HEX`. Dissection renders every option as
    an indexed `opt.N.*` record section (raw `code/len/value` +
    typed `ip/num/text` subregions — the v4 mapping) and **nested
    sub-options render one level deep** (`opt.N.sub.M.*` — IA_NA →
    IAADDR, the record-section recursion's first nested use; deeper
    nesting flattens into `value`). Relay shapes (12/13) dissect with
    their 33-byte header; crafting relay messages is deferred.
    Verification: codec units (header, grammar records/typing/
    nesting, truncation, udp dispatch both ports + degradation), a
    both-direction differential mirroring `tests/dhcp_differential.
    rs` (wrex craft → dhcproto v6 parse, dhcproto v6 encode → wrex
    dissect; `dhcp_oracle` grows the v6 arm; order normalized per
    the v4 precedent), differential stacks `eth-ipv6-udp-dhcp6` +
    `eth-vlan-ipv6-udp-dhcp6` (`udp_for_dhcp6()` pin) vs etherparse
    + tshark (the repeated-key caveat again), a handcrafted `dhcp6`
    golden corpus (the full message-type set + rapid-commit + relay
    pair dissected), `fuzz_dissect_dhcp6` in the fuzz gate, the
    crate joins the Miri job, a CLI roundtrip. Deliberate
    deferrals: DHCPv6 auth (option 11 — crypto-adjacent, the
    standing rule), relay crafting, reconfigure/keyed surfaces, DUID
    structured typing, CLI-settable option records (`opt` stays
    dissect-only on the set side — the v4 decision, same rationale).

## Standing rules (carried from the tranche-1 plan)

- Protocol extension stays a compile-time registry: a new protocol is a
    new feature-gated crate with parent-crate deps and one `register()`
    closure — no dynamic loading ([ADR 1](adr/0001-compile-time-registry.md)
    resolved the T7 revisit; [ADR 3](adr/0003-codec-dependency-direction.md)
    set the dependency direction at T17-0: children require parents,
    dispatch-into-children stays registry strings, and every feature
    selection is parent-complete by closure).
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