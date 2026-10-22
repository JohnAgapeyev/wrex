# wrex

Wire Experiments Toolkit — a Rust CLI + library for arbitrary packet
crafting, sending, capture, and dissection. A long-term fusion of
curl/nmap/dig/scapy/tshark, built sans-IO, modular, and incremental over
successive tranches.

**Tranche 1** (delivered): the Cargo workspace and core engine,
L2–L4 protocol codecs (Ethernet, ARP, IPv4, ICMP, UDP, TCP), Linux
`AF_PACKET` raw send/recv, and the `wrex` binary with per-layer-flag
crafting plus `dissect`/`iface`/`fields` verbs, byte-transparent
stdin/stdout pipelines, and the full testing/verification infrastructure
(property-based, differential vs etherparse + tshark, golden corpus,
Miri, cargo-fuzz targets, advisory coverage) with per-commit CI.

**Tranche 2** (delivered): `wrex scan` — TCP SYN/connect, UDP and ICMP
scan orchestration as a sans-IO state machine (the frozen `Session`
contract in `wrex-session`), a kernel-routed raw-IP driver
(`wrex-io` `RawIpDriver`), seeded jitter/pacing, and target/port
grammar (IPv4, CIDR, ranges, top-100 TCP defaults). The receive path
now skips its own outgoing copies (`sll_pkttype`), resolving the
tranche-1 loopback-duplicate TODO.

**Tranche 3** (delivered): `wrex query` — DNS. A `wrex-proto-dns` codec
(one craftable question, full-message dissection with indexed record
paths `an.0.name`, `an.0.rdata`, … and compression-pointer decoding),
a records extension to the core schema (settable record sections,
`dns.an.0.ttl=300`-style filters), UDP port-53 dispatch, and a
seeded raw-UDP ask session (`wrex-dns`). Differentials: hickory-proto
(in-process; craft is byte-identical) and dig (subprocess, stub-server,
no external network).

**Tranche 4** (delivered): `wrex http` — an HTTP/1.1 client session
(`wrex-http`, httparse + `http` types, close-mode, chunked-with-trailers)
over the new kernel-TCP `TcpDriver` (unprivileged; `--source-port`),
`wrex query --tcp` (RFC 7766), and a deterministic recipe JSON format
(byte-identical replay; T6's mutation substrate). Differentials:
reqwest (in-process) + curl (subprocess, stub-server), plus Kani
proofs as a gating CI stage (chunked decoder, dns name decoding,
checksum folding). https:// closed its tranche-4 deferral at 8a.

## Install

```sh
cargo install --path crates/wrex
# or from the remote: cargo install --git https://github.com/JohnAgapeyev/wrex wrex
wrex --version          # wrex 0.1.0
```

Release profile, and the default feature set is the full user-facing
tool: every protocol codec (eth arp ipv4 icmp udp tcp) ships enabled.
Test/dev machinery (wrex-test, xtask, fuzz) is workspace-only and never
installed. Slim builds: `cargo install --path crates/wrex
--no-default-features --features proto-eth,proto-ip,proto-udp`.

Shell completions: `wrex completions bash|zsh|fish|elvish|powershell`.

## Manual

Systemd-style split — regenerate with `cargo xtask man`; CI verifies the
committed pages stay fresh with the code:

- `man/wrex.1`, `man/wrex-<verb>.1` — the CLI surface, generated from
  the same clap definition that renders `--help`.
- `man/wrex-<kind>.7` — one page per protocol, generated from the same
  in-code schema docs that rustdoc and `wrex fields [KIND]` print.

```sh
man man/wrex.1
man man/wrex-ipv4.7
```

## Quickstart

Craft with per-layer flags (`.` in field paths becomes `-`):

```sh
wrex craft --format hex \
  --layer eth --layer ipv4 --layer udp \
  --eth-dst=ff:ff:ff:ff:ff:ff \
  --ipv4-src=127.0.0.1 --ipv4-dst=127.0.0.1 \
  --udp-sport=4444 --udp-dport=5555 \
  --payload=hex:deadbeef
```

prints
`ffffffffffff0000000000000800450000200000000040117ccb7f0000017f000001115c15b3000c3d27deadbeef`.
Omit the `--layer` flags and the same bytes come out (layers implied from
the field flags, ordered by rank).

Discover every settable field, type, default and bit name before
reaching for anything else:

```sh
wrex fields            # all layers
wrex fields tcp        # one layer, with per-field docs
```

Dissect (never fatal; anomalies render as `! path: message`):

```sh
wrex craft --format raw ... | wrex dissect --format json
wrex dissect --format text < frame.bin
```

Send / receive on an interface (needs `CAP_NET_RAW`; the CLI prints the
`setcap` hint when missing):

```sh
wrex send -i lo --layer eth --layer ipv4 --layer udp \
  --ipv4-src=127.0.0.1 --ipv4-dst=127.0.0.1 \
  --udp-sport=1 --udp-dport=2 --payload=hex:aa
wrex recv -i lo --count 1 --format jsonl --filter 'udp.dport=2'
```

Interfaces:

```sh
wrex iface
```

Scan (tranche 2; needs `CAP_NET_RAW` like send/recv):

```sh
# default: syn scan of the top-100 TCP ports
wrex scan -i eth0 192.168.1.10

# explicit ports + ranges, 500 packets/sec, reproducible under a pinned seed
wrex scan -i eth0 --ports 22,80,443,8000-8100 --rate 500 --seed 42 192.168.1.10

# UDP scan (ICMP port-unreachable quotes are attributed per-probe)
wrex scan -i eth0 --mode udp --ports 53,161 192.168.1.10

# host sweep: echo ping across a range
wrex scan -i eth0 --mode icmp 10.0.0.1-10.0.0.99
```

Results stream as they resolve (`--format text|json|jsonl`); a scan
completes with exit 0 regardless of findings. Pacing defaults to
100 packets/sec (`--rate 0` = uncapped burst), `--jitter` is seeded
from `--seed`, and probe identities (source ports, tcp seqs, icmp
ids) are bit-reproducible under a pinned seed.

DNS (tranche 3; needs `CAP_NET_RAW`):

```sh
# ask one question over raw UDP; the reply dissects to stdout
wrex query -i eth0 --server 192.168.1.1 example.com
wrex query -i eth0 --server 1.1.1.1 --type MX --seed 42 example.com

# craft/dissect DNS directly (records surface as indexed paths)
wrex craft --format hex --layer dns --dns-name example.com --dns-type AAAA
wrex dissect --start dns < reply.bin        # an.0.rdata, an.0.ttl, …
wrex fields dns
```

A reply is exit 0 whatever the rcode says (NXDOMAIN/SERVFAIL are
data); silence after `--retries` attempts is exit 1. Under a pinned
`--seed` the query bytes (source port + 16-bit id) are bit-reproducible.
`--tcp` carries the same question over a fresh TCP connection per
attempt (RFC 7766); `--tls` wraps it in DNS-over-TLS (RFC 7858, default
port 853, `--tls-insecure`/`--tls-ca` like http).

HTTP (tranche 4; plain kernel TCP — no capabilities needed):

```sh
wrex http http://example.com/
wrex http POST http://example.com/api -H X-Thing:42 --data '{"a":1}'
wrex http --recipe req.json --format json     # deterministic replay
wrex http http://example.com/ --fail          # 4xx/5xx -> exit 1
wrex http https://example.com/ --tls-insecure   # lab targets: no cert check
wrex http https://example.com/ --tls-ca myca.pem # extra roots next to system
```

Any completed exchange is exit 0; the response dissects to
text/json/raw (`raw` = body bytes only).

**Tranche 8a** (delivered): TLS. https:// rides rustls (0.23, `ring`
provider) behind a `wrex-tls` driver adapter that composes the kernel
`TcpDriver` under the same stream conventions (orderly close =
empty frame), so the retry/render/`--fail`/budget paths stay
byte-identical to plain http. `--tls-ca` adds roots (PEM/DER) on top
of the system store; `--tls-insecure` accepts any certificate;
`query --tls` is DNS-over-TLS on port 853. Deferrals: mTLS, session
resumption/0-RTT, ALPN/h2, keep-alive.

**Tranche 5** (delivered): `wrex capture`/`wrex replay` — an in-house
classic pcap reader/writer (`wrex-pcap`, no libpcap; all four magic
variants read, streaming LE-µs write), the AF_PACKET capture tap
(`-w FILE.pcap`, optional `--format` tee), and offline dissect /
paced verbatim re-send of captured files.

**Tranche 8b** (delivered): pcapng. `wrex capture --pcapng` writes
pcapng (SHB + one EN10MB interface, EPB records); `wrex replay`,
`wrex mut -r` and the corpus importer read both classic pcap (all four
magic variants) and pcapng (LE/BE × µs/ns, unknown blocks skipped).

**Tranche 6** (delivered): over-the-wire fuzzing. `wrex mut`
(`wrex-mut`) — seeded, dissect-aware frame mutation (field/len/flip/
splice/raw strategies; checksums re-derive) into stdout or a pcap
corpus; `wrex fuzz` (`wrex-fuzz`) — the stateful recording prober:
baseline + mutated probes over the raw-IP driver, replies matched
per probe (post-mutation identity), one finding per probe with the
exact probe bytes (replayable with `wrex send`/`replay`) for offline
differential.

**Tranche 9a** (delivered): HTTP keep-alive + chunked request
bodies. `wrex http [METHOD] URL [URL...]` (or a recipe array /
`{"requests": [...]}` file) rides ONE connection in order — the
response's own `Connection` header (and HTTP/1.0, and read-to-close
framing) decides whether the queue continues; recipe
`body_framing: "chunked"` (+ fixed `chunk_size`, default 4096) sends
deterministic fixed-size request chunks.

**Tranche 9b** (delivered): application-layer fuzzing. `wrex fuzz
--mode http|dns` — the probe unit is one whole request exchange over
a fresh kernel `TcpDriver` connection (no raw sockets, no `-i`):
mutated request bytes out, response bytes recorded until EOF (budget
capped), one finding per probe, seeded and reproducible. The
twice-deferred userspace TCP stack stays deferred — kernel transport
covers application-layer mutation; only mutating TCP state *and*
continuing the exchange would need it.
 
**Tranche 11** (delivered): lossless dissection + the span-patch
engine — `DissectedPacket` retains the frame (reassemble is
byte-identical by construction), every dissected field carries wire
geometry (`dissect --spans`), and `wrex_core::patch::patch` applies
byte/bit edits + a caller-selected consistency scope. **13a**: the
`Codec::reencode` hook applies `ReEncode` regions (dhcp
`sname`/`file` NUL-padding) and dns compression-resolved names
re-attach over the **pointer target** — a same-width wire-name patch
rewrites the shared target, aliases see it too. **13b**: `wrex fuzz
--mode http|dns --tls` wraps each probe connection in the T8a rustls
adapter (https/DoT; `--tls-ca` complements the system roots,
`--tls-insecure` accepts anything; defaults 443/853).

**Tranche 12** (delivered): `wrex diff BASELINE.jsonl MUTATED.jsonl` —
the offline findings differential (outcome deltas, reply
add/remove/divergence, one-sided probes; pairs by probe identity,
index-wise, `strategy` never matched; exit 0, malformed lines exit 2).

**Tranche 13** (delivered): span-patch completion + TLS-wrapped app
probes. **13a**: every dissected field key is patchable — the
`Codec::reencode` codec hook applies `FieldSpan::ReEncode` regions
(dhcp sname/file: value + NUL padding, the craft-time rule re-used;
over-length/embedded-NUL are pointed rejections), and dns names
resolved through compression pointers carry the **pointer target's**
extent: a patch rewrites the shared target in place (same width,
wire-label bytes validated; every alias through the pointer sees the
change; length changes ride Insert/Delete, the 11b-β policy). The
`wrex-mut` field strategy keeps its ReEncode exclusion deliberately —
the hook's value encoding is codec-specific, so the engine API/tests
carry those patches. **13b**: `wrex fuzz --mode http|dns --tls` — one
fresh TLS connection per probe over the T8a `TlsDriver` (lazy
handshake inside the first pump under the probe deadline; a connect
or verification failure spends the attempt as a silence finding),
`--tls-insecure`/`--tls-ca` carried through (SNI from the target),
default ports 443/853, retries repeat the exact mutated bytes on
fresh connections. The userspace TCP stack keeps its deferral (the
6th; the trigger is still unmet).

**Tranche 10** (delivered): IPv6 parity closure. **10a**: the kernel
`TcpDriver` speaks both families (EOF/bind/`--source-port` conventions
unchanged), so `wrex query --server ::1` (raw UDP, `--tcp`, `--tls`
DoT), `wrex http http://[::1]/`, and `wrex fuzz --mode http|dns` v6
targets all ride v6; the DNS session builds `ipv6`-rooted queries with
family-aware reply matching. **10b**: the raw v6 driver resolves
off-link next hops — `/proc/net/ipv6_route` lookup plus an NDP
cache (hand-rolled NS/NA in `wrex-io::ndp`, no codec deps); local and
multicast destinations keep the `lo`/on-link iface-MAC behavior, and
a failed resolution falls back to it (never fatal).

Mutation and probing (tranche 6; `mut` needs no privileges, `fuzz`
injects via a raw-IP socket — `CAP_NET_RAW`):

```sh
# 8 seeded mutants of a golden frame (deterministic under --seed)
wrex mut --count 8 --seed 42 <frame.hex>
wrex mut -r capture.pcap --strategy field -w mut.pcap

# prober: one baseline + 4 mutated rounds per slot, findings as jsonl
wrex fuzz -i lo --baseline --rounds 4 --format jsonl 127.0.0.1
wrex fuzz -i eth0 --mode udp --ports 53,161 --seed 7 10.0.0.0/24
```

Deliberately invalid packets are a feature: explicit values always win
and are kept unvalidated; `--strict` validates and reports violations
(`wrex: <layer>.<field>: <message>`, exit 2).

**Tranche 11a** (delivered): the byte-fidelity contract. Dissection
retains the original frame (`DissectedPacket::frame`) and
`reassemble()` splices the layer spans + payload back verbatim —
zero edits ⇒ byte-identical by construction, malformed input
included (nothing is re-derived: wrong checksums, compressed names,
trailing bytes all survive). Gated by `tests/reassemble.rs`: every
stack strategy, every corpus frame, and a deliberately wrong
checksum that must stay wrong.

**Tranche 11b-α+β** (delivered): the span-patch engine. Per-field
wire geometry (`FieldSpan`: bytes, bit windows, re-encode, none)
populated for **all** codecs (L2–L4 via static layout tables;
dns/dhcp via parse-time spans: record sections, the hoisted
`msg_type` source, pointer-vs-uncompressed name policy,
scattered dns flag bits), and `wrex_core::patch`: an ordered edit
list (`SetField`/`Insert`/`Delete`) with a representability +
overlap pre-pass, splice application (bit-masked container
writes), and the caller-selected **consistency scope**
(`Scope::all` / `none` / selective with layer shorthand) driving
derived-field recomputation (lengths, checksums over the
pseudo-header from the dissected facts) — edits decide bytes,
scope decides recomputation, stale fields outside scope stay
verbatim, wrongness included. The golden workflow: add a DNS
record with one edit set (Insert + explicit `ancount` patch),
no spec round-trip. `wrex mut` edit-set integration and
`dissect --spans` are the chartered follow-up.

## Layout

```
crates/wrex           CLI + library facade + registry composition
crates/wrex-core      field/value model, schema (+record sections), codecs, encode/dissect engines
crates/wrex-io        Clock, Rng, Driver, AF_PACKET/raw-IP/kernel-TCP drivers (only unsafe crate), ifaces, NDP next-hop resolution (T10b)
crates/wrex-session   sans-IO Session contract + the shared runtime loop
crates/wrex-scan      scan orchestration: probe table, scheduler, seeded jitter
crates/wrex-dns       query orchestration: DNS ask sessions (udp + tcp)
crates/wrex-http      HTTP/1.1 client session (httparse + http types) + recipes
crates/wrex-tls       rustls-backed TLS Driver adapter composing the kernel TCP driver (tranche 8a)
crates/wrex-pcap      classic pcap + pcapng readers/writers (no libpcap)
crates/wrex-mut       seeded, dissect-aware mutation engine (tranche 6a)
crates/wrex-fuzz      stateful recording prober session (tranche 6b)
crates/wrex-test      test-support: strategies, oracles (+hickory/dig/reqwest), corpus, CLI harness, TLS stub
crates/wrex-proto-*   eth arp ip icmp udp tcp dns (one crate each; no cross-deps)
fuzz/                 cargo-fuzz targets (excluded from the workspace)
xtask/                `cargo xtask` — verify (+kani) / coverage / man / corpus-import
man/                  generated man pages: wrex(1), wrex-<verb>(1), wrex-<kind>(7)
```

Protocol extension is a compile-time registry: a new protocol is a new
crate behind a `wrex` feature flag plus one `register` line in
`crates/wrex/src/lib.rs`.

## Verification

The commands CI runs per commit (all green locally except where noted):

```sh
cargo xtask verify                     # fmt + clippy + workspace tests
cargo xtask verify --with-differential # + differential suites (tshark if present)
cargo xtask verify --with-miri         # + Miri (needs nightly)
cargo xtask verify --with-fuzz         # + 60s fuzz smoke per target (nightly)
cargo xtask coverage --branch --mcdc-probe   # advisory coverage + MC/DC probe
```

- Property-based: 256 cases/run, deterministic via `PROPTEST_RNG_SEED=31337`.
- Fuzzing: cargo-fuzz targets do **not** run per commit — the full
  list with a real libFuzzer budget is the release gate
  (`.github/workflows/fuzz.yml`: version tags + manual dispatch,
  300s/target; `cargo xtask verify --with-fuzz` is the local 60s/target
  smoke mirror). Per-commit CI carries the unit, proptest and
  reference-model suites over the same engines.
- Miri: also not per commit — it grew past ~11 minutes once the
  tranche-11b codec population landed, so it runs in the same release
  gate as the fuzz matrix (`.github/workflows/fuzz.yml`, tags +
  manual dispatch; `cargo xtask verify --with-miri` is the local
  mirror over the deterministic golden/unit suites).
- Differential: our dissection vs etherparse (in-process) and tshark
  (subprocess over a hand-written classic-pcap wrapper); DNS vs
  hickory-proto (in-process) and dig (subprocess against an in-test
  stub server — no external network); HTTP vs reqwest (in-process,
  http:// and https:// over the same in-test TLS stub, reqwest with
  `rustls-tls`) and curl (subprocess, stub server). Missing tools
  skip with a printed notice.
- Kani proofs (gating CI job, scoped for cost): chunked-body decoder
  panic-freedom and checksum folding — curated bounds under a 6GB
  memory ceiling (a dns decode_name proof was retired: every scoped
  variant cost multi-GB solver state; that decoder is carried by 18
  unit vectors and `fuzz_dissect_dns`).
- Raw-socket tests are env-gated (`WREX_DRIVER_TESTS=1`, run under sudo
  in CI): send/recv round-trip on `lo`, scan + query ground truth
  (bound listener → open, unbound → closed, UDP/ICMP semantics, seed
  determinism, query --tcp). Without passwordless sudo:
  `unshare -Urn sh -c 'ip link set lo up; WREX_DRIVER_TESTS=1 cargo
  test --all-features -p wrex-io -p wrex'` runs them in a user
  namespace with CAP_NET_RAW. HTTP and query --tcp ride plain kernel
  TCP: their stub-server suites run unprivileged everywhere.
- Golden corpus: 4 real captures under `crates/wrex-test/corpus/`
  (arp, icmp, tcp, udp), committed with expected dissections; import
  more with `cargo xtask corpus-import <pcap> <name>`.
- Coverage is advisory (reported, never gated). MC/DC: rustc removed
  `-Zcoverage-options=mcdc` in late 2025; `cargo xtask coverage
  --mcdc-probe` reports nightly availability until the 2026 re-land.

## License

MIT OR Apache-2.0.