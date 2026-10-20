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
checksum folding). https:// is out of charter (no TLS this tranche).

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
`--seed` the query bytes (source port + 16-bit id) are
bit-reproducible. `--tcp` carries the same question over a fresh TCP
connection per attempt (RFC 7766).

HTTP (tranche 4; plain kernel TCP — no capabilities needed):

```sh
wrex http http://example.com/
wrex http POST http://example.com/api -H X-Thing:42 --data '{"a":1}'
wrex http --recipe req.json --format json     # deterministic replay
wrex http http://example.com/ --fail          # 4xx/5xx -> exit 1
```

Any completed exchange is exit 0; the response dissects to
text/json/raw (`raw` = body bytes only). https:// is out of charter
(no TLS this tranche).

Deliberately invalid packets are a feature: explicit values always win
and are kept unvalidated; `--strict` validates and reports violations
(`wrex: <layer>.<field>: <message>`, exit 2).

## Layout

```
crates/wrex           CLI + library facade + registry composition
crates/wrex-core      field/value model, schema (+record sections), codecs, encode/dissect engines
crates/wrex-io        Clock, Rng, Driver, AF_PACKET/raw-IP/kernel-TCP drivers (only unsafe crate), ifaces
crates/wrex-session   sans-IO Session contract + the shared runtime loop
crates/wrex-scan      scan orchestration: probe table, scheduler, seeded jitter
crates/wrex-dns       query orchestration: DNS ask sessions (udp + tcp)
crates/wrex-http      HTTP/1.1 client session (httparse + http types) + recipes
crates/wrex-test      test-support: strategies, oracles (+hickory/dig/reqwest), corpus, CLI harness
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
- Differential: our dissection vs etherparse (in-process) and tshark
  (subprocess over a hand-written classic-pcap wrapper); DNS vs
  hickory-proto (in-process) and dig (subprocess against an in-test
  stub server — no external network); HTTP vs reqwest (in-process)
  and curl (subprocess, stub server). Missing tools skip with a
  printed notice.
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