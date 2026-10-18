# wrex

Wire Experiments Toolkit — a Rust CLI + library for arbitrary packet
crafting, sending, capture, and dissection. A long-term fusion of
curl/nmap/dig/scapy/tshark, built sans-IO, modular, and incremental over
successive tranches.

**Tranche 1** (this repo state): the Cargo workspace and core engine,
L2–L4 protocol codecs (Ethernet, ARP, IPv4, ICMP, UDP, TCP), Linux
`AF_PACKET` raw send/recv, and the `wrex` binary with per-layer-flag
crafting plus `dissect`/`iface`/`fields` verbs, byte-transparent
stdin/stdout pipelines, and the full testing/verification infrastructure
(property-based, differential vs etherparse + tshark, golden corpus,
Miri, cargo-fuzz targets, advisory coverage) with per-commit CI.

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

Deliberately invalid packets are a feature: explicit values always win
and are kept unvalidated; `--strict` validates and reports violations
(`wrex: <layer>.<field>: <message>`, exit 2).

## Layout

```
crates/wrex           CLI + library facade + registry composition
crates/wrex-core      field/value model, schema, codecs, encode/dissect engines
crates/wrex-io        Clock, Driver, AF_PACKET raw driver (only unsafe crate), ifaces
crates/wrex-test      test-support: strategies, oracles, corpus, CLI harness
crates/wrex-proto-*   eth arp ip icmp udp tcp (one crate each; no cross-deps)
fuzz/                 cargo-fuzz targets (excluded from the workspace)
xtask/                `cargo xtask` — verify / coverage / man / corpus-import
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
  (subprocess over a hand-written classic-pcap wrapper). tshark tests
  skip with a printed notice when tshark is absent.
- Golden corpus: 4 real captures under `crates/wrex-test/corpus/`
  (arp, icmp, tcp, udp), committed with expected dissections; import
  more with `cargo xtask corpus-import <pcap> <name>`.
- Raw-socket tests are env-gated (`WREX_DRIVER_TESTS=1`, run under sudo
  in CI): send/recv round-trip on `lo`. Without passwordless sudo:
  `unshare -Urn sh -c 'ip link set lo up; WREX_DRIVER_TESTS=1 cargo
  test --all-features -p wrex-io -p wrex'` runs them in a user
  namespace with CAP_NET_RAW.
- Coverage is advisory (reported, never gated). MC/DC: rustc removed
  `-Zcoverage-options=mcdc` in late 2025; `cargo xtask coverage
  --mcdc-probe` reports nightly availability until the 2026 re-land.

## License

MIT OR Apache-2.0.