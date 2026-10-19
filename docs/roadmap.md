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
- **T2 — scan**: sans-IO `Session` trait (event/queue state machine à la
  quinn-proto; shape frozen at T2 planning), TCP SYN/connect + UDP +
  ICMP scan orchestration over drivers, seeded jitter, `wrex scan`,
  RawIp driver.
- **T3 — DNS**: `wrex-proto-dns`, `wrex query`, differential vs
  trust-dns-proto (in-process) and `dig` (subprocess).
- **T4 — HTTP/1.1**: in-house sans-IO client session (httparse/http as
  parser substrate), `wrex http`, differential vs curl (subprocess) +
  reqwest (in-process); recipe JSON format.
- **T5 — capture/replay**: `wrex capture` (AF_PACKET + pcap writer),
  pcap import, `wrex replay`.
- **T6 — over-the-wire fuzzing**: mutation strategies (`wrex mut`),
  stateful prober, `wrex fuzz` against external stacks.
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