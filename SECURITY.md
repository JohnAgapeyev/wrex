# Security policy

wrex crafts, sends, captures and dissects raw network traffic. It is a
deliberate offensive-capability toolkit: it opens raw sockets and
writes attacker-controlled bytes to the network. Treat every invocation
as privileged tooling, not as an untrusted-input-safe service.

## Reporting a vulnerability

Report privately via GitHub security advisories ("Report a
vulnerability" on the repository Security tab). Please include:

- the commit you tested against,
- a reproducer (fuzz artifact, input file, command line),
- the affected surface (dissector, patch engine, pcap reader, ...).

Expect acknowledgement within a few days; fixes ship as soon as a
patch is verified against the full CI matrix (including the fuzz,
Miri and Kani release gates). No bounties — this is a personal
project; credit in the CHANGELOG is offered.

## Security posture

- **Scope**: the surface that matters is the parsers — `wrex dissect`,
  `replay`, `patch` and the pcap readers accept untrusted *files*;
  `recv` accepts untrusted *network bytes*. Both feed the same
  dissect/patch engines. Craft/send paths take user-intent input and
  are not considered an untrusted boundary.
- **Memory safety**: pure Rust everywhere except `wrex-io` (Linux
  AF_PACKET/AF_INET FFI; every unsafe site carries a SAFETY comment,
  enforced by a CI gate). All parsing crates are `#![forbid(unsafe_code)]`
  or unsafe-free by construction.
- **Verification stack**: units, property tests with persisted
  regressions, differential suites against independent oracles
  (etherparse, tshark, hickory, dhcproto, reqwest, curl, dig),
  libFuzzer (27 targets, committed seed corpora + a protocol
  dictionary), Kani proofs (checksums, schema quantization, chunked
  framing, filter/patch arithmetic), Miri on the release gate.
- **Resource bounds**: fixed caps on stdin (64 MiB), HTTP bodies,
  pcap trailers, DNS jumps, HPACK dynamic tables, h2
  streams/windows — each with an enforcement test; parsers are never
  fatal (structural failures are pointed anomalies or errors).

## Operational requirements

- Linux with `CAP_NET_RAW` for send/recv/capture/scan (all other
  functionality is unprivileged). macOS/BSD are **not** supported —
  non-Linux builds fail at the libc FFI boundary.
- Toolchain floor: Rust 1.88 (MSRV-gated in CI).
- The release gate runs the full fuzz matrix (300 s/target) and Miri
  before any tag ships.

## Telemetry

**None.** wrex makes no network connections on its own behalf except
the ones you ask for (scan/query/http/query --tcp targets), collects
nothing, and reports nothing anywhere. There is no update check, no
crash reporting, no usage statistic. This is a stated guarantee, not
an accident of the current implementation.

## Compatibility

- `wrex capture [--pcapng]` output is readable by Wireshark/tcpdump
  (pcapng SHB per RFC layout; verified against Wireshark 4.7.4), and
  the reader accepts foreign classic pcap (all four magic variants)
  and pcapng.
- File-format and CLI compatibility are tracked in CHANGELOG.md; a
  semver/deprecation policy arrives with the 1.0 tranche.
