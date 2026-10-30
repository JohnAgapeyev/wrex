# wrex — Deferral ledger

Every consciously-deferred item in one tracked place. The delivered
tranche charters record deferrals inline (spread across ~1,600 lines
of [roadmap](roadmap.md)); this ledger is the reconciled view, with one
row per item, deduplicated (the userspace-TCP stack was deferred
six separate times before its trigger was met), each with an owner
and a trigger. Reconciled at the 2026-10-23 extension pass.

Status semantics:

- **Open — owner Tn**: in scope of a planned tranche.
- **Parked — trigger**: deliberately not scheduled; the recorded
  trigger decides if it ever returns.
- **Won't-do (recorded)**: a standing decision, recorded so it is
  never re-litigated accidentally.
- **Closed by Tn**: kept for history, so a re-read of an old charter
  resolves.

Priorities (P0–P3) follow the [roadmap extension](roadmap.md)
definitions. Items never chartered live in [backlog.md](backlog.md)
instead; open *decisions* live in the roadmap's extension section.

## Crypto & TLS

| Item | Origin | Status |
|------|--------|--------|
| mTLS / client certificates | T8a (re-deferred T10a) | Open — T32 |
| Session resumption / 0-RTT | T8a (re-deferred T10a) | Open — T32 |
| ALPN negotiation | T8a | Closed by T15a |
| Keep-alive | T4 | Closed by T9a |
| https:// scheme | T4 | Closed by T8a |
| System-store override by `--tls-ca` | T8a | Won't-do (complements, never replaces) |
| TLS-protocol fuzzing (malformed-but-authenticated records; needs session keys) | Standing rule | Parked — separate specialized capability; if chartered, composes via rustls unbuffered access |
| h2 server role; HTTP/2 server push | T15/T16 | Won't-do (probers/listeners only; push never enabled) |
| ESP plaintext decryption | T17a | Won't-do (crypto standing rule) |
| DHCPv6 auth (option 11) | T17c | Parked — crypto-adjacent, standing rule |

## pcap / capture formats

| Item | Origin | Status |
|------|--------|--------|
| BPF filter compilation | T5 (re-affirmed T14) | Open — T25 (cBPF rung) |
| Non-Ethernet capture linktypes | T5 | Open — T23a (SLL/SLL2 write, RAW/NULL/LOOP read) |
| Ring-buffer / rotation | T5 | Open — T23b |
| Raw-IP capture | T5 | Open — T23a (subsumed by the RAW linktype read) |
| `--snaplen` on patch/capture write | T14 | Open — T23a |
| pcapng multi-interface write | T8b | Closed by T18b (`new_multi`) |
| IDB/EPB write options (`if_tsresol`, `epb_flags`) | T8b | Closed by T18b |
| Simple Packet Block read / write | T8b | Read closed by T18b; **write parked** (no timestamp — capture needs one), P3 |
| Multi-section files (read) | T8b | Closed by T18b (mid-file SHB skips) |
| Per-interface resolutions under `new_multi` | T18b | Open, P3 |
| `epb_flags` on the CLI | T18b | Open, P3 (no caller yet) |
| Pcapng compression | T8b | Open, P3 |
| Span-carrying pcapng options | T11a | Open, P3 |

## HTTP/1.x, h2, h3

| Item | Origin | Status |
|------|--------|--------|
| Chunked request bodies | T4 | Closed by T9a |
| HPACK Huffman encode | T15 | Closed by T16a |
| HPACK incremental indexing on send | T15 | Closed by T16a |
| h2c / prior-knowledge cleartext | T15 | Closed by T16b (prior knowledge only) |
| `Upgrade: h2c` / 101-switch path | T16 | Won't-do for h2c (prior knowledge by design); **the 101 door opens for WebSocket at T27 — a different protocol's upgrade** |
| Extended CONNECT | T15/T16 | Open — T27 (WebSocket over h2) |
| HPACK never-indexed sending | T16 | Open, P3 (client-side privacy hint, not a wire need) |
| Huffman *ratios* (beyond strictly-shorter) | T16 | Won't-do (strictly-shorter is the whole rule) |
| SETTINGS_MAX_CONCURRENT_STREAMS-driven stream queueing | T15/T16 | Open, P3 (the `MAX_STREAMS` budget stands) |
| CONTINUATION on send | T16 | Open, P3 (CLI grammar fits headers in one frame) |
| Cross-queue encoder reuse | T16 | Won't-do (one connection, one encoder, by construction) |
| http-head-aware `field` mutation strategies | T9b | Open, P3 (raw level covers) |
| v6 TLS stubs in the CLI suite | T13b | Open, P2 (stub binds 127.0.0.1; the driver is family-agnostic) |
| h2 redirect-chain stream reuse | T19a | Open, P2 (an h2 chain under `--follow` opens a connection per hop; the 1.1 chain rides `push_request`; wiring H2Session re-entry is the future work) |
| Digest `qop=auth-int` (HA2 over the body hash) | T19a | Open, P3 (challenges offering it are pointed errors; `auth` and the legacy no-qop shape cover the field) |
| curl `-w` `%{…}` stdout DSL | T19a | Won't-do as a DSL — `--timing` carries the four fields json-shaped (the whole output is jsonl/json contracts) |
| Multi-member gzip decode divergence | T19a | Recorded divergence (wrex decodes like browsers; curl exits 23 after the first member) — kept deliberately |
| RFC 9722 dictionary-based content compression | T19 | Won't-do (browsers-only today; no curl parity to close) |
| `libzstd-rs` migration trigger | T19 | Parked — swap `ruzstd` when Trifecta's pure-Rust zstd leaves pre-release (same seam, one-line); the C `zstd` crate is the named fallback if the perf-diff delta ever matters |
| Proxy env-var pickup (`http_proxy`/`HTTPS_PROXY`/`ALL_PROXY`/`no_proxy`) | T19b | Open, P2 (flags only today; curl's env semantics incl. the lowercase-only `http_proxy` rule are a follow-up) |
| `--retry` backoff (curl's 1s/2s/4s… delay) | T19a | Won't-do as default (the lab-tool deviation: retry immediately, deterministic; a `--retry-delay` knob can ride if a need appears) |
| URL-embedded credentials (`user:pass@host`) | T19 | Open, P3 (curl strips them cross-host; `-u`/`--user` covers) |
| `-d`-implies-POST (curl's `-d` method default) | T19 | Open, P3 (the T4 grammar keeps `--data` orthogonal to the METHOD token; a POST without a method verb is sugar) |

## DNS / DHCP

| Item | Origin | Status |
|------|--------|--------|
| EDNS0 crafting (OPT records) | T3 | Closed by T20a-1 (the `--dns-edns*` sugar) |
| Typed rdata: SOA/MX/NS/SRV (+ settable answer records) | T3 | Closed by T20a-2 (the full alias table + `an/ns/ar` index paths; rdata craft stays `hex:` — typed rdata *crafting* is the recorded remainder) |
| Typed rdata *crafting* (building rdata from typed subkeys; the read side renders, the write side stays `hex:` bytes) | T20a-2 | Open, P3 (the T7c `hex:` escape precedent covers) |
| DoH over negotiated h2 (RFC 8484 §5.1 prefers HTTP/2; `--doh` rides the 1.1 session today — h2 composition = the T15d `H2Session`, a whole-queue runner rework) | T20b | Open, P2 |
| Filter typing for nested `sub` record paths (dns `an.0.mx.preference`, the dhcp6 shape) | T20a-2 | Open, P2 |
| DNSSEC chain validation | T20a-2 | Won't-do (read-side structural rendering only, the crypto standing rule) |
| mDNS responder/announce mode (the query verb asks; `wrex listen`-adjacent answering is T33 territory) | T20b | Open — T33 |
| LLMNR crafting (5355 dissect-only by design; queries ride `wrex query` + `--port 5355`) | T20b | Won't-do (dissect-only) |
| Multi-question craft | T3 | Open, P3 |
| DNS name patches through compression pointers | T11b-β | Closed by T13a |
| `Derived::Count` (section-count recomputation) | T11b-β (re-affirmed T13a, T14) | Parked — revisit only if a scope-managed count workflow appears |
| DHCPv6 | T7c | Closed by T17c |
| DHCPv6 relay message crafting | T17c | Open, P2 (the pointed write error stands) |
| DHCPv6 reconfigure / keyed surfaces | T17c | Parked |
| DHCPv6 DUID structured typing | T17c | Open, P2 |
| CLI-settable option records (`opt` dissect-only on the set side) | T7c (re-affirmed T17c) | Parked (the `hex:` escape covers; same rationale both times) |
| Filter typing for nested `sub` record paths (dhcp6) | T17c | Open, P2 |
| DHCPv4 relay / sname-overload semantics | T7c | Open, P3 |

## IPv4 / IPv6 / L4 codecs

| Item | Origin | Status |
|------|--------|--------|
| IPv4/TCP options read-side typing (the T11 dynamic regions) | T11 | Open — T22 |
| IPv6 extension headers | T7b | Closed by T17a |
| Hopopts/dstopts option typing (Router Alert/Jumbo/PadN sugar) | T17a | Open, P2 (MLD goldens hand-hex the RA option) |
| Routing type-2 typed segments | T17a | Open, P3 |
| Mobility/HIP/Shim6 dispatch | T17a | Won't-do (deliberately undispatched) |
| 6LoWPAN/NHC | T17a | Parked |
| MLD codecs (v1 triad, v2 query/report) | T7b | Closed by T17b |
| MLD probing (scan/fuzz mode) | T17b | Closed by T21a — `wrex scan --mode mld` (MLDv1 query per group, report → alive); fuzz-mode MLD rides the icmpv6 probe shapes |
| Parse-time span population for icmpv6 conditional bodies (mld.* / mld flags) | HP3-a (new) | Open, P2 — the fields are `None`-by-policy (no static layout; the conditional v1/v2 body position), patching is the pointed `UnsupportedPath`; the wire positions are pinned by the G3 KAV table + the G2 sweep instead |
| Off-link NDP resolution | T7b | Closed by T10b |
| NDP option crafting | T7b/T10b | Closed by T17b |
| NDP probe fuzzing | T10b | Parked (the cache is best-effort infrastructure) |
| NDP cache policy changes | T17b | Parked |
| Route re-reads on drift | T10b | Won't-do (read once at open, by design) |
| Retransmitted NS beyond the single bounded attempt | T10b | Won't-do (by design) |
| `opt` sections on echo messages (icmpv6) | T17b | Open, P3 |
| Fragment reassembly | T17a | Closed by T18a |
| Atomic-fragments rule (RFC 6946 §4) | T18a | Open, P2 |
| Pathological-fragment hardening beyond the byte budget | T18a | Parked (the 1 MiB budget covers) |
| Fragment *emission* | T18a | Won't-do (wrex never fragments on send — MTU is the kernel's) |
| `dissect --reassemble` | T18a | Won't-do (dissect is a single-frame verb; streams live in replay) |
| Foreign-fragment corpus | T18a | Closed by HP3-b (the `scen-frag-v4`/`scen-frag-v6` oracle-capture scenarios: kernel-carved `ping -M want` fragments over a 1500-MTU veth, both families, the mf-bug's own corpus) |
| v6 pseudo-header length convention under ext chains (RFC 8200 §8.1 upper-layer length vs `upper_start` region length) | T18a | Closed by HP3-b — the foreign corpus demanded it (the kernel's own MLDv2 reports through a Router-Alert hopopts dissected with a constant-delta false `icmpv6.checksum` anomaly): the L4 checksum now covers the L4 message only (pseudo length = L4 length, fold from the L4 header — the kernel/tshark reading of §8.1), on encode, verify, and the patch walk (`ChecksumStart::UpperPacket` collapses to `Layer`) |
| L4 checksum verify on single-fragment carriers | HP3-b (new) | Closed by HP3-b: a fragment can never verify (the checksum folds over the original unfragmented message); `Facts::fragmented` records the carrier and icmp/icmpv6/udp/tcp skip the verify — the reassembled datagram verifies instead (the kernel/tshark behavior) |
| v6 tail-shorthand ranges | T7b | Open, P3 |
| IPv6 zone-ids in URL targets | T10a | Open, P2 |

## Engines (patch / mut / dissect)

| Item | Origin | Status |
|------|--------|--------|
| `dissect --frame` / retained frame in JSON | T11a | Closed by T14 |
| ReEncode patch application | T11b-α | Closed by T13a |
| `wrex-mut` edit-set integration; `dissect --spans` | T11b-α | Closed by T11b-γ |
| `mut` ReEncode strategies | T13a | Won't-do (the hook's value encoding is codec-specific; the engine API/tests carry those patches) |
| Record-section sugar ("append an A record" one-liner) | T14 | Open, P2 (the engine accepts the edit set; sugar rides the recipe generalization, T34-adjacent) |
| JSON edit-list files / per-frame edit scripts | T14 | Open, P2 — owner: recipe generalization (T34) |
| Presentation-to-wire sugar for Str-over-raw-span fields | T14 | Open, P2 (`wire:HEX` covers) |
| `--send` composite on `patch` | T14 | Won't-do (composition over composites; `replay -i` covers the send step) |

## Scan / fuzz / sessions / transport

| Item | Origin | Status |
|------|--------|--------|
| Userspace TCP stack | T4; re-deferred at T6, T9b, T10a (the roadmap's own count reaches "fourth" by T10a) | Open — T31; **trigger formally met** ("mutate TCP state itself and continue the exchange"); reuse-first (smoltcp) behind the frozen `Driver` contract |
| Cross-stack differential targets | T6 | Closed by T12 (`diff`) |
| TLS-wrapped app probes | T9b | Closed by T13b |
| v6 app-layer fuzz targets | T9b | Closed by T10a |
| `--tls-insecure`/`--tls-ca` without `--tls` | T13b | Won't-do (inert, not errors) |

## Platform & process

| Item | Origin | Status |
|------|--------|--------|
| Dynamic `.so` plugin loading; dissect-only profiles | ADR 1 | Won't-do (compile-time registry, resolved) |
| macOS/BSD/Windows support | Hardening pass 2 | Won't-do (owner decision; non-Linux builds fail loudly at the libc FFI boundary) |
