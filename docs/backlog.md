# wrex — Backlog

Candidate work **not chartered in any planned tranche**. Semantics:
unlike the [deferral ledger](deferred.md) (items that were in scope
and consciously deferred, with owners and triggers), these are ideas
that were never chartered. The backlog is mined when a new tranche is
chartered; it never obligates anything.

Priorities (P0–P3) follow the [roadmap extension](roadmap.md)
definitions: P1 = charter-worthy soon, P2 = charter when adjacent work
touches the area, P3 = parking lot. Recorded at the 2026-10-23
extension pass.

## Scan & discovery deep cuts

| Item | P | Notes |
|------|---|-------|
| Service/version probe engine v1 (banner grab + committed probe table + match DSL) | P1 | **Absorbed into T21c** (delivered 2026-10-30): `scan --service`, NULL/HTTPGet probes, regex match DSL |
| Scan report extras (`--reason`, `--stats-every`, summary tables) | P2 | jsonl exists; presentation only |
| Window-scan inference (window-size ≠ 0 ⇒ open heuristic) | P2 | Heuristic must be flagged, never asserted |
| Decoy probes over raw TX | P2 | Probe identity stays wrex-derived |
| Spoofed-source raw scans | P3 | Reply matching breaks by design — document loudly if ever built |
| `-f` fragment-probe scan mode | P3 | |
| Idle/zombie scan (IPID side channel) | P3 | Needs an IPID-observable accomplice host |

## Protocol packs

| Item | P | Notes |
|------|---|-------|
| App pack A: RADIUS, CoAP, MQTT | P2 | Small codecs, high lab value; each follows the tranche-1 contract + HP3 doctrine gates |
| SCTP dissect-only (INIT/DATA/HEARTBEAT chunks) | P2 | |
| 802.11 management frames dissect-only (linktype 105) | P2 | **Scope decision pending at T23 planning** (recommended: dissect-only; monitor-mode injection out) |
| Teredo / Geneve dissect | P2 | Ride T28's encapsulation engine if chartered there |
| App pack B: SNMP BER subset, SIP dissect-only, RTP/RTCP, EAPOL/802.1X | P3 | |
| DCCP | P3 | |

## DNS extras

| Item | P | Notes |
|------|---|-------|
| AXFR/IXFR zone transfer over TCP | P2 | Multi-message reply session growth in `wrex-dns` |
| resolv.conf defaults + search list for `query` | P2 | Convenience defaults, not a resolver |
| DNSSEC display records (DS/DNSKEY/RRSIG dissection, DO-bit) | P3 | Validation crypto would be reuse-only (ADR 2) |
| DoQ (RFC 9250) | P2 | Rides T26's QUIC transport once chartered |

## Client & UX extras

| Item | P | Notes |
|------|---|-------|
| Hostname targets for scan/fuzz (resolve-then-probe) | P3 | Resolvers are someone else's job; convenience wrapper only |
| Per-protocol "show me the handshake" explainers (text-mode transcript annotation) | P3 | Dissections exist; presentation layer |

## Explicit non-goals (recorded so they are never re-litigated)

- **Non-Linux platforms** — out by owner decision (hardening pass 2).
- **Server roles for owned protocols** — probers and listeners only;
  no BGP speaker, no HTTP server, no RIB, no route selection.
- **TLS record-layer crypto, ESP plaintext, DHCPv6 auth** —
  delegated/never (ADR 2 + standing rules).
- **IDS/SIEM features** (rule engines, alerting) and **forensic mining
  at Zeek scale** — adjacent, not the mission.
- **Embedded scripting** (Lua/NSE-style) — the SDK, recipe JSON, and
  `converse` (T34) are the scripting answer.
- **GUI** — the CLI + jsonl contracts are the interface.
