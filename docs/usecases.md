# wrex — Use-case catalog

The **job view** of the project. The [roadmap](roadmap.md) is the
charter view (what gets built, in what order), the [deferral
ledger](deferred.md) is the liability view (what is consciously out of
scope) — this document records what a human actually sits down to *do*
with wrex, so that the machinery stays discoverable and every piece of
CLI sugar has a job to justify it.

- Every entry either documents a **working composition** (which keeps
  the docs honest — every `Today:` line is a command the golden
  workflow tests actually run) or records a **GAP**, and every GAP
  resolves to either thin sugar over existing machinery or a chartered
  tranche. Nothing else.
- Statuses: **WORKS** (documented composition), **SUGAR** (a thin door
  over delivered machinery is warranted), **GAP** (owner tranche).
- Every `WORKS` entry has a golden workflow test (`WF-n` runs
  `UC-n`'s incantation; see
  [verification.md](verification.md#executable-golden-workflows-hp3-c)).
- Recorded at the 2026-10-23 extension pass; grown by tranches (every
  new charter names the UCs it closes; a new UC needs a champion
  tranche or a recorded won't-do).

## Explore (nmap-adjacent)

| UC | The job | How today | Status |
|----|----------|-----------|--------|
| UC-1 | "Which hosts are alive on my L2 segment?" | — | **GAP → T21a** (`scan --mode arp`: the arp codec exists, the orchestration arm doesn't) |
| UC-2 | "What's listening on this host?" | `wrex scan -i eth0 --ports 22,80,443 192.168.1.10` | **WORKS** (WF-2) |
| UC-3 | "Is this port closed or filtered?" | UDP/ICMP attribution works; FIN/NULL/XMAS/ACK variants absent | **GAP → T21a** (`unfiltered` outcome state) |
| UC-4 | "What path does traffic take to X?" | — | **GAP → T21b** (`wrex trace`) |
| UC-5 | "What OS/vendor is this?" | — | **GAP → T30** (fingerprinting) |
| UC-6 | "What service *version* is behind this port?" | — | **GAP → backlog** (probe/match engine; candidate at T21 planning) |

## Inspect (tshark-adjacent)

| UC | The job | How today | Status |
|----|----------|-----------|--------|
| UC-7 | "Capture this interface, inspect later" | `wrex capture -i eth0 -w cap.pcap` then `wrex replay cap.pcap --format jsonl` | **WORKS** (WF-7) |
| UC-8 | "Find the TCP conversation in this capture" | — | **GAP → T24a** (stream follow) |
| UC-9 | "Give me an endpoints/conversations overview" | — | **GAP → T24b** (`wrex stats`) |
| UC-10 | "Show vendor names for MACs, service names for ports" | — | **GAP → T24b** (name tables) |
| UC-11 | "Does my weird capture file parse?" | `wrex replay foreign.pcapng --format jsonl` (all four classic magics + pcapng LE/BE µs/ns) | **WORKS** (WF-11; foreign fixtures pin interop) |
| UC-12 | "Reassemble fragments in a capture" | `wrex replay cap.pcap --reassemble` | **WORKS** (WF-12) |
| UC-13 | "Extract the files from this HTTP capture" | — | **GAP → T24b** (export objects) |

## Craft & surgery (scapy-adjacent)

The deepest machinery in the project; historically the least
documented as workflows. Every entry below is available today.

| UC | The job | How today | Status |
|----|----------|-----------|--------|
| UC-14 | "Build an exact frame by hand" | `wrex fields tcp` to discover, then `wrex craft --layer eth --layer ipv4 --layer tcp … \| wrex send -i eth0` | **WORKS** (WF-14) |
| UC-15 | "Rewrite a captured stream onto new IPs/ports, replay it" | `wrex patch -r cap.pcap --filter 'tcp.dport=80' --set tcp.dport=8080 -w edited.pcap` → `wrex replay -i eth0 edited.pcap` → `wrex diff` findings | **WORKS** (WF-15; the T14 end-to-end story) |
| UC-16 | "Fix/normalize a broken capture" | `wrex patch -r cap.pcap -w fixed.pcap` (zero edits + default scope *is* the normalize verb) | **WORKS** (WF-16) |
| UC-17 | "Send deliberately-stale checksums to test device strictness" | `wrex patch --set tcp.window=512 --no-recompute frame.hex` | **WORKS** (WF-17) |
| UC-18 | "Show where this field physically lives in the bytes" | `wrex dissect --spans --format json < frame.bin` | **WORKS** (WF-18) |
| UC-19 | "Edit a shared DNS pointer-target / padded DHCP sname" | `wrex patch --set 'an.0.name=wire:…'` (ReEncode regions; every alias through a pointer sees the change) | **WORKS** (WF-19) |

## Fuzz & QA

| UC | The job | How today | Status |
|----|----------|-----------|--------|
| UC-20 | "Mutate this seed offline, deterministically" | `wrex mut --count 8 --seed 42 < frame.hex` | **WORKS** (WF-20) |
| UC-21 | "Probe a service with mutated frames, record every outcome" | `wrex fuzz -i lo --baseline --rounds 4 --format jsonl 127.0.0.1` | **WORKS** (WF-21) |
| UC-22 | "Diff two probe runs" | `wrex diff baseline.jsonl mutated.jsonl` | **WORKS** (WF-22) |
| UC-23 | "Fuzz a TLS-wrapped service" | `wrex fuzz --mode http --tls --rounds 4 --format jsonl HOST` | **WORKS** (WF-23) |
| UC-24 | "Use my own production capture as the probe corpus" | `wrex mut -r prod.pcap --strategy all --count 500 --seed 7 -w probes.pcap` → `wrex replay -i eth0 probes.pcap` | **WORKS** (WF-24; the [oracle-capture](verification.md#oracle-captured-corpora-hp3-b) scenarios enrich fuzz seed corpora from real traffic) |

## Client verbs (curl/dig-adjacent)

| UC | The job | How today | Status |
|----|----------|-----------|--------|
| UC-25 | "Reproduce an API exchange byte-exactly in CI" | `wrex http --recipe req.json --format json` (deterministic recipe JSON; byte-identical replay) | **WORKS** (WF-25) |
| UC-26 | "Follow a redirect chain" | `wrex http -L --format json http://…/start` (RFC 9110 §15.4 method rules; same-origin hops ride one connection; the chain reports in json) | **WORKS** (WF-26) |
| UC-27 | "Maintain a cookie-authenticated session" | `wrex http -c jar.txt http://…/login` then `wrex http -b jar.txt http://…/echo` (RFC 6265 jar; the jar owns the Cookie header) | **WORKS** (WF-27) |
| UC-28 | "Debug DNS the way real resolvers speak it (EDNS/DO)" | `wrex query --server 192.168.1.1 --edns 1232 --edns-do --type HTTPS example.com` (the OPT record renders typed: `dns.ar.0.udp_size`, `.do`, TLVs `dns.ar.0.opt.M.*`) | **WORKS** (WF-28) |
| UC-29 | "Resolve a .local name" | `wrex query --mdns --type PTR _services._dns-sd._udp.local` (multicast 224.0.0.251:5353; udp dispatches 5353→dns) | **WORKS** (WF-29) |
| UC-30 | "Get out via DoH" | `wrex query --doh https://dns.example/dns-query --short example.com` (RFC 8484 POST, `application/dns-message`) | **WORKS** (WF-30) |

## Lab

| UC | The job | How today | Status |
|----|----------|-----------|--------|
| UC-31 | "Stand up a responder so I can test my client" | — | **GAP → T33** (`wrex listen`) |
| UC-32 | "Test client reactions to rogue RA/DHCP" | — | **GAP → T33** |
| UC-33 | "Script a deterministic multi-step conversation with expect rules" | — | **GAP → T34** (`wrex converse`) |

## The sugar rule

House rule: composition over composite verbs (the recorded T14
decision — `patch` deliberately has no `--send`). The catalog supplies
the principled exception test: sugar a composition when it **recurs
across catalog entries** (frequency) or is **error-prone to type**
(fragility). Current sugar candidates: a `--diff-baseline` shortcut on
`fuzz` (UC-21/22 co-occur in every fuzzing job); everything else stays
a documented pipeline until frequency proves otherwise.

## User-defined use-cases

Recipes are the mechanism for users to codify their own UCs without a
scripting language — `http --recipe` already is one; the recorded
T14 "JSON edit-list files" deferral makes `patch` recipes the same,
and `converse` (T34) generalizes it to multi-step exchanges. Every
recipe stays deterministic and seedable (the house style).

## Growth rules

1. Every tranche charter names the UCs it closes or advances.
2. A new UC enters with a champion tranche or a recorded won't-do.
3. The catalog is the cookbook TOC for the 1.0 docs story (T38).
4. Entries are re-verified by their golden workflow tests — a `Today:`
   line that stops working fails CI, so the catalog cannot rot.
