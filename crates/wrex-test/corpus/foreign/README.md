# Foreign pcap fixtures (pass-2 data compatibility)

Real captures written by OTHER tools (not `wrex capture`), pinned so
the in-house reader stays wire-compatible with the outside world:

- `classic_le.pcap` — classic pcap, little-endian microsecond
  (text2pcap → editcap, Wireshark 4.7.4)
- `classic_be.pcap` — byte-swapped variant (big-endian microsecond)
- `classic_le_ns.pcap` — nanosecond magic patch of the LE file
- `classic_be_ns.pcap` — byte-swapped ns variant
- `pcapng_le.pcapng` — pcapng (text2pcap 4.7.4 default: one SHB +
  one IDB + EPBs)

Frames: the udp/tcp/icmpv6 corpus frame 0s (see
`crates/wrex/tests/foreign_pcap.rs`). Regenerate with
`fuzz/dict/wrex.dict`… no — with `text2pcap -l 1` over the corpus
hexdump, then `editcap -F pcap` and the byte-swap script in the test
history.
