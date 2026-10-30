//! clap definitions. The craft/send field flags (`--<kind>-<field>`) are
//! real clap args, built at startup from the registry schemas — one
//! source of truth for the grammar, the help text, the completions and
//! the man pages. Standard options and field flags interleave freely.

use clap::{ArgAction, Args, Command, CommandFactory, Parser, Subcommand};
use wrex_core::{FieldKind, Registry};

/// Root epilog: the cross-cutting grammars (kinds, values, filters, exit
/// codes) a user needs before picking a verb. Per-verb flags and examples
/// live on the verbs (`wrex <verb> --help`).
pub const ROOT_AFTER_HELP: &str = "\
FIELD FLAGS:
  craft and send take per-layer field flags, listed in their --help
  (e.g. --eth-dst, --ipv4-ttl, --tcp-flags-syn, --icmp-echo-id); dots in
  field paths become dashes in flags. Standard options and field flags
  interleave freely.
  Every settable field, type, default and bit name: wrex fields [KIND].

LAYER KINDS:
  eth, arp, vlan, ipv4 (CLI alias: ip), ipv6 (CLI aliases: ip6, v6),
  icmp, icmpv6, udp, tcp, dns, dhcp.
  Ranks: eth 10; vlan 15; arp/ipv4/ipv6 20; icmp/icmpv6/udp/tcp 30
  (stack on ipv4|ipv6); dns 40 (port-53 datagrams dissect into it);
  dhcp 40 (port-67/68 datagrams dissect into it).
  Man pages: wrex(1), wrex-<kind>(7) in man/ of the source checkout.

VALUE GRAMMAR:
  ints       63 | 0x3f | 0b111111 | 0o77 (range-checked per field)
  ipv4       127.0.0.1            ipv6    ::1 | 2001:db8::1
  mac        aa:bb:cc:dd:ee:ff
  bytes      hex:DEADBEEF | text:... | @FILE | @- (stdin) | repeat:8x00
  flagsets   syn,ack | syn+ack | 0x02    bool  true | false | 1 | 0
  durations  (--count/--interval/--timeout)  500ms | 2s | 1m (bare: seconds)

FILTERS (recv --filter, send --wait-reply, patch --filter):
  space-separated AND-terms: path OP value, OP in = != < <= > >=
  ipv4 = accepts CIDR (10.0.0.0/8); flagset = accepts bit names;
  bytes = is a hex-prefix match; a path absent from a frame is false

EXIT CODES:
  0  success (recv timeout end included)
  1  runtime/data outcomes: driver errors, wait-reply timeout,
     dissect --strict anomalies, unknown iface name
  2  malformed request: usage errors, bad specs/filters,
     craft/send --strict validation failures";

/// Epilog shared by craft and send: the semantics the per-flag help
/// cannot carry (implied layers, explicit-wins, --strict).
pub const CRAFT_SEND_AFTER_HELP: &str = "\
LAYER ORDER:
  --layer KIND declares encapsulation order (repeatable). Without it,
  layers are implied by the field flags present, ordered by rank;
  a sibling conflict (two rank-30 kinds, or arp+ipv4) errors with a
  hint to pass --layer. Field flags for a kind you did not declare
  require --layer KIND.

SEMANTICS:
  Explicit values always win over autofill and are kept unvalidated;
  --strict re-validates the crafted packet (violations exit 2).
  Every settable field, type, default and bit name: wrex fields [KIND].

EXAMPLES:
  # 46-byte golden frame; autofill derives eth.type, ipv4.total_len,
  # ipv4.checksum, udp.length and udp.checksum from the packet
  wrex craft --format hex --layer eth --layer ipv4 --layer udp \\
    --eth-dst=ff:ff:ff:ff:ff:ff --ipv4-src=127.0.0.1 --ipv4-dst=127.0.0.1 \\
    --udp-sport=4444 --udp-dport=5555 --payload=hex:deadbeef

  # implied mode: the same bytes without --layer (layers come from flags)
  wrex craft --format hex \\
    --eth-dst=ff:ff:ff:ff:ff:ff --ipv4-src=127.0.0.1 --ipv4-dst=127.0.0.1 \\
    --udp-sport=4444 --udp-dport=5555 --payload=hex:deadbeef

  # send on an interface (needs CAP_NET_RAW; send stacks start with eth)
  wrex send -i lo --layer eth --layer ipv4 --layer udp \\
    --ipv4-src=127.0.0.1 --ipv4-dst=127.0.0.1 \\
    --udp-sport=1 --udp-dport=2 --payload=hex:aa

  # no field flags + piped stdin: raw stdin bytes are sent as-is";

/// Epilog for dissect: formats, the span taxonomy, the retained frame
/// and the never-fatal contract.
pub const DISSECT_AFTER_HELP: &str = "\
FORMATS:
  raw   input bytes echoed out (byte-transparent pipelines)
  hex   lowercase hex + newline
  text  indented field tree, '! path: message' anomaly lines and a
        trailing payload hexdump (default)
  json / jsonl  {\"start\":..,\"layers\":[..],\"payload_hex\":..,\"anomalies\":[..]}

SPANS (--spans, tranche 11b):
  emits the field-span taxonomy alongside the fields: per layer a
  `spans` map (path -> geometry: bytes / bits{shift,width} / reencode /
  none — absolute frame offsets) and a `payload_span`; text adds a
  `spans:` section per layer and a payload span line. Total presence:
  every dissected field key resolves (the `none` variant carries the
  unpatchable policy — pointer-resolved names, dynamic regions).

FRAME (--frame, tranche 14):
  the retained input frame as hex — json/jsonl gain a top-level
  `frame` key, text a `frame (N bytes): <hex>` line after the payload
  section. The input bytes verbatim (the tranche-11a retention);
  default output stays byte-identical. raw/hex already echo them.

EXAMPLES:
  wrex craft --format raw --layer eth ... | wrex dissect --format json
  wrex dissect --start eth < frame.bin
  wrex dissect --spans --format json < frame.bin   # span taxonomy
  wrex patch --format raw --set ipv4.ttl=7 FRAME | wrex dissect --frame
  # --strict exits 1 when dissection finds anomalies (data failed checks)";

/// Epilog for recv: formats, filters and stop conditions.
pub const RECV_AFTER_HELP: &str = "\
FORMATS:
  jsonl  one DissectedPacket per line (default)
  raw    matching frame bytes concatenated
  text / json / hex as elsewhere

FILTERS:
  --filter 'path OP value' — space-separated AND-terms,
  OP in = != < <= > >=; ipv4 = accepts CIDR (10.0.0.0/8);
  flagset = accepts bit names (syn,ack); bytes = is a hex prefix.

NOTES:
  stops at --count matching frames or after --timeout (exit 0);
  --promisc opts into promiscuous mode. Needs CAP_NET_RAW.";

/// Epilog for http: the HTTP/1.1 ask verb (tranche 4; https at 8a;
/// keep-alive queues + chunked request bodies at 9a).
pub const HTTP_AFTER_HELP: &str = "\
HTTP GRAMMAR:
  wrex http [METHOD] URL [URL...] [-H NAME:VALUE]... [--data TEXT|@FILE|hex:…]
           [--timeout DUR] [--retries N] [--max-bytes N]
           [--source-port N] [--fail] [--recipe FILE]
           [--tls-insecure] [--tls-ca FILE]
           [--format text|json|raw]

  One URL (or a lone --recipe object) is the tranche-4 close mode:
  one exchange per connection (Connection: close). Multiple URLs
  (or a recipe array / {\"requests\": [...]} file) ride ONE
  keep-alive connection in order — every request but the last
  carries Connection: keep-alive; a response that says close (or
  HTTP/1.0, or read-to-close framing) ends the queue there.

  Requests are fully materialized first, so the same arguments (or
  the same --recipe FILE) replay byte-identical wire bytes. Host,
  User-Agent, Accept and Content-Length derive automatically with
  explicit-wins semantics (user headers come first, in order);
  -H/--data apply to every URL of a multi-URL run.

  Bodies: content-length and chunked (trailers merge into headers),
  read-to-close when neither is declared; recipe body_framing
  \"chunked\" switches the REQUEST to fixed-size chunks (chunk_size,
  default 4096 — deterministic). 1xx skipped; HEAD/204/304 carry no
  body. https:// rides TLS (the rustls engine behind the wrex-tls
  driver adapter): SNI from the URL host, system roots plus optional
  --tls-ca FILE additions (PEM or DER); --tls-insecure accepts ANY
  certificate (dangerous: no name/chain/validity check — for lab
  targets).

  Any completed run is exit 0 whatever the statuses say; --fail
  turns any 4xx/5xx into exit 1 (after printing); connect/timeout/
  protocol failures are exit 1; grammar and recipe errors are exit 2.

RECIPE (--recipe FILE, JSON):
  {\"method\": \"POST\", \"url\": \"https://host/api\",
   \"headers\": [[\"X-A\", \"1\"]], \"body_hex\": \"deadbeef\",
   \"body_framing\": \"chunked\", \"chunk_size\": 4096,
   \"timeout_ms\": 1500, \"retries\": 1, \"max_bytes\": 67108864,
   \"tls_insecure\": false, \"tls_ca\": \"ca.pem\"}
  A queue is a top-level array of such objects or
  {\"requests\": [obj, obj, …]} (one keep-alive connection, in
  order). Ordered header pairs keep wire bytes deterministic;
  body_hex and body_text are mutually exclusive. tls_insecure/tls_ca
  are additive (defaults: off/absent) and honored for https urls.

EXAMPLES:
  wrex http http://example.com/
  wrex http POST http://example.com/api -H X-Thing:42 --data '{\"a\":1}'
  wrex http http://example.com/a http://example.com/b   # one connection
  wrex http --recipe req.json --format json
  wrex http https://example.com/ --tls-insecure
  wrex http https://example.com/ --tls-ca myca.pem
  wrex http GET http://example.com/ --data @body.bin --source-port 42424";

/// Epilog for scan: modes, grammar, pacing and the seeded RNG.
pub const SCAN_AFTER_HELP: &str = "\
TARGETS:
  repeatable positional: IPv4/IPv6 addresses, CIDR
  (10.0.0.0/24; v4 network and broadcast skipped below /31,
  2001:db8::/64), or inclusive ranges (10.0.0.1-10.0.0.9; tails
  allowed on v4: 10.0.0.0-0.255). One family per scan (v6 targets
  switch the probes to ipv6/icmpv6 framing; mixed lists error).

MODES (--mode):
  syn      TCP SYN scan (default): SYN+ACK -> open (RST sent to kill
           the half-open), RST -> closed, silence -> filtered
  connect  full handshake: ACK then RST after SYN+ACK -> open
  udp      empty datagrams: UDP reply -> open, ICMP 3/3 -> closed,
           ICMP 3/{1,2,9,10,13} -> filtered, silence -> open|filtered
           (v6 targets: ICMPv6 1/4 -> closed — the RFC 4443 §3.1 port-
           unreachable code — and 1/{0,1,2,3,5,6,7} -> filtered)
  icmp     echo sweep (no ports): reply -> alive, silence -> dead
           (v6 targets speak icmpv6 echo, type 128/129)

PORTS (--ports):
  comma list with ranges (22,80,100-200). syn/connect default to a
  committed top-100 TCP list (see wrex fields / the man page);
  udp REQUIRES --ports; icmp takes none.

TIMING:
  --rate N        packets/sec (0 = uncapped burst)
  --interval DUR  explicit pacing (e.g. 200ms); overrides --rate
  (no pacing flags: uncapped burst, bounded by --concurrent — nmap's
   parallelism model; the seeded --rate/--interval/--jitter are the
   opt-in politeness knobs)
  --jitter DUR    seeded +/- jitter on the pacing step
  --seed U64      pins the RNG (default: time-derived): probe source
                  ports, tcp seqs, icmp ids and the jitter schedule
                  are bit-reproducible under a pinned seed
  --timeout DUR   per-attempt reply timeout (default 1s)
  --retries N     extra attempts per probe (default 1)
  --concurrent N  max in-flight probes (default 256)

PROBES:
  Datagrams injected kernel-routed (raw-IP socket for v4, AF_PACKET
  0x86dd frames for v6; needs CAP_NET_RAW); replies are captured on
  -i IFACE. Results stream as they resolve (--format text|json|jsonl).

EXAMPLES:
  # default TCP scan of one host (top-100 ports)
  wrex scan -i eth0 192.168.1.10

  # explicit ports, syn scan of a /24, 500 packets/sec
  wrex scan -i eth0 --ports 22,80,443,8000-8100 --rate 500 192.168.0.0/24

  # host sweep: which of 10.0.0.1-99 answers pings
  wrex scan -i eth0 --mode icmp 10.0.0.1-10.0.0.99

  # reproducible UDP scan (pinned seed)
  wrex scan -i eth0 --mode udp --ports 53,161 --seed 42 10.0.0.5";

#[derive(Parser)]
#[command(
    name = "wrex",
    version,
    about = "wrex — wire experiments toolkit: craft, send, capture, dissect",
    after_help = ROOT_AFTER_HELP
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Cmd,
}

impl Cli {
    /// Verbosity of the active subcommand (tracing init).
    pub fn verbose_level(&self) -> u8 {
        match &self.cmd {
            Cmd::Craft(a) => a.common.verbose,
            Cmd::Dissect(a) => a.common.verbose,
            Cmd::Send(a) => a.common.verbose,
            Cmd::Recv(a) => a.common.verbose,
            Cmd::Capture(a) => a.common.verbose,
            Cmd::Replay(a) => a.common.verbose,
            Cmd::Scan(a) => a.common.verbose,
            Cmd::Mut(a) => a.common.verbose,
            Cmd::Patch(a) => a.common.verbose,
            Cmd::Fuzz(a) => a.common.verbose,
            Cmd::Http(a) => a.common.verbose,
            Cmd::Query(a) => a.common.verbose,
            Cmd::Diff(a) => a.common.verbose,
            Cmd::Iface(a) => a.common.verbose,
            Cmd::Fields(a) => a.common.verbose,
            Cmd::Completions(_) => 0,
        }
    }
}

/// Options shared by the verbs.
#[derive(Args, Debug)]
pub struct Common {
    /// Interface for send/recv.
    #[arg(short = 'i', long)]
    pub iface: Option<String>,

    /// Output format: raw|hex|text|json|jsonl.
    #[arg(long)]
    pub format: Option<String>,

    /// Verbosity (repeatable: -v info, -vv debug, -vvv trace).
    #[arg(short = 'v', action = ArgAction::Count)]
    pub verbose: u8,

    /// Disable every autofill/derivation (unspecified numeric fields → 0).
    #[arg(long)]
    pub no_autofill: bool,

    /// Validate the crafted packet after encode (violations → exit 2).
    #[arg(long)]
    pub strict: bool,
}

impl Common {
    #[allow(dead_code)]
    pub fn verbose(&self) -> u8 {
        self.verbose
    }
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Encode a PacketSpec from field flags → stdout.
    Craft(CraftArgs),

    /// Print shell completions to stdout (bash|zsh|fish|elvish|powershell).
    Completions(CompletionsArgs),

    /// stdin → DissectedPacket → stdout (never fatal).
    Dissect(DissectArgs),

    /// Send a crafted frame (or raw stdin bytes) on an interface.
    Send(SendArgs),

    /// Receive frames on an interface, filtered, until count/timeout/Ctrl-C.
    Recv(RecvArgs),

    /// Capture frames from an interface into a pcap file (classic or,
    /// with `--pcapng`, pcapng).
    Capture(CaptureArgs),

    /// Read a pcap (dissect to stdout) or re-send it on an interface.
    Replay(ReplayArgs),

    /// Scan targets (TCP SYN/connect, UDP, ICMP) and classify ports/hosts.
    Scan(ScanArgs),

    /// Mutate seed frames (dissect-aware, seeded) → stdout / pcap.
    Mut(MutArgs),

    /// Deterministic surgical edits of real frames (span-patch engine)
    /// → stdout / pcap.
    Patch(PatchArgs),

    /// Probe targets with mutated packets; record replies as findings.
    Fuzz(FuzzArgs),

    /// HTTP/1.1 exchanges: send request(s), dissect the responses.
    Http(Box<HttpArgs>),

    /// Ask a DNS server one question (kernel UDP/TCP/TLS) and dissect the reply.
    Query(QueryArgs),

    /// Diff two findings JSONL files (offline, exit 0).
    Diff(DiffArgs),

    /// Interface table: name, mac, ipv4s, mtu, up.
    Iface(IfaceArgs),

    /// Registry introspection: every settable field.
    Fields(FieldsArgs),
}

/// The craft/send grammar args: `--layer`, `--payload`, and one arg per
/// registered field path (`--<kind>-<path>`, dots as dashes, `ip` aliases
/// for `ipv4`, per-bit subpaths as boolean flags).
///
/// Built from the registry at startup: a new protocol crate needs no CLI
/// change, and the help text, completions and man pages enumerate its
/// flags automatically.
pub fn field_args(registry: &Registry) -> Vec<clap::Arg> {
    let mut args = vec![
        clap::Arg::new("layer")
            .long("layer")
            .value_name("KIND")
            .action(ArgAction::Append)
            .help("declare encapsulation order (repeatable)"),
        clap::Arg::new("payload")
            .long("payload")
            .value_name("VALUE")
            .help("terminal payload bytes (hex:…, text:…, @FILE, @-, repeat:NxHEX)"),
    ];
    let mut used_longs: std::collections::HashSet<String> = Default::default();
    for &kind in registry.kinds() {
        let schema = registry.schema(kind).expect("registered kind");
        for field in schema.fields {
            let long = flag_long(kind, field.name);
            let mut arg = clap::Arg::new(long.clone())
                .long(long.clone())
                .help(field.doc)
                .value_name(value_hint(field.kind))
                .num_args(1);
            // CLI-only kind aliases (pinned): `ip` → `ipv4`,
            // `ip6`/`v6` → `ipv6`.
            if kind == "ipv4" {
                arg = arg.alias(format!("ip-{}", dashed(field.name)));
            }
            if kind == "ipv6" {
                arg = arg.alias(format!("ip6-{}", dashed(field.name)));
                arg = arg.alias(format!("v6-{}", dashed(field.name)));
            }
            args.push(arg);
            used_longs.insert(long.clone());
            if field.kind == FieldKind::FlagSet {
                for &bit in field.bit_names {
                    let blong = flag_long(kind, &format!("{}.{}", field.name, bit));
                    args.push(
                        clap::Arg::new(blong.clone())
                            .long(blong.clone())
                            .action(ArgAction::SetTrue)
                            .help(format!(
                                "set only the {bit} bit of {kind}.{} (aggregate: --{long})",
                                field.name
                            )),
                    );
                    used_longs.insert(blong);
                }
            }
        }
        // Record-section flags: a settable record bounded at max 1 gets
        // an unindexed shorthand (`--dns-name` → `qd.0.name`); a
        // settable unbounded record (tranche 20a-2: dns `an`/`ns`/`ar`)
        // enumerates its index-0 paths (`--dns-an-0-name`) — deeper
        // indices ride the spec JSON, not flags. The arg id stays the
        // full dashed path so spec assembly is unambiguous. Dissect-only
        // records take no flags.
        for record in schema.records {
            if !record.settable {
                continue;
            }
            let shorthand = record.max == Some(1);
            for field in record.fields {
                let arg_id = flag_long(kind, &format!("{}.0.{}", record.name, field.name));
                let short = format!("{kind}-{}", field.name);
                let long = if !shorthand {
                    // Unbounded: the indexed full path only.
                    used_longs.insert(arg_id.clone());
                    arg_id.clone()
                } else if used_longs.insert(short.clone()) {
                    short
                } else {
                    // flat field or earlier shorthand already owns the
                    // short spelling: fall back to the indexed form.
                    used_longs.insert(arg_id.clone());
                    arg_id.clone()
                };
                args.push(
                    clap::Arg::new(arg_id)
                        .long(long.clone())
                        .help(field.doc)
                        .value_name(value_hint(field.kind))
                        .num_args(1),
                );
            }
        }
    }
    args
}

/// `--<kind>-<path>` long-flag spelling: dots become dashes.
fn flag_long(kind: &str, path: &str) -> String {
    format!("{kind}-{}", dashed(path))
}

fn dashed(path: &str) -> String {
    path.replace('.', "-")
}

/// Value placeholder per field kind (help rendering).
fn value_hint(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::U8 | FieldKind::U16 | FieldKind::U32 | FieldKind::U64 | FieldKind::U128 => "INT",
        FieldKind::Ipv4 => "IP",
        FieldKind::Ipv6 => "IPV6",
        FieldKind::Mac => "MAC",
        FieldKind::Bytes | FieldKind::ByteList => "BYTES",
        FieldKind::FlagSet => "BITS",
        FieldKind::Str => "STRING",
    }
}

/// The full command: derive skeleton plus the dynamic craft/send field
/// args. One builder for parsing, `--help`, completions and man pages.
pub fn build_cli() -> Command {
    let registry = crate::standard();
    let field_args = field_args(&registry);
    let mut cmd = Cli::command();
    // Thread the field args into craft/send. clap's `args()` builder
    // consumes `Command`, so clone-write through the &mut (order kept).
    for sub in cmd.get_subcommands_mut() {
        let is_grammar = matches!(sub.get_name(), "craft" | "send");
        if is_grammar {
            *sub = sub.clone().args(field_args.clone());
        }
    }
    cmd
}

#[derive(Args, Debug)]
#[command(after_help = CRAFT_SEND_AFTER_HELP)]
pub struct CraftArgs {
    #[command(flatten)]
    pub common: Common,
}

#[derive(Args, Debug)]
#[command(after_help = DISSECT_AFTER_HELP)]
pub struct DissectArgs {
    #[command(flatten)]
    pub common: Common,
    /// Dissection start: auto|eth|ipv4|… (default auto).
    #[arg(long)]
    pub start: Option<String>,
    /// Emit the field-span taxonomy (tranche 11b): per-layer `spans`
    /// maps plus the payload span, json/jsonl and text.
    #[arg(long)]
    pub spans: bool,
    /// Emit the retained input frame as hex (tranche 14): a top-level
    /// `frame` key in json/jsonl, a `frame (N bytes):` line in text.
    #[arg(long)]
    pub frame: bool,
}

#[derive(Args, Debug)]
#[command(after_help = CRAFT_SEND_AFTER_HELP)]
pub struct SendArgs {
    #[command(flatten)]
    pub common: Common,
    /// Send count (default 1).
    #[arg(long)]
    pub count: Option<u64>,
    /// Pacing between sends (e.g. 200ms); without it: burst.
    #[arg(long)]
    pub interval: Option<String>,
    /// Wait-reply timeout (default 2s).
    #[arg(long)]
    pub timeout: Option<String>,
    /// Wait for the first reply frame on the iface, dissect to stdout.
    #[arg(long)]
    pub wait_reply: bool,
    /// Filter for --wait-reply matches (same engine as recv).
    #[arg(long)]
    pub filter: Option<String>,
}

#[derive(Args, Debug)]
#[command(after_help = RECV_AFTER_HELP)]
pub struct RecvArgs {
    #[command(flatten)]
    pub common: Common,
    /// Stop after N matching frames.
    #[arg(long)]
    pub count: Option<u64>,
    /// Stop after this duration (exit 0).
    #[arg(long)]
    pub timeout: Option<String>,
    /// Filter expression (space-separated AND-terms: path<op>value).
    #[arg(long)]
    pub filter: Option<String>,
    /// Promiscuous mode (opt-in).
    #[arg(long)]
    pub promisc: bool,
}

/// Epilog for capture: the tranche-5 pcap tap (tranche 8b: --pcapng).
pub const CAPTURE_AFTER_HELP: &str = "\
GRAMMAR:
  wrex capture -i IFACE -w FILE.pcap [options]

  AF_PACKET receive loop (like recv) into a pcap file: classic pcap
  (little-endian microsecond, link type EN10MB) by default, or pcapng
  with --pcapng (little-endian, one EN10MB interface, EPB records;
  in-house writers, no libpcap). Frames pass --filter before they
  are written; --snaplen truncates the stored copy (orig_len keeps
  the wire length).

FORMATS (optional tee):
  without --format: pcap file only (nothing on stdout)
  with --format:    the same per-frame output as recv (default jsonl)
  on stdout WHILE the records land in the file

NOTES:
  stops at --count written frames or after --timeout (exit 0);
  --promisc opts into promiscuous mode. Needs CAP_NET_RAW.";

/// Epilog for replay: offline dissection or wire re-send.
pub const REPLAY_AFTER_HELP: &str = "\
GRAMMAR:
  wrex replay FILE.pcap [--filter EXPR] [--count N] [--format FMT]
  wrex replay FILE.pcap -i IFACE [--rate N|--interval DUR] [--jitter DUR]
                        [--seed U64]

  Offline (default): dissect each captured frame and print it —
  the same --format family as recv (default jsonl), --filter and
  --count apply. No raw sockets.

SEND MODE (-i/--iface): re-send the captured frames verbatim on the
  interface (AF_PACKET; needs CAP_NET_RAW). Pacing:
    default          original capture-delta (sleeps between frames)
    --rate N         fixed N frames/sec (0 = uncapped burst)
    --interval DUR   explicit pacing (overrides --rate)
    --jitter DUR     seeded +/- jitter on the pacing step
    --seed U64       pins the jitter schedule (default: time-derived)
  --rate/--interval are mutually exclusive; --jitter needs --seed or
  settles on the time-derived seed.

PCAP:
  classic files (all 4 magic variants) or pcapng (LE/BE x µs/ns) —
  the shared in-house reader auto-detects the format. Write out with
  `wrex capture [--pcapng]`, text2pcap or mergecap if needed.";

/// `wrex capture`: AF_PACKET recv loop into a pcap file (classic or,
/// with `--pcapng`, pcapng).
#[derive(Args, Debug)]
#[command(after_help = CAPTURE_AFTER_HELP)]
pub struct CaptureArgs {
    #[command(flatten)]
    pub common: Common,
    /// Output pcap file (frames land here; --format tees to stdout).
    #[arg(short = 'w', long = "write", value_name = "FILE", required = true)]
    pub write: String,
    /// Stop after N written frames.
    #[arg(long)]
    pub count: Option<u64>,
    /// Stop after this duration (exit 0).
    #[arg(long)]
    pub timeout: Option<String>,
    /// Filter expression (space-separated AND-terms: path<op>value).
    #[arg(long)]
    pub filter: Option<String>,
    /// Promiscuous mode (opt-in).
    #[arg(long)]
    pub promisc: bool,
    /// Max stored bytes per frame (default 65535; wire length kept).
    #[arg(long)]
    pub snaplen: Option<usize>,
    /// Write pcapng instead of classic pcap (SHB+IDB+EPB, LE).
    #[arg(long)]
    pub pcapng: bool,
    /// Write pcapng `if_tsresol` 9 (nanosecond EPB timestamps; the
    /// option-less IDB default stays microseconds) — tranche T18b.
    /// Usage error without `--pcapng`.
    #[arg(long, requires = "pcapng")]
    pub pcapng_ns: bool,
}

/// `wrex replay`: offline dissection or re-send of a pcap (classic or
/// pcapng).
#[derive(Args, Debug)]
#[command(after_help = REPLAY_AFTER_HELP)]
pub struct ReplayArgs {
    #[command(flatten)]
    pub common: Common,
    /// Pcap file to read (classic or pcapng; auto-detected).
    #[arg(value_name = "FILE")]
    pub pcap: String,
    /// Stop after N matching frames.
    #[arg(long)]
    pub count: Option<u64>,
    /// Filter expression (space-separated AND-terms: path<op>value).
    #[arg(long)]
    pub filter: Option<String>,
    /// Send rate in frames/sec (send mode only; 0 = uncapped burst).
    #[arg(long)]
    pub rate: Option<u64>,
    /// Pacing between sends (e.g. 200ms); overrides --rate.
    #[arg(long)]
    pub interval: Option<String>,
    /// Seeded jitter magnitude (+/-) on the pacing step.
    #[arg(long)]
    pub jitter: Option<String>,
    /// RNG seed (default: time-derived; pins the jitter schedule).
    #[arg(long)]
    pub seed: Option<u64>,
    /// Reassemble IP fragments (offline mode only, tranche T18a):
    /// complete datagrams are re-dissected and printed in stream
    /// order; non-fragment frames pass through; residual incomplete
    /// datagrams report as notes (data, exit 0).
    #[arg(long)]
    pub reassemble: bool,
}

/// Epilog for query: the DNS ask verb (tranche 3; DoT at 8a; v6 at 10a;
/// kernel sockets everywhere since perf-pass 3b).
pub const QUERY_AFTER_HELP: &str = "\
QUERY GRAMMAR:
  wrex query [--server IP] [--port 53] [--tcp] [--tls] [--doh URL]
             [--mdns] [--reverse] [--short] [--edns SIZE] [--edns-do]
             [--tls-insecure] [--tls-ca FILE] [options] NAME

  Sends one seeded DNS question and waits for the matching reply
  (the reply must echo the query's dns id; with --tcp: RFC 7766
  length-prefixed DNS over a fresh TCP connection per attempt).
  --retries re-sends the SAME query (same dns id) after --timeout.
  A reply received is a success (exit 0) whatever the rcode says —
  NXDOMAIN/SERVFAIL are data, printed in the dissected reply.

  Every transport rides a kernel socket — no -i, no capabilities
  (the raw-IP + AF_PACKET tap path was retired in perf-pass 3b:
  ~15-19ms of fixed cost per invocation, measured by `cargo xtask
  perf-diff` against dig). -i, when given, pins the source address
  on multihomed hosts; the seeded source port binds when free.

  --server accepts IPv4 or IPv6 (tranche 10a): a v6 server speaks
  over the v6 kernel socket on any transport.

  --tls is DNS-over-TLS (RFC 7858): implies the TCP transport (a
  fresh TLS connection per attempt), default server port 853, server
  name from --server. --tls-insecure accepts any server certificate
  and --tls-ca FILE adds extra roots, as with `wrex http`.

  --edns SIZE advertises EDNS0 (tranche 20a-1): one OPT pseudo-record
  lands in the reply's ar section, dissected typed (udp_size,
  ext_rcode, version, do, z, and option TLVs ar.N.opt.M.*).
  --edns-do sets the DO bit. --mdns (tranche 20b) asks the multicast
  group 224.0.0.251 / ff02::fb on port 5353 instead of a unicast
  server; -i pins the multicast interface (recommended — a default
  egress would strand the group datagram off-host). --doh URL (tranche 20b) POSTs the bare message as
  application/dns-message (RFC 8484; http/https URL, fresh connection
  per attempt — the h2 ALPN transport is a recorded deferral).
  --reverse is dig -x sugar (NAME is an IP; PTR under in-addr.arpa /
  ip6.arpa); --short prints only the answer rdata values (text).

RECORD FIELDS (wrex dissect --filter also accepts these):
  answers/authority/additional records dissect into indexed paths:
  dns.an.0.name, dns.an.0.type, dns.an.0.ttl, dns.an.0.rdata …
  A rdata is typed ipv4; CNAME/NS/PTR resolve (compression pointers
  included) to names; every common record type walks its typed
  subfields (tranche 20a-2): dns.an.0.mx.preference,
  dns.an.0.soa.serial, dns.an.0.svcb.M.key …; EDNS OPT renders
  dns.ar.N.udp_size / .do and its TLVs dns.ar.N.opt.M.*.

EXAMPLES:
  wrex query --server 192.168.1.1 example.com
  wrex query --server 1.1.1.1 --type MX --seed 42 example.com
  wrex query --server 1.1.1.1 --type HTTPS --edns 1232 --edns-do --short example.com
  wrex query --tcp --server 192.168.1.1 example.com
  wrex query --tls --server 192.168.1.1 --tls-insecure example.com
  wrex query --doh https://dns.example/dns-query --short example.com
  wrex query --mdns --type PTR _services._dns-sd._udp.local
  wrex query --reverse --server 192.168.1.1 192.168.1.10
  wrex query --server ::1 example.com";

/// Epilog for mut: the tranche-6a mutation verb.
pub const MUT_AFTER_HELP: &str = "\
GRAMMAR:
  wrex mut [FRAMES...] [-r FILE.pcap] [--strategy S] [--count N]
                 [--seed U64] [--format FMT] [-w FILE.pcap]

  Seeds: positional hex frames, -r/--read pcap records (classic,
  all 4 magic variants, or pcapng — auto-detected), and/or raw
  stdin. Mutants print per --format (default hex): hex/raw are the
  bytes; text/json/jsonl dissect the mutant. -w writes the mutants
  as a classic pcap (LE microsecond, EN10MB) — a mutated corpus
  `wrex replay` and `wrex fuzz` consume.

STRATEGIES (--strategy, default all):
  field   dissect the seed, mutate one typed field value, apply it as
          a span-patch edit under preserve semantics (nothing
          re-derives: untouched invalidities ride along unhealed)
  len     perturb a length field explicitly (preserve keeps it)
  flip    raw bit flip, biased toward header bytes
  splice  cross-over A[..k] + B[k..] of two seeds (needs >= 2)
  raw     byte surgery anywhere: flip/overwrite/insert/delete
  all     seeded weighted mix of the rest

DETERMINISM:
  --seed U64 pins the stream (default time-derived): the same seeds
  + seed yield byte-identical mutants, replayable anywhere.

EXAMPLES:
  wrex mut --format hex --seed 42 --count 8 45...1f
  wrex mut -r capture.pcap --strategy field --count 100 -w mut.pcap
  wrex craft --format raw --layer eth --layer ipv4 --layer udp \\
    --ipv4-dst=10.0.0.5 --udp-dport=53 | wrex mut --count 4";

/// Epilog for fuzz: the tranche-6b recording prober (+ 9b app modes).
pub const FUZZ_AFTER_HELP: &str = "\
GRAMMAR:
  wrex fuzz -i IFACE [--mode tcp|udp|icmp] [options] TARGET...
  wrex fuzz [--mode http|dns] [--ports N] [options] TARGET...

  For every (target, port) slot: an optional unmutated baseline probe
  (--baseline), then --rounds mutated probes (wrex-mut strategies).
  Probes inject via a raw-IP socket (kernel routes; needs
  CAP_NET_RAW), replies captured on -i. Every probe resolves to one
  recorded finding: a matching reply (reply bytes included), an
  ICMP-unreachable attribution, or silence after --retries.

MODES (--mode, default udp):
  tcp    SYN probes; any segment on the probe 4-tuple is a reply
  udp    empty datagrams; any datagram on the 4-tuple is a reply;
         ICMP 3/x unreachables attribute via the quoted datagram
  icmp   echo sweeps (no ports); type-0 replies with a matching id
  http   APPLICATION-LAYER (tranche 9b): one GET per probe over a
         fresh kernel TCP connection (no -i, no capabilities); the
         mutated REQUEST bytes are recorded with the response
  dns    application-layer DNS: one RFC 7766 length-prefixed query
         per probe over a fresh TCP connection (response recorded)

  Targets speak either family (tranche 10a): v6 targets ride the
  dual-family kernel driver for the app modes; the raw modes keep
  the scan's AF_PACKET/raw-IP inject paths.

TLS (--tls, tranche 13b; app modes http|dns only): wraps each probe
  connection in rustls (the T8a adapter; https for http, DoT/RFC 7858
  for dns; default ports become 443/853). --tls-ca FILE adds trust
  anchors that COMPLEMENT the system roots; --tls-insecure accepts any
  certificate (no verification at all). One fresh TLS connection per
  probe, retries repeat the exact mutated bytes on fresh connections;
  a connect or handshake failure spends the attempt as silence.

  Reply keys derive from the POST-mutation dissection: a mutation
  that moved the identity still matches its own replies.

PORTS (--ports): comma list with ranges. tcp defaults to the
  committed top-100 list (same as scan); udp REQUIRES --ports; icmp
  takes none; http defaults to 80 (443 under --tls); dns defaults to
  53 (853 under --tls).

TIMING (same vocabulary as scan): --rate N (0 = burst; no pacing
  flags = uncapped burst bounded by --concurrent), --interval DUR,
  --jitter DUR, --seed U64 (identities, mutation streams, jitter),
  --timeout DUR (default 1s), --retries N, --concurrent N
  (default 256; raw modes only).

FINDINGS: one line per probe — --format text (default), json (array)
  or jsonl; every finding carries the exact probe bytes (hex), so
  anything interesting replays with `wrex send`/`wrex replay`, and a
  baseline run diffs offline against the mutated rounds.

EXAMPLES:
  wrex fuzz -i lo --baseline --rounds 4 127.0.0.1
  wrex fuzz -i eth0 --mode udp --ports 53,161 --rounds 16 --seed 7 10.0.0.0/24
  wrex fuzz -i eth0 --mode tcp --ports 22,443 --strategy field 10.0.0.5
  wrex fuzz --mode http --baseline --rounds 4 127.0.0.1   # app layer
  wrex fuzz --mode dns --ports 5353 --rounds 8 127.0.0.1
  wrex fuzz --mode http --tls --tls-insecure --baseline --rounds 4 127.0.0.1";

/// Epilog for patch: the tranche-14 span-patch verb — deterministic
/// surgical edits of real frames.
pub const PATCH_AFTER_HELP: &str = "\
GRAMMAR:
  wrex patch [FRAMES...] [-r FILE.pcap] --set path=value ...
                 [--insert AT:HEX] [--delete AT:LEN]
                 [--scope SEL[,…]|--no-recompute]
                 [--index N[-M][,…]] [--filter EXPR]
                 [--format FMT] [-w FILE.pcap] [--pcapng]

  The CLI door into the span-patch engine (tranche 11b/13a): dissect,
  apply typed edits, run the wire->wire consistency walk. Deterministic
  surgical edits of REAL frames — the mut field strategy's fixed-value
  counterpart. Seeds: positional hex, -r pcap records (classic, all 4
  magic variants, or pcapng — auto-detected), and/or raw stdin; the
  stream is the frame list in that order.

EDITS:
  --set path=value   typed per the field's schema (the value grammar:
                     ints/0x…, IPv4/IPv6, mac, hex:… bytes, flagset
                     bit names or raw masks; flag subpaths take
                     true|false: --set tcp.flags.syn=1). Every
                     dissected field key is addressable (see
                     `wrex fields`); ReEncode regions route through
                     the codec hook (dhcp sname/file take their text).
                     Over-wide bit-window values mask (the craft
                     rule). String-typed fields over raw spans refuse
                     typed values — their presentation is not their
                     wire encoding (dns names are label-encoded,
                     dns type/class are u16s behind names).
  --set path=wire:HEX  raw region bytes, the escape for everything
                     the typed grammar cannot speak: codec-owned
                     encodings (dhcp msg_type's 1-byte TLV: wire:08),
                     dns names (wire labels), dns type/class u16s.
  --insert AT:HEX    insert bytes at an absolute pre-edit offset
  --delete AT:LEN    delete LEN bytes at absolute offset AT
  All offsets are INPUT-frame coordinates; the whole set validates
  before anything applies (never partial, never last-write-wins).

SCOPE (what re-derives after the edits):
  default            every derived field (lengths, checksums): minimal
                     edits, whole frame consistent — re-dissecting the
                     output shows zero anomalies
  --no-recompute     preserve semantics: nothing re-derives, stale
                     checksums ride along (the mut field rule)
  --scope udp.*      selective: whole layers (KIND.*) and single
                     fields (udp.checksum), comma list
  An edit on a scope-selected derived field is a pointed usage error.
  NO edits + default scope = normalize (recompute every derived field
  in place); no edits + --no-recompute = pure passthrough.

SELECTION (--index 1-based ordinals, N-M ranges; --filter 'path OP
  value', the recv filter grammar): pick WHICH frames of the stream
  get patched (both given = intersection). Untouched frames pass
  through byte-identical with their timestamps and orig_len kept —
  nothing is dropped (replay's --filter drops; this one selects).
  A path missing from a selected frame is a pointed runtime error
  naming the frame (exit 1).

OUTPUT: stdout carries the whole stream (patched + passthrough) per
  --format (default hex; raw bytes; text/json/jsonl dissections of the
  output frames); -w writes the same stream as a pcap (classic by
  default, --pcapng the T8b writer). Purely offline: patch writes,
  `wrex replay -i` sends, `wrex diff` compares findings.

EXAMPLES:
  # two fields, everything re-derived (checksums stay valid)
  wrex patch --set ipv4.ttl=7 --set ipv4.dst=10.0.0.5 FRAME.hex

  # re-write every captured web flow onto a new port, whole corpus out
  wrex patch -r cap.pcap --filter 'tcp.dport=80' \\
    --set tcp.dport=8080 -w edited.pcap

  # frame 3 only, stale checksums kept deliberately
  wrex patch -r cap.pcap --index 3 --set tcp.window=512 --no-recompute

  # payload surgery: insert 4 bytes, lengths/checksums recompute
  wrex craft --format raw ... | wrex patch --insert 42:deadbeef

  # a codec-owned TLV through its wire encoding
  wrex patch --set dhcp.msg_type=wire:08 -r dhcp.pcap";

/// `wrex patch`: the span-patch engine's CLI door.
#[derive(Args, Debug)]
#[command(after_help = PATCH_AFTER_HELP)]
pub struct PatchArgs {
    #[command(flatten)]
    pub common: Common,
    /// Seed frames as hex (repeatable); -r/--read and stdin also feed.
    #[arg(value_name = "FRAME")]
    pub frames: Vec<String>,
    /// Pcap (classic or pcapng) to read frames from (repeatable).
    #[arg(short = 'r', long = "read", value_name = "FILE")]
    pub read: Vec<String>,
    /// Set one field: path=value, typed per the field's schema
    /// (repeatable; `wire:HEX` hands codec-owned regions raw bytes).
    #[arg(long = "set", value_name = "PATH=VALUE")]
    pub set: Vec<String>,
    /// Insert HEX bytes at absolute frame offset AT (repeatable).
    #[arg(long, value_name = "AT:HEX")]
    pub insert: Vec<String>,
    /// Delete LEN bytes at absolute frame offset AT (repeatable).
    #[arg(long, value_name = "AT:LEN")]
    pub delete: Vec<String>,
    /// Recompute only these derived fields after the edits:
    /// KIND.* (whole layer) or kind.field, comma list (default: all).
    #[arg(long, value_name = "SEL[,…]")]
    pub scope: Option<String>,
    /// Nothing re-derives: stale checksums ride along (preserve).
    #[arg(long)]
    pub no_recompute: bool,
    /// Patch only these frames (1-based ordinals, N-M ranges, comma
    /// list).
    #[arg(long, value_name = "N[-M][,…]")]
    pub index: Option<String>,
    /// Patch only frames matching this filter expression (the recv
    /// grammar; unlike replay nothing is dropped — it selects).
    #[arg(long)]
    pub filter: Option<String>,
    /// Write the edited stream as a pcap file (patched + passthrough,
    /// original timestamps kept).
    #[arg(short = 'w', long = "write", value_name = "FILE")]
    pub write: Option<String>,
    /// Write pcapng instead of classic pcap (with -w).
    #[arg(long)]
    pub pcapng: bool,
}

/// `wrex mut`: seeded, dissect-aware frame mutation.
#[derive(Args, Debug)]
#[command(after_help = MUT_AFTER_HELP)]
pub struct MutArgs {
    #[command(flatten)]
    pub common: Common,
    /// Seed frames as hex (repeatable); -r/--read and stdin also feed.
    #[arg(value_name = "FRAME")]
    pub frames: Vec<String>,
    /// Classic pcap to read seed frames from (repeatable).
    #[arg(short = 'r', long = "read", value_name = "FILE")]
    pub read: Vec<String>,
    /// Mutation strategy: field|len|flip|splice|raw|all (default all).
    #[arg(long)]
    pub strategy: Option<String>,
    /// Mutants to produce (default 8).
    #[arg(long)]
    pub count: Option<u64>,
    /// RNG seed (default time-derived; pins the mutant stream).
    #[arg(long)]
    pub seed: Option<u64>,
    /// Write the mutants as a classic pcap file.
    #[arg(short = 'w', long = "write", value_name = "FILE")]
    pub write: Option<String>,
}

/// `wrex fuzz`: the stateful recording prober.
#[derive(Args, Debug)]
#[command(after_help = FUZZ_AFTER_HELP)]
pub struct FuzzArgs {
    #[command(flatten)]
    pub common: Common,
    /// Probe mode: tcp|udp|icmp (default udp).
    #[arg(long)]
    pub mode: Option<String>,
    /// Targets: IPv4, CIDR or START-END ranges (repeatable).
    #[arg(value_name = "TARGET", required = true)]
    pub targets: Vec<String>,
    /// Ports: comma list with ranges (tcp defaults to the top-100
    /// list; required for udp; illegal for icmp).
    #[arg(long)]
    pub ports: Option<String>,
    /// Mutated rounds per (target, port) slot (default 4).
    #[arg(long)]
    pub rounds: Option<u32>,
    /// Send one unmutated baseline probe per slot first.
    #[arg(long)]
    pub baseline: bool,
    /// Mutation strategy for the rounds: field|len|flip|splice|raw|all.
    #[arg(long)]
    pub strategy: Option<String>,
    /// Send rate in packets/sec (0 = uncapped burst; no pacing flag:
    /// uncapped, bounded by --concurrent).
    #[arg(long)]
    pub rate: Option<u64>,
    /// Pacing between sends (e.g. 200ms); overrides --rate.
    #[arg(long)]
    pub interval: Option<String>,
    /// Seeded jitter magnitude (+/-) on the pacing step.
    #[arg(long)]
    pub jitter: Option<String>,
    /// RNG seed (default time-derived; pins identities + mutations).
    #[arg(long)]
    pub seed: Option<u64>,
    /// Extra attempts per probe beyond the first (default 1).
    #[arg(long)]
    pub retries: Option<u32>,
    /// Per-attempt reply timeout (default 1s).
    #[arg(long)]
    pub timeout: Option<String>,
    /// Max in-flight probes (default 256).
    #[arg(long)]
    pub concurrent: Option<usize>,
    /// Wrap the app-mode probe connections in TLS (https for `http`,
    /// DoT/RFC 7858 for `dns`; implies the app modes — default ports
    /// become 443/853).
    #[arg(long)]
    pub tls: bool,
    /// Accept any server certificate (no verification at all; see
    /// wrex-tls: the danger is semantic, documented at every surface).
    #[arg(long)]
    pub tls_insecure: bool,
    /// Extra CA bundle (PEM or DER) complementing — never replacing —
    /// the system roots (with --tls).
    #[arg(long, value_name = "FILE")]
    pub tls_ca: Option<String>,
}

/// Epilog for diff: the offline findings differential (tranche 12).
pub const DIFF_AFTER_HELP: &str = "\
GRAMMAR:
  wrex diff BASELINE.jsonl MUTATED.jsonl [--format text|json|jsonl]

  Diffs two `wrex fuzz --format jsonl` findings files offline: a
  baseline run against a mutated run (or two targets probed with the
  same corpus). Findings pair by probe identity — (target, port,
  proto, round); `strategy` is carried, never matched on — and every
  pair with a difference renders one entry:

    outcome deltas   reply -> silence, silence -> unreachable:3, …
    reply changes    reply added / removed / divergent bytes
    one-sided probes  present in only one file (with the probe hex)

  Equal pairs are silent; any completed diff is exit 0 (the report is
  data). Malformed lines are exit 2 with the file and line number.

EXAMPLES:
  wrex fuzz -i lo --baseline --rounds 4 --seed 7 --format jsonl \\
    127.0.0.1 > base.jsonl
  wrex fuzz -i lo --baseline --rounds 4 --seed 8 --format jsonl \\
    127.0.0.1 > mut.jsonl
  wrex diff base.jsonl mut.jsonl";

/// `wrex diff`: offline findings differential.
#[derive(Args, Debug)]
#[command(after_help = DIFF_AFTER_HELP)]
pub struct DiffArgs {
    #[command(flatten)]
    pub common: Common,
    /// Two findings JSONL files (baseline vs mutated, or two runs).
    #[arg(value_name = "FILE", num_args = 2, required = true)]
    pub files: Vec<String>,
}

/// `wrex scan`: TCP SYN/connect + UDP + ICMP scan over a raw-IP driver.
#[derive(Args, Debug)]
#[command(after_help = SCAN_AFTER_HELP)]
pub struct ScanArgs {
    #[command(flatten)]
    pub common: Common,
    /// Scan mode: syn|connect|udp|icmp (default syn).
    #[arg(long)]
    pub mode: Option<String>,
    /// Targets: IPv4, CIDR or START-END ranges (repeatable).
    #[arg(value_name = "TARGET", required = true)]
    pub targets: Vec<String>,
    /// Ports: comma list with ranges (default: top-100 TCP for
    /// syn/connect; required for udp; illegal for icmp).
    #[arg(long)]
    pub ports: Option<String>,
    /// Send rate in packets/sec (0 = uncapped burst; no pacing flag:
    /// uncapped, bounded by --concurrent).
    #[arg(long)]
    pub rate: Option<u64>,
    /// Pacing between sends (e.g. 200ms); overrides --rate.
    #[arg(long)]
    pub interval: Option<String>,
    /// Seeded jitter magnitude (+/-) on the pacing step.
    #[arg(long)]
    pub jitter: Option<String>,
    /// RNG seed (default: time-derived; pins reproducible scans).
    #[arg(long)]
    pub seed: Option<u64>,
    /// Extra attempts per probe beyond the first (default 1).
    #[arg(long)]
    pub retries: Option<u32>,
    /// Per-attempt reply timeout (default 1s).
    #[arg(long)]
    pub timeout: Option<String>,
    /// Max in-flight probes (default 256).
    #[arg(long)]
    pub concurrent: Option<usize>,
}

/// `wrex query`: one seeded DNS question over a kernel socket (UDP by
/// default; `--tcp`/`--tls` over streams).
#[derive(Args, Debug)]
#[command(after_help = QUERY_AFTER_HELP)]
pub struct QueryArgs {
    #[command(flatten)]
    pub common: Common,
    /// DNS server to ask (IPv4 or IPv6; tranche 10a).
    #[arg(long)]
    pub server: Option<String>,
    /// Server port (default 53).
    #[arg(long)]
    pub port: Option<u16>,
    /// Use DNS over TCP (RFC 7766; fresh connection per attempt).
    #[arg(long)]
    pub tcp: bool,
    /// Use DNS over TLS (RFC 7858; implies --tcp, default port 853,
    /// fresh TLS connection per attempt).
    #[arg(long)]
    pub tls: bool,
    /// Accept any server certificate (--tls; insecure).
    #[arg(long)]
    pub tls_insecure: bool,
    /// Extra CA bundle, PEM or DER (--tls; complements system roots).
    #[arg(long, value_name = "FILE")]
    pub tls_ca: Option<String>,
    /// Question type (default A; names or numbers: A, AAAA, MX, …).
    #[arg(long = "type")]
    pub qtype: Option<String>,
    /// Question class (default IN).
    #[arg(long = "class")]
    pub qclass: Option<String>,
    /// Advertise EDNS0 (tranche 20a): append an OPT pseudo-record;
    /// the value is the udp payload size (RFC 6891 §6.2.5 floors it at
    /// 512 — smaller is a usage error).
    #[arg(long, value_name = "SIZE")]
    pub edns: Option<u16>,
    /// Set the EDNS0 DO bit (DNSSEC OK; RFC 6891 §6.1.2) — implies
    /// --edns.
    #[arg(long)]
    pub edns_do: bool,
    /// DNS-over-HTTPS (RFC 8484, tranche 20b): POST the bare message
    /// to URL (http:// or https://…) as application/dns-message;
    /// fresh connection per attempt. Implies no --server/--port.
    #[arg(long, value_name = "URL")]
    pub doh: Option<String>,
    /// mDNS (RFC 6762, tranche 20b): ask the multicast group instead of
    /// a unicast server (224.0.0.251 / ff02::fb, port 5353).
    #[arg(long)]
    pub mdns: bool,
    /// Reverse lookup sugar (dig -x): NAME is an IP address; query PTR
    /// for its in-addr.arpa / ip6.arpa name.
    #[arg(long)]
    pub reverse: bool,
    /// dig +short: print only the answer rdata values (text format).
    #[arg(long)]
    pub short: bool,
    /// Extra attempts beyond the first, same query id (default 1).
    #[arg(long)]
    pub retries: Option<u32>,
    /// Per-attempt reply timeout (default 1s).
    #[arg(long)]
    pub timeout: Option<String>,
    /// RNG seed (default: time-derived; pins query id + source port).
    #[arg(long)]
    pub seed: Option<u64>,
    /// Question name (dotted form, e.g. example.com).
    #[arg(value_name = "NAME")]
    pub name: String,
}

/// `wrex http`: one HTTP/1.1 exchange over a kernel TCP connection.
#[derive(Args, Debug)]
#[command(after_help = HTTP_AFTER_HELP)]
pub struct HttpArgs {
    #[command(flatten)]
    pub common: Common,
    /// Positional grammar: [METHOD] URL [URL...] (a URL-looking first
    /// token ⇒ GET + a URL list; more URLs ride one keep-alive
    /// connection, tranche 9a). Declared as one vec so clap cannot
    /// mis-assign a URL to the method slot.
    #[arg(value_name = "URL_OR_METHOD")]
    pub positional: Vec<String>,
    /// Request header, repeatable (NAME:VALUE).
    #[arg(short = 'H', long, value_name = "NAME:VALUE")]
    pub header: Vec<String>,
    /// Request body: literal text, @FILE or hex:BYTES.
    #[arg(long, value_name = "TEXT|@FILE|hex:…")]
    pub data: Option<String>,
    /// Replay a recipe file (method/url/headers/body in JSON).
    #[arg(long, value_name = "FILE")]
    pub recipe: Option<String>,
    /// Per-attempt exchange timeout (default 10s).
    #[arg(long)]
    pub timeout: Option<String>,
    /// Extra attempts beyond the first on timeout/truncation (default 0).
    #[arg(long)]
    pub retries: Option<u32>,
    /// Response byte budget, head included (default 64 MiB).
    #[arg(long)]
    pub max_bytes: Option<u64>,
    /// Bind this local source port (determinism on multihomed hosts).
    #[arg(long)]
    pub source_port: Option<u16>,
    /// Accept any server certificate for https:// (dangerous; no
    /// name/chain/validity check).
    #[arg(long)]
    pub tls_insecure: bool,
    /// Extra CA bundle, PEM or DER (complements the system roots).
    #[arg(long, value_name = "FILE")]
    pub tls_ca: Option<String>,
    /// HTTP version: `1.1` (default) or `2` — for https, h2 rides ALPN
    /// (`h2` then `http/1.1`; a server that declines h2 falls back to
    /// HTTP/1.1 with a note); for http, h2 is cleartext **prior
    /// knowledge** (RFC 9113 §3.4: the preface goes straight over the
    /// TCP stream, no `Upgrade:` dance). Recipe wins over the flag.
    #[arg(long = "http-version", value_name = "1.1|2")]
    pub http_version: Option<String>,
    /// Send-side HPACK policy for h2 (tranche 16a): `indexed`
    /// (default: dynamic table + Huffman-when-strictly-shorter) or
    /// `literal` (the pre-16 wire bytes: indexed statics, no
    /// dynamic-table state, never Huffman — the replay-parity knob).
    /// Recipe wins over the flag; inert on 1.1 runs.
    #[arg(long, value_name = "indexed|literal")]
    pub hpack: Option<String>,
    /// Follow 3xx redirects (tranche 19a): Location resolution per
    /// RFC 3986, method rules per RFC 9110 §15.4 + curl (303 ⇒ GET,
    /// 301/302 rewrite POST ⇒ GET, 307/308 preserve; Authorization
    /// drops on a cross-origin hop). Same-origin hops ride the open
    /// connection; `--format json` adds `url` + `redirects` keys.
    #[arg(short = 'L', long)]
    pub follow: bool,
    /// Redirect hop budget under --follow (default 50, curl's).
    #[arg(long, value_name = "N")]
    pub max_redirs: Option<u32>,
    /// Cookie input (tranche 19a): a Netscape-format jar file
    /// (curl -b), or — when the string is not a readable file — a
    /// literal `Cookie:` header value. With a jar, the jar owns the
    /// Cookie header on every request (an explicit -H Cookie does
    /// not survive it); Set-Cookie responses update it.
    #[arg(short = 'b', long = "cookie", value_name = "FILE|VALUE")]
    pub cookie: Option<String>,
    /// Write the (updated) cookie jar here on exit, Netscape format
    /// (curl -c); implies a jar even without -b (collect-only).
    #[arg(short = 'c', long = "cookie-jar", value_name = "FILE")]
    pub cookie_jar: Option<String>,
    /// Exit 1 on 4xx/5xx statuses (completed exchanges stay data).
    #[arg(long)]
    pub fail: bool,
    /// Basic-auth credentials (tranche 19a): `Authorization: Basic` on
    /// every request (curl -u). USER alone = empty password.
    #[arg(short = 'u', long, value_name = "USER[:PASS]")]
    pub user: Option<String>,
    /// `Authorization: Bearer TOKEN` on every request (exclusive with
    /// --user).
    #[arg(long, value_name = "TOKEN")]
    pub bearer: Option<String>,
    /// With --user: answer a `401` carrying a Digest challenge via
    /// the RFC 7616 dance (no preemptive header; MD5, MD5-sess,
    /// SHA-256, SHA-256-sess, qop=auth and the legacy no-qop shape;
    /// a Basic-only 401 stays data).
    #[arg(long)]
    pub digest: bool,
    /// Request compressed content (tranche 19a): advertise the four
    /// codecs wrex decodes — `deflate, gzip, br, zstd` (curl's list,
    /// byte-exact) — and decode `Content-Encoding` responses
    /// (stacked codings right-to-left; the raw deflate fallback;
    /// multi-member gzip). Decoded bytes count against --max-bytes
    /// exactly like wire bytes (the bomb cap).
    #[arg(long)]
    pub compressed: bool,
    /// Write the response BODY to FILE, one -o per URL in order
    /// (curl -o); responses past the last -o go to stdout. Exclusive
    /// with -O.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Vec<String>,
    /// Write the body to the URL's remote basename in the CWD
    /// (curl -O). Exclusive with -o.
    #[arg(short = 'O', long)]
    pub remote_name: bool,
    /// Upload FILE: PUT with the file bytes as the body (curl -T;
    /// exclusive with --data).
    #[arg(short = 'T', long, value_name = "FILE")]
    pub upload_file: Option<String>,
    /// HEAD request (curl -I; exclusive with an explicit METHOD).
    #[arg(short = 'I', long)]
    pub head: bool,
    /// Include the response head in raw output (curl --include; the
    /// short -i is taken by --iface on every wrex verb — long only).
    /// The text format always carries the head.
    #[arg(long)]
    pub include: bool,
    /// Range request sugar: `Range: bytes=<SPEC>` (curl -r; SPEC is
    /// `N-M`, `N-` or `-N`).
    #[arg(short = 'r', long, value_name = "SPEC")]
    pub range: Option<String>,
    /// Pin a hostname to an address, bypassing resolution
    /// (curl --resolve `HOST[:PORT]:ADDR`, repeatable; applies to
    /// redirect hops too).
    #[arg(long, value_name = "HOST[:PORT]:ADDR")]
    pub resolve: Vec<String>,
    /// Retry on transient response statuses: N extra attempts when a
    /// completed response is 5xx (per request, fresh exchange — no
    /// delay; curl's backoff is deliberately not implemented, the
    /// lab-tool deviation).
    #[arg(long, value_name = "N")]
    pub retry: Option<u32>,
    /// Route through a proxy (tranche 19b, curl -x): `[http://]` an
    /// HTTP proxy (absolute-form request-targets for http://, CONNECT
    /// tunnels for https://), `socks5://` (local resolution) or
    /// `socks5h://` (the proxy resolves). Applies to redirect hops.
    #[arg(short = 'x', long, value_name = "[SCHEME://]HOST:PORT")]
    pub proxy: Option<String>,
    /// Proxy credentials (curl -U `USER[:PASS]`): Basic for CONNECT,
    /// RFC 1929 for SOCKS5.
    #[arg(short = 'U', long, value_name = "USER[:PASS]")]
    pub proxy_user: Option<String>,
    /// Add a `timing` object to each `--format json` response:
    /// time_connect_ms / time_appconnect_ms (TLS, https only) /
    /// time_starttransfer_ms / time_total_ms — the curl -w fields,
    /// json-shaped. Per original request (a redirect chain's timings
    /// span its hops).
    #[arg(long)]
    pub timing: bool,
}

#[derive(Args, Debug)]
pub struct IfaceArgs {
    #[command(flatten)]
    pub common: Common,
    /// Show a single interface by name.
    pub name: Option<String>,
}

#[derive(Args, Debug)]
pub struct FieldsArgs {
    #[command(flatten)]
    pub common: Common,
    /// Show a single layer kind by name (e.g. tcp; alias: ip).
    pub kind: Option<String>,
}

/// `wrex completions <SHELL>`: emit shell completions to stdout.
#[derive(Args, Debug)]
pub struct CompletionsArgs {
    /// Shell to emit completions for (bash|zsh|fish|elvish|powershell).
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

/// Initialize tracing-subscriber: `-v` levels, `RUST_LOG` respected.
pub fn init_tracing(verbose: u8) {
    let level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[cfg(test)]
mod tests {
    use super::{Cli, Cmd, build_cli, field_args};
    use clap::Parser;
    use wrex_core::Registry;

    /// The derive skeleton parses every verb and maps the common flags;
    /// craft/send's dynamic field args come from `build_cli` (below).
    #[test]
    fn subcommand_dispatch_and_common_flags() {
        let cli = Cli::try_parse_from(["wrex", "fields"]).expect("fields parses");
        match &cli.cmd {
            Cmd::Fields(_) => {}
            other => panic!("expected Fields, got {other:?}"),
        }
        // -v is a Count on every verb; verbose_level reads it back.
        let cli =
            Cli::try_parse_from(["wrex", "dissect", "-vv", "--start", "eth"]).expect("dissect");
        let Cmd::Dissect(a) = &cli.cmd else {
            panic!("expected Dissect");
        };
        assert_eq!((a.common.verbose, cli.verbose_level()), (2, 2));
        assert_eq!(a.start.as_deref(), Some("eth"));
        // Completions is the one verb with no common flags.
        let cli = Cli::try_parse_from(["wrex", "completions", "bash"]).expect("completions");
        assert_eq!(cli.verbose_level(), 0);
        // Unknown verb is a usage error (exit 2 at dispatch).
        assert!(Cli::try_parse_from(["wrex", "no-such-verb"]).is_err());
        // A verb that needs args but got none errors, not defaults.
        assert!(Cli::try_parse_from(["wrex", "completions"]).is_err());
    }

    /// The dynamic craft/send grammar: `--layer`, `--payload`, and one
    /// per-field flag per registry schema field (aliases included).
    #[test]
    fn field_args_cover_the_registry_grammar() {
        let registry: Registry = crate::standard();
        let args = field_args(&registry);
        let longs: std::collections::HashSet<String> = args
            .iter()
            .filter_map(|a| a.get_long().map(str::to_string))
            .collect();
        // The two grammar anchors exist for every registry.
        assert!(longs.contains("layer"));
        assert!(longs.contains("payload"));
        // Per-field flags: dotted paths dashed (`--icmpv6-ra-flags`).
        assert!(longs.contains("eth-dst"));
        assert!(longs.contains("ipv4-ttl"));
        assert!(longs.contains("icmpv6-ndp-ra_flags"));
        // FlagSet bit flags (`--tcp-flags-syn`).
        assert!(longs.contains("tcp-flags-syn"));
        // CLI aliases (pinned): ip-*/ip6-*/v6-* mirror ipv4/ipv6 fields
        // (aliases are not `get_long`s; collect them separately).
        let aliases: std::collections::HashSet<String> = args
            .iter()
            .filter_map(|a| a.get_aliases())
            .flatten()
            .map(str::to_string)
            .collect();
        assert!(aliases.contains("ip-ttl"));
        assert!(aliases.contains("ip-ttl"));
        assert!(
            aliases.contains("ip6-hop_limit") || aliases.contains("v6-hop_limit"),
            "expected the pinned ip6/v6 hop-limit aliases"
        );
        // Every field of every registered kind has a flag.
        for &kind in registry.kinds() {
            let schema = registry.schema(kind).expect("registered");
            for field in schema.fields {
                let want = format!("{kind}-{}", field.name.replace('.', "-"));
                assert!(longs.contains(&want), "missing flag --{want}");
            }
        }
    }

    /// `build_cli` threads the field args into craft/send only: the
    /// full command parses a real craft invocation, values and all.
    #[test]
    fn build_cli_parses_craft_field_flags() {
        let cmd = build_cli();
        let m = cmd
            .try_get_matches_from([
                "wrex",
                "craft",
                "--layer",
                "eth",
                "--layer",
                "ipv4",
                "--layer",
                "udp",
                "--eth-dst",
                "ff:ff:ff:ff:ff:ff",
                "--ipv4-src",
                "127.0.0.1",
                "--udp-dport",
                "53",
                "--payload",
                "hex:deadbeef",
            ])
            .expect("craft parses");
        let sub = m.subcommand_matches("craft").expect("craft");
        assert_eq!(
            sub.get_many::<String>("layer").unwrap().collect::<Vec<_>>(),
            vec!["eth", "ipv4", "udp"]
        );
        assert_eq!(
            sub.get_one::<String>("eth-dst").map(String::as_str),
            Some("ff:ff:ff:ff:ff:ff")
        );
        assert_eq!(
            sub.get_one::<String>("udp-dport").map(String::as_str),
            Some("53")
        );
        assert_eq!(
            sub.get_one::<String>("payload").map(String::as_str),
            Some("hex:deadbeef")
        );
        // The alias path parses to the same arg (ipv4-ttl ≡ ip-ttl).
        let m = build_cli()
            .try_get_matches_from(["wrex", "craft", "--ip-ttl", "63"])
            .expect("alias parses");
        let sub = m.subcommand_matches("craft").expect("craft");
        assert_eq!(
            sub.get_one::<String>("ipv4-ttl").map(String::as_str),
            Some("63")
        );
        // A field flag on a verb without the grammar is a usage error.
        assert!(
            build_cli()
                .try_get_matches_from(["wrex", "dissect", "--eth-dst", "aa:bb:cc:dd:ee:ff"])
                .is_err()
        );
    }

    /// `--help`/`--version` render (the man pages are generated from this
    /// command; the drift check lives in ci lint).
    #[test]
    fn help_and_version_render() {
        let err = build_cli()
            .try_get_matches_from(["wrex", "--version"])
            .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        let err = build_cli()
            .try_get_matches_from(["wrex", "--help"])
            .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        // And the built command's help mentions the root epilog grammar
        // sections (one source of truth: help text, man pages, docs).
        let styled = build_cli().render_help();
        let text = styled.to_string();
        for needle in ["VALUE GRAMMAR", "FILTERS", "EXIT CODES"] {
            assert!(text.contains(needle), "root epilog missing {needle}");
        }
    }
}
