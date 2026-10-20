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
  eth, arp, vlan, ipv4 (CLI alias: ip), icmp, udp, tcp, dns.
  Ranks: eth 10; vlan 15; arp/ipv4 20; icmp/udp/tcp 30 (stack on
  ipv4); dns 40 (stacks on udp; port-53 datagrams dissect into it).
  Man pages: wrex(1), wrex-<kind>(7) in man/ of the source checkout.

VALUE GRAMMAR:
  ints       63 | 0x3f | 0b111111 | 0o77 (range-checked per field)
  ipv4       127.0.0.1            mac     aa:bb:cc:dd:ee:ff
  bytes      hex:DEADBEEF | text:... | @FILE | @- (stdin) | repeat:8x00
  flagsets   syn,ack | syn+ack | 0x02    bool  true | false | 1 | 0
  durations  (--count/--interval/--timeout)  500ms | 2s | 1m (bare: seconds)

FILTERS (recv --filter, send --wait-reply):
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

/// Epilog for dissect: formats and the never-fatal contract.
pub const DISSECT_AFTER_HELP: &str = "\
FORMATS:
  raw   input bytes echoed out (byte-transparent pipelines)
  hex   lowercase hex + newline
  text  indented field tree, '! path: message' anomaly lines and a
        trailing payload hexdump (default)
  json / jsonl  {\"start\":..,\"layers\":[..],\"payload_hex\":..,\"anomalies\":[..]}

EXAMPLES:
  wrex craft --format raw --layer eth ... | wrex dissect --format json
  wrex dissect --start eth < frame.bin
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

/// Epilog for http: the HTTP/1.1 ask verb (tranche 4).
pub const HTTP_AFTER_HELP: &str = "\
HTTP GRAMMAR:
  wrex http [METHOD] URL [-H NAME:VALUE]... [--data TEXT|@FILE|hex:…]
           [--timeout DUR] [--retries N] [--max-bytes N]
           [--source-port N] [--fail] [--recipe FILE]
           [--format text|json|raw]

  One HTTP/1.1 exchange per connection (Connection: close): the
  request is fully materialized first, so the same arguments (or the
  same --recipe FILE) replay byte-identical wire bytes. Host,
  User-Agent, Accept and Content-Length derive automatically with
  explicit-wins semantics (user headers come first, in order).

  Bodies: content-length and chunked (trailers merge into headers),
  read-to-close when neither is declared; 1xx skipped; HEAD/204/304
  carry no body. https:// is out of the tranche-4 charter (no TLS).

  Any completed exchange is exit 0 whatever the status says; --fail
  turns 4xx/5xx into exit 1; connect/timeout/protocol failures are
  exit 1; grammar and recipe errors are exit 2.

RECIPE (--recipe FILE, JSON):
  {\"method\": \"POST\", \"url\": \"http://host/api\",
   \"headers\": [[\"X-A\", \"1\"]], \"body_hex\": \"deadbeef\",
   \"timeout_ms\": 1500, \"retries\": 1, \"max_bytes\": 67108864}
  Ordered header pairs keep wire bytes deterministic; body_hex and
  body_text are mutually exclusive.

EXAMPLES:
  wrex http http://example.com/
  wrex http POST http://example.com/api -H X-Thing:42 --data '{\"a\":1}'
  wrex http --recipe req.json --format json
  wrex http GET http://example.com/ --data @body.bin --source-port 42424";

/// Epilog for scan: modes, grammar, pacing and the seeded RNG.
pub const SCAN_AFTER_HELP: &str = "\
TARGETS:
  repeatable positional: IPv4, CIDR (10.0.0.0/24; network and
  broadcast skipped below /31), or inclusive ranges
  (10.0.0.1-10.0.0.9; tails allowed: 10.0.0.0-0.255).

MODES (--mode):
  syn      TCP SYN scan (default): SYN+ACK -> open (RST sent to kill
           the half-open), RST -> closed, silence -> filtered
  connect  full handshake: ACK then RST after SYN+ACK -> open
  udp      empty datagrams: UDP reply -> open, ICMP 3/3 -> closed,
           ICMP 3/{1,2,9,10,13} -> filtered, silence -> open|filtered
  icmp     echo sweep (no ports): reply -> alive, silence -> dead

PORTS (--ports):
  comma list with ranges (22,80,100-200). syn/connect default to a
  committed top-100 TCP list (see wrex fields / the man page);
  udp REQUIRES --ports; icmp takes none.

TIMING:
  --rate N        packets/sec (default 100; 0 = uncapped burst)
  --interval DUR  explicit pacing (e.g. 200ms); overrides --rate
  --jitter DUR    seeded +/- jitter on the pacing step
  --seed U64      pins the RNG (default: time-derived): probe source
                  ports, tcp seqs, icmp ids and the jitter schedule
                  are bit-reproducible under a pinned seed
  --timeout DUR   per-attempt reply timeout (default 1s)
  --retries N     extra attempts per probe (default 1)
  --concurrent N  max in-flight probes (default 256)

PROBES:
  IPv4 datagrams injected via a raw-IP socket (kernel routes and
  fragments; needs CAP_NET_RAW); replies are captured on -i IFACE.
  Results stream as they resolve (--format text|json|jsonl).

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
            Cmd::Fuzz(a) => a.common.verbose,
            Cmd::Http(a) => a.common.verbose,
            Cmd::Query(a) => a.common.verbose,
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

    /// Capture frames from an interface into a classic pcap file.
    Capture(CaptureArgs),

    /// Read a pcap (dissect to stdout) or re-send it on an interface.
    Replay(ReplayArgs),

    /// Scan targets (TCP SYN/connect, UDP, ICMP) and classify ports/hosts.
    Scan(ScanArgs),

    /// Mutate seed frames (dissect-aware, seeded) → stdout / pcap.
    Mut(MutArgs),

    /// Probe targets with mutated packets; record replies as findings.
    Fuzz(FuzzArgs),

    /// One HTTP/1.1 exchange: send a request, dissect the response.
    Http(HttpArgs),

    /// Ask a DNS server one question over raw UDP and dissect the reply.
    Query(QueryArgs),

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
            // CLI-only kind aliases (pinned): `ip` → `ipv4`.
            if kind == "ipv4" {
                arg = arg.alias(format!("ip-{}", dashed(field.name)));
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
        // an unindexed shorthand (`--dns-name` → `qd.0.name`); the arg
        // id stays the full dashed path so spec assembly is unambiguous.
        // Other records are dissect-only and take no flags.
        for record in schema.records {
            if !(record.settable && record.max == Some(1)) {
                continue;
            }
            for field in record.fields {
                let arg_id = flag_long(kind, &format!("{}.0.{}", record.name, field.name));
                let short = format!("{kind}-{}", field.name);
                let long = if used_longs.insert(short.clone()) {
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

/// Epilog for capture: the tranche-5 pcap tap.
pub const CAPTURE_AFTER_HELP: &str = "\
GRAMMAR:
  wrex capture -i IFACE -w FILE.pcap [options]

  AF_PACKET receive loop (like recv) into a classic pcap file:
  little-endian microsecond, link type EN10MB (in-house writer, no
  libpcap). Frames pass --filter before they are written; --snaplen
  truncates the stored copy (orig_len keeps the wire length).

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
  classic files only (all 4 magic variants read; pcapng is out of the
  tranche-5 charter — write out with text2pcap/mergecap if needed).";

/// `wrex capture`: AF_PACKET recv loop into a classic pcap file.
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
}

/// `wrex replay`: offline dissection or re-send of a classic pcap.
#[derive(Args, Debug)]
#[command(after_help = REPLAY_AFTER_HELP)]
pub struct ReplayArgs {
    #[command(flatten)]
    pub common: Common,
    /// Classic pcap file to read.
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
}

/// Epilog for query: the DNS ask verb (tranche 3).
pub const QUERY_AFTER_HELP: &str = "\
QUERY GRAMMAR:
  wrex query [-i IFACE] --server IP [--port 53] [--tcp] [options] NAME

  Sends one seeded DNS question and waits for the matching reply
  (id + 4-tuple over UDP; with --tcp: RFC 7766 length-prefixed DNS
  over a fresh TCP connection per attempt). --retries re-sends the
  SAME query (same dns id) after --timeout. A reply received is a
  success (exit 0) whatever the rcode says — NXDOMAIN/SERVFAIL are
  data, printed in the dissected reply.

RECORD FIELDS (wrex dissect --filter also accepts these):
  answers/authority/additional records dissect into indexed paths:
  dns.an.0.name, dns.an.0.type, dns.an.0.ttl, dns.an.0.rdata …
  A rdata is typed ipv4; CNAME/NS/PTR resolve (compression pointers
  included) to names; TXT and everything else stay raw hex bytes.

EXAMPLES:
  wrex query -i eth0 --server 192.168.1.1 example.com
  wrex query -i eth0 --server 1.1.1.1 --type MX --seed 42 example.com
  wrex query --tcp --server 192.168.1.1 example.com";

/// Epilog for mut: the tranche-6a mutation verb.
pub const MUT_AFTER_HELP: &str = "\
GRAMMAR:
  wrex mut [FRAMES...] [-r FILE.pcap] [--strategy S] [--count N]
                 [--seed U64] [--format FMT] [-w FILE.pcap]

  Seeds: positional hex frames, -r/--read classic pcap records
  (all 4 magic variants), and/or raw stdin. Mutants print per
  --format (default hex): hex/raw are the bytes; text/json/jsonl
  dissect the mutant. -w writes the mutants as a classic pcap
  (LE microsecond, EN10MB) — a mutated corpus `wrex replay` and
  `wrex fuzz` consume.

STRATEGIES (--strategy, default all):
  field   dissect the seed, mutate one typed field value, re-encode
          with autofill (checksums re-derive)
  len     perturb a length field explicitly (autofill keeps it)
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

/// Epilog for fuzz: the tranche-6b recording prober.
pub const FUZZ_AFTER_HELP: &str = "\
GRAMMAR:
  wrex fuzz -i IFACE [--mode tcp|udp|icmp] [options] TARGET...

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

  Reply keys derive from the POST-mutation dissection: a mutation
  that moved the identity still matches its own replies.

PORTS (--ports): comma list with ranges. tcp defaults to the
  committed top-100 list (same as scan); udp REQUIRES --ports; icmp
  takes none.

TIMING (same vocabulary as scan): --rate N (default 100; 0 = burst),
  --interval DUR, --jitter DUR, --seed U64 (identities, mutation
  streams, jitter), --timeout DUR (default 1s), --retries N,
  --concurrent N (default 256).

FINDINGS: one line per probe — --format text (default), json (array)
  or jsonl; every finding carries the exact probe bytes (hex), so
  anything interesting replays with `wrex send`/`wrex replay`, and a
  baseline run diffs offline against the mutated rounds.

EXAMPLES:
  wrex fuzz -i lo --baseline --rounds 4 127.0.0.1
  wrex fuzz -i eth0 --mode udp --ports 53,161 --rounds 16 --seed 7 10.0.0.0/24
  wrex fuzz -i eth0 --mode tcp --ports 22,443 --strategy field 10.0.0.5";

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
    /// Send rate in packets/sec (default 100; 0 = uncapped burst).
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
    /// Send rate in packets/sec (default 100; 0 = uncapped burst).
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

/// `wrex query`: one seeded DNS question over a raw UDP datagram.
#[derive(Args, Debug)]
#[command(after_help = QUERY_AFTER_HELP)]
pub struct QueryArgs {
    #[command(flatten)]
    pub common: Common,
    /// DNS server to ask.
    #[arg(long)]
    pub server: Option<String>,
    /// Server port (default 53).
    #[arg(long)]
    pub port: Option<u16>,
    /// Use DNS over TCP (RFC 7766; fresh connection per attempt).
    #[arg(long)]
    pub tcp: bool,
    /// Question type (default A; names or numbers: A, AAAA, MX, …).
    #[arg(long = "type")]
    pub qtype: Option<String>,
    /// Question class (default IN).
    #[arg(long = "class")]
    pub qclass: Option<String>,
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
    /// Positional grammar: [METHOD] URL (URL alone ⇒ GET). Declared as
    /// one vec so clap cannot mis-assign a URL to the method slot.
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
    /// Exit 1 on 4xx/5xx statuses (completed exchanges stay data).
    #[arg(long)]
    pub fail: bool,
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
