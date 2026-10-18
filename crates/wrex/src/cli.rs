//! clap definitions. Standard options always precede the trailing field
//! capture: once a field flag appears, every later token is a field (per the
//! pinned craft/send grammar).

use clap::{ArgAction, Args, Parser, Subcommand};

/// Root epilog: the cross-cutting grammars (kinds, values, filters, exit
/// codes) a user needs before picking a verb. Per-verb examples live on the
/// verbs (`wrex <verb> --help`).
pub const ROOT_AFTER_HELP: &str = "\
FIELD FLAGS:
  craft and send take per-layer field flags after the standard options:
    --layer KIND            declare encapsulation order (repeatable)
    --payload VALUE         terminal payload bytes
    --<kind>-<field>=VALUE  set one field; dots in the path become dashes
                            (--ipv4-ttl=63, --tcp-flags-syn, --icmp-echo-id=5)
  Full grammar and examples: wrex craft --help.
  Every settable field, type, default and bit name: wrex fields [KIND].

LAYER KINDS:
  eth, arp, ipv4 (CLI alias: ip), icmp, udp, tcp.
  Ranks: eth 10; arp/ipv4 20; icmp/udp/tcp 30 (stack on ipv4).
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

/// Epilog shared by craft and send: the trailing field-flag grammar is
/// identical on both verbs, so one text serves both help screens.
pub const CRAFT_SEND_AFTER_HELP: &str = "\
FIELD FLAGS:
  Beyond the options above, every trailing token is a field flag:
    --layer KIND              declare encapsulation order (repeatable)
    --payload VALUE           terminal payload bytes
    --<kind>-<field>=VALUE   set one field; dots in the path become dashes
                              (--ipv4-ttl=63, --tcp-flags-syn, --icmp-echo-id=5)
  Kinds: eth, arp, ipv4 (alias: ip), icmp, udp, tcp. Without --layer,
  field flags imply their layers in rank order; a sibling conflict
  (two rank-30 kinds, or arp+ipv4) errors with a hint to pass --layer.
  Explicit values always win and are kept unvalidated; --strict
  re-validates the result (violations exit 2).
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
            Cmd::Iface(a) => a.common.verbose,
            Cmd::Fields(a) => a.common.verbose,
            Cmd::Completions(_) => 0,
        }
    }
}

/// Options shared by the verbs (must appear BEFORE any field flag).
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
    /// Standard options come first; everything after the first field flag
    /// (--layer, --payload, --<kind>-<field>=<value>) is a field flag.
    Craft(CraftArgs),

    /// Print shell completions to stdout (bash|zsh|fish|elvish|powershell).
    /// The trailing field flags are parsed by wrex itself and are not in
    /// the completion set; spell them via `wrex fields`.
    Completions(CompletionsArgs),

    /// stdin → DissectedPacket → stdout (never fatal).
    Dissect(DissectArgs),

    /// Send a crafted frame (or raw stdin bytes) on an interface.
    Send(SendArgs),

    /// Receive frames on an interface, filtered, until count/timeout/Ctrl-C.
    Recv(RecvArgs),

    /// Interface table: name, mac, ipv4s, mtu, up.
    Iface(IfaceArgs),

    /// Registry introspection: every settable field.
    Fields(FieldsArgs),
}

#[derive(Args, Debug)]
#[command(after_help = CRAFT_SEND_AFTER_HELP)]
pub struct CraftArgs {
    #[command(flatten)]
    pub common: Common,
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 0..
    )]
    pub fields: Vec<String>,
}

#[derive(Args, Debug)]
#[command(after_help = DISSECT_AFTER_HELP)]
pub struct DissectArgs {
    #[command(flatten)]
    pub common: Common,
    /// Dissection start: auto|eth|ipv4|… (default auto).
    #[arg(long)]
    pub start: Option<String>,
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 0..
    )]
    pub fields: Vec<String>,
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
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 0..
    )]
    pub fields: Vec<String>,
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
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 0..
    )]
    pub fields: Vec<String>,
}

#[derive(Args, Debug)]
pub struct IfaceArgs {
    #[command(flatten)]
    pub common: Common,
    /// Show a single interface by name.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
    pub fields: Vec<String>,
}

#[derive(Args, Debug)]
pub struct FieldsArgs {
    #[command(flatten)]
    pub common: Common,
    /// Show a single layer kind by name.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
    pub fields: Vec<String>,
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
