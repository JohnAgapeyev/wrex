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
                }
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
