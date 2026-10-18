//! clap definitions. Standard options always precede the trailing field
//! capture: once a field flag appears, every later token is a field (per the
//! pinned craft/send grammar).

use clap::{ArgAction, Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "wrex",
    version,
    about = "wrex — wire experiments toolkit: craft, send, capture, dissect"
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
