#![forbid(unsafe_code)]
//! wrex binary: clap dispatch → verbs → exit codes (0 success, 1 runtime,
//! 2 usage). The CLI surface lives in the library (`wrex::cli`,
//! `wrex::verbs`); the craft/send field flags are built from the registry
//! at startup ([`wrex::cli::build_cli`]).

use clap::FromArgMatches as _;

use wrex::cli::{Cli, build_cli, init_tracing};
use wrex::verbs;

fn main() {
    let cmd = build_cli();
    // Clap handles usage errors itself: prints to stderr, exits 2.
    let matches = cmd.get_matches();
    let parsed = Cli::from_arg_matches(&matches).expect("matches came from the same command");
    init_tracing(parsed.verbose_level());
    match verbs::dispatch(&parsed, &matches) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            for line in e.lines() {
                eprintln!("wrex: {line}");
            }
            std::process::exit(e.exit_code());
        }
    }
}
