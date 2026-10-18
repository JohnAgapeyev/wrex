#![forbid(unsafe_code)]
//! wrex binary: clap dispatch → verbs → exit codes (0 success, 1 runtime,
//! 2 usage). The CLI surface lives in the library (`wrex::cli`,
//! `wrex::verbs`) so man-page generation and tests share one definition.

use clap::Parser;

use wrex::cli::{Cli, init_tracing};
use wrex::verbs;

fn main() {
    let parsed = Cli::parse();
    init_tracing(parsed.verbose_level());
    match verbs::dispatch(&parsed) {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            for line in e.lines() {
                eprintln!("wrex: {line}");
            }
            std::process::exit(e.exit_code());
        }
    }
}
