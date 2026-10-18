#![forbid(unsafe_code)]
//! wrex binary: clap dispatch → verbs → exit codes (0 success, 1 runtime,
//! 2 usage).

mod cli;
mod spec;
mod verbs;

use clap::Parser;

fn main() {
    let parsed = cli::Cli::parse();
    cli::init_tracing(parsed.verbose_level());
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
