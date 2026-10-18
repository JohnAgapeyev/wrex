//! MC/DC probe: compile a one-function probe with nightly
//! `-Zcoverage-options=mcdc` and report availability (advisory only).
//!
//! rustc removed `-Zcoverage-options=mcdc` in late 2025; re-landing is a
//! 2026 Rust goal. This probe NEVER gates CI — per the owner decision it
//! only prints availability to the step summary.

use std::path::Path;
use std::process::Command;

pub fn run(root: &Path) -> ProbeOutcome {
    let dir = root.join("target").join("mcdc-probe");
    let src = dir.join("probe.rs");
    if std::fs::create_dir_all(&dir).is_err() {
        return ProbeOutcome::Unavailable("cannot create target/mcdc-probe".into());
    }
    // One function with two independent conditions: the classic MC/DC shape.
    let body = r#"
pub fn decide(a: bool, b: bool) -> bool {
    if a && b { true } else { a || b }
}
fn main() {
    std::hint::black_box(decide(true, false));
}
"#;
    if std::fs::write(&src, body).is_err() {
        return ProbeOutcome::Unavailable("cannot write probe.rs".into());
    }
    let out = Command::new("rustc")
        .arg("+nightly")
        .arg("-Zcoverage-options=mcdc")
        .arg("--emit=llvm-ir")
        .arg("-o")
        .arg(dir.join("probe.ll"))
        .arg(&src)
        .output();
    match out {
        Ok(o) if o.status.success() => ProbeOutcome::Available {
            rustc: nightly_version(),
        },
        Ok(o) => ProbeOutcome::Unavailable(format!(
            "nightly rustc rejected -Zcoverage-options=mcdc (exit {}): {}",
            o.status,
            String::from_utf8_lossy(&o.stderr)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
        )),
        Err(e) => ProbeOutcome::Unavailable(format!("no nightly rustc: {e}")),
    }
}

fn nightly_version() -> String {
    Command::new("rustc")
        .arg("+nightly")
        .arg("--version")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "nightly (unknown)".into())
}

pub enum ProbeOutcome {
    Available { rustc: String },
    Unavailable(String),
}

impl std::fmt::Display for ProbeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeOutcome::Available { rustc } => write!(
                f,
                "MC/DC AVAILABLE: nightly rustc accepted -Zcoverage-options=mcdc ({rustc})"
            ),
            ProbeOutcome::Unavailable(why) => {
                write!(f, "MC/DC unavailable (advisory, no gate): {why}")
            }
        }
    }
}
