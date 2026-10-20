#![forbid(unsafe_code)]
//! xtask: wrex dev orchestration (`cargo xtask …`).

use std::path::{Path, PathBuf};
use std::process::Command;
mod man;
mod mcdc;
use clap::{Parser, Subcommand};

const PROPTEST_RNG_SEED: &str = "31337";

#[derive(Parser)]
#[command(name = "xtask", about = "wrex dev task runner")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// fmt check + clippy + workspace tests (+ optional stages)
    Verify {
        #[arg(long)]
        with_miri: bool,
        #[arg(long)]
        with_differential: bool,
        #[arg(long)]
        with_fuzz: bool,
        #[arg(long)]
        with_kani: bool,
    },
    /// advisory coverage report (no gate)
    Coverage {
        #[arg(long)]
        branch: bool,
        #[arg(long)]
        mcdc_probe: bool,
    },
    /// import a classic pcap into wrex-test/corpus/<name>/ (dev-only, needs tshark)
    CorpusImport { pcap: PathBuf, name: String },
    /// generate man pages into man/: wrex(1) + wrex-<kind>(7) per protocol
    Man {},
}

fn main() {
    let cli = Cli::parse();
    let root = workspace_root();
    match cli.cmd {
        Cmd::Verify {
            with_miri,
            with_differential,
            with_fuzz,
            with_kani,
        } => {
            verify(&root, with_miri, with_differential, with_fuzz, with_kani);
        }
        Cmd::Coverage { branch, mcdc_probe } => {
            coverage(&root, branch, mcdc_probe);
        }
        Cmd::CorpusImport { pcap, name } => {
            corpus_import(&root, &pcap, &name);
        }
        Cmd::Man {} => {
            let dir = man::generate(&root);
            println!("man pages written to {}", dir.display());
        }
    }
}

fn verify(root: &Path, with_miri: bool, with_differential: bool, with_fuzz: bool, with_kani: bool) {
    run(root, "fmt --check", "cargo", &["fmt", "--all", "--check"]);
    run(
        root,
        "clippy",
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    );
    run(
        root,
        "workspace tests",
        "cargo",
        &["test", "--workspace", "--all-features"],
    );
    if with_miri {
        let pkgs = [
            "wrex-core",
            "wrex-proto-eth",
            "wrex-proto-arp",
            "wrex-proto-ip",
            "wrex-proto-icmp",
            "wrex-proto-udp",
            "wrex-proto-tcp",
            "wrex-proto-dns",
            "wrex-session",
            "wrex-scan",
            "wrex-dns",
            "wrex-http",
            "wrex-pcap",
        ];
        let mut args = vec!["+nightly", "miri", "test"];
        for p in pkgs {
            args.push("-p");
            args.push(p);
        }
        run(root, "miri", "cargo", &args);
    }
    if with_differential {
        run(
            root,
            "differential",
            "cargo",
            &[
                "test",
                "--workspace",
                "--all-features",
                "--",
                "differential",
            ],
        );
    }
    if with_fuzz {
        fuzz_stage(root);
    }
    if with_kani {
        kani_stage(root);
    }
    println!("xtask verify: all requested stages green");
}

/// Kani proofs (tranche 4): curated tight-bounds harnesses, gating.
/// Skips with a notice when cargo-kani is not installed (advisory
/// locally; the CI `kani` job always runs them).
///
/// Memory discipline: harnesses are deliberately tiny (symbolic-byte
/// count is the exponential cost driver — see the per-harness docs),
/// and each proof runs under a virtual-memory ceiling so a regression
/// fails the gate loudly instead of swapping the machine. Runs are
/// sequential: solver peaks must not stack.
fn kani_stage(root: &Path) {
    let kani = Command::new("cargo")
        .arg("kani")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !kani {
        eprintln!("xtask verify --with-kani: SKIPPED (advisory): cargo kani not installed");
        return;
    }
    for pkg in ["wrex-core", "wrex-http", "wrex-pcap"] {
        run(
            root,
            pkg,
            "sh",
            &[
                "-c",
                &format!("ulimit -v {KANI_VMEM_KB}; exec cargo kani -p {pkg}"),
            ],
        );
    }
}

/// Virtual-memory ceiling per proof (~6 GB): solver-peak guardrail.
/// The curated harnesses verify well under 1 GB; this ceiling exists so
/// a harness regression fails the gate instead of swapping machines.
const KANI_VMEM_KB: u64 = 6 * 1024 * 1024;

fn coverage(root: &Path, branch: bool, mcdc_probe: bool) {
    let mut args = vec!["+nightly", "llvm-cov", "--workspace", "--all-features"];
    if branch {
        args.push("--branch");
    }
    args.push("--lcov");
    args.push("--output-path");
    args.push("target/coverage/lcov.info");
    let dir = root.join("target").join("coverage");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("xtask coverage: cannot create {}: {e}", dir.display());
        std::process::exit(1);
    }
    run(root, "llvm-cov", "cargo", &args);
    if mcdc_probe {
        mcdc_probe_stage(root);
    }
}

fn fuzz_stage(root: &Path) {
    // cargo +nightly fuzz run <t> -- -max_total_time=60 -rss_limit_mb=2560
    let targets = [
        "fuzz_dissect_eth",
        "fuzz_dissect_arp",
        "fuzz_dissect_ipv4",
        "fuzz_dissect_icmp",
        "fuzz_dissect_udp",
        "fuzz_dissect_tcp",
        "fuzz_dissect_dns",
        "fuzz_craft_roundtrip",
        "fuzz_scan_session",
        "fuzz_http_session",
        "fuzz_pcap_reader",
        "fuzz_pcap_roundtrip",
        "fuzz_mut_strategies",
        "fuzz_prober_session",
    ];
    let nightly = Command::new("cargo")
        .arg("+nightly")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let cargo_fuzz = Command::new("cargo")
        .arg("fuzz")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !nightly {
        eprintln!(
            "xtask verify --with-fuzz: SKIPPED (advisory): no nightly toolchain (`cargo +nightly` unavailable)"
        );
        return;
    }
    if !cargo_fuzz {
        eprintln!("xtask verify --with-fuzz: SKIPPED (advisory): cargo-fuzz not installed");
        return;
    }
    for t in targets {
        run(
            root,
            t,
            "cargo",
            &[
                "+nightly",
                "fuzz",
                "run",
                t,
                "--",
                "-max_total_time=60",
                "-rss_limit_mb=2560",
            ],
        );
    }
}

fn mcdc_probe_stage(root: &Path) {
    let outcome = mcdc::run(root);
    println!("cargo xtask coverage --mcdc-probe: {outcome}");
}

fn corpus_import(_root: &Path, pcap: &Path, name: &str) {
    let out = wrex_test::corpus::import(pcap, name).unwrap_or_else(|e| {
        eprintln!("xtask corpus-import: {e}");
        std::process::exit(1);
    });
    println!("imported corpus {name} -> {}", out.display());
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn run(root: &Path, label: &str, program: &str, args: &[&str]) {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(root)
        .env("PROPTEST_RNG_SEED", PROPTEST_RNG_SEED);
    let status = match cmd.status() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("xtask: failed to spawn {program}: {e}");
            std::process::exit(1);
        }
    };
    if !status.success() {
        eprintln!("xtask: stage failed: {label}");
        std::process::exit(status.code().unwrap_or(1));
    }
}
