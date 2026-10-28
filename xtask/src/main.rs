#![forbid(unsafe_code)]
//! xtask: wrex dev orchestration (`cargo xtask …`).

use std::path::{Path, PathBuf};
use std::process::Command;
mod man;
mod mcdc;
mod perfdiff;
mod scenarios;
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
    /// import a pcap (classic or pcapng) into wrex-test/corpus/<name>/ (dev-only, needs tshark)
    CorpusImport { pcap: PathBuf, name: String },
    /// generate man pages into man/: wrex(1) + wrex-<kind>(7) per protocol
    Man {},
    /// run the workspace tests recording per-suite wall-clock, then
    /// ratchet against xtask/suitetime-baseline.json (HP3-e)
    Suitetime {
        /// re-baseline: record this run's times as the new baseline
        #[arg(long)]
        update: bool,
    },
    /// regenerate the per-crate public-API snapshots into
    /// xtask/api-snapshots/ (HP3-e; `--check` exits nonzero on drift)
    ApiSnapshot {
        /// fail on drift instead of writing
        #[arg(long)]
        check: bool,
    },
    /// HP3-b oracle-capture scenarios: foreign-tool traffic captured by
    /// tcpdump into crates/wrex-test/corpus/scen-*/ (needs the
    /// `unshare -Urn` sandbox — re-execs itself there)
    CorpusCapture {
        /// capture only this scenario (by name)
        #[arg(long)]
        only: Option<String>,
    },
    /// performance differentials vs tshark/dig/curl/nmap on equivalent
    /// output (informational, like the bench tripwires — never a gate).
    /// Re-execs under `unshare -Urn` (raw-socket rows need CAP_NET_RAW);
    /// `--no-sandbox` stays outside and skips those rows.
    PerfDiff {
        /// only rows whose name contains this substring
        #[arg(long)]
        only: Option<String>,
        /// repetitions per side (median + min reported)
        #[arg(long, default_value = "5")]
        reps: u32,
        /// stay outside the sandbox; raw-socket rows skip with notice
        #[arg(long)]
        no_sandbox: bool,
    },
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
        Cmd::Suitetime { update } => {
            suitetime(&root, update);
        }
        Cmd::ApiSnapshot { check } => {
            api_snapshot(&root, check);
        }
        Cmd::CorpusCapture { only } => {
            corpus_capture(&root, only.as_deref());
        }
        Cmd::PerfDiff {
            only,
            reps,
            no_sandbox,
        } => {
            perf_diff(&root, only.as_deref(), reps, no_sandbox);
        }
    }
}

/// `cargo xtask perf-diff` — the release-profile precondition, then
/// the `unshare -Urn` re-exec (the corpus-capture pattern): the
/// raw-UDP query row and every scan row need CAP_NET_RAW, and one
/// uniform environment keeps all rows comparable.
fn perf_diff(root: &Path, only: Option<&str>, reps: u32, no_sandbox: bool) {
    // Release precondition (the hotpaths rule): a dev-profile wrex
    // measures debug-assertions and overflow checks, not wrex.
    run(
        root,
        "wrex release build",
        "cargo",
        &["build", "--release", "-p", "wrex"],
    );
    let in_sandbox = std::env::var("WREX_PERFDIFF_SANDBOX").as_deref() == Ok("1");
    if in_sandbox || no_sandbox {
        perfdiff::run(root, only, reps, in_sandbox);
        return;
    }
    let mut cmd =
        format!("export WREX_PERFDIFF_SANDBOX=1; cargo run -q -p xtask -- perf-diff --reps {reps}");
    if let Some(name) = only {
        cmd.push_str(&format!(" --only {name:?}"));
    }
    let status = Command::new("unshare")
        .arg("-Urn")
        .arg("sh")
        .arg("-ec")
        .arg(&cmd)
        .current_dir(root)
        .status()
        .expect("spawn unshare (needs a kernel with user namespaces)");
    if !status.success() {
        eprintln!("xtask perf-diff: sandbox run failed ({status})");
        std::process::exit(1);
    }
}

/// `cargo xtask corpus-capture` — re-exec under the user-namespace
/// sandbox when not already inside one (the scenarios need
/// CAP_NET_ADMIN/CAP_NET_RAW for veth pairs, tcpdump and arping;
/// `unshare -Urn` provides them unprivileged — the README recipe).
fn corpus_capture(root: &Path, only: Option<&str>) {
    let in_sandbox = std::env::var("WREX_SCENARIO_SANDBOX").as_deref() == Ok("1");
    if in_sandbox {
        scenarios::capture(root, only);
        return;
    }
    let mut cmd = String::from("export WREX_SCENARIO_SANDBOX=1; ");
    if let Some(name) = only {
        cmd.push_str(&format!(
            "cargo run -p xtask -- corpus-capture --only {name}"
        ));
    } else {
        cmd.push_str("cargo run -p xtask -- corpus-capture");
    }
    let status = Command::new("unshare")
        .arg("-Urn")
        .arg("sh")
        .arg("-ec")
        .arg(&cmd)
        .current_dir(root)
        .status()
        .expect("spawn unshare (needs a kernel with user namespaces)");
    if !status.success() {
        eprintln!("xtask corpus-capture: sandbox run failed ({status})");
        std::process::exit(1);
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
    // The workspace tests ride the suite-time ratchet (HP3-e): the
    // same single cargo-test pass records per-suite wall-clock and
    // gates >2x growth (the doctrine's pointed-name rule; the Miri
    // precedent — a suite that quietly triples is a suite that moves
    // to the extended gate).
    suitetime(root, false);
    if with_miri {
        let pkgs = [
            "wrex-core",
            "wrex-proto-eth",
            "wrex-proto-arp",
            "wrex-proto-ip",
            "wrex-proto-ip6",
            "wrex-proto-ip6ext",
            "wrex-proto-icmp",
            "wrex-proto-icmpv6",
            "wrex-proto-udp",
            "wrex-proto-tcp",
            "wrex-proto-dns",
            "wrex-proto-dhcp",
            "wrex-proto-dhcp6",
            "wrex-proto-vlan",
            "wrex-session",
            "wrex-scan",
            "wrex-dns",
            "wrex-http",
            "wrex-pcap",
            "wrex-frag",
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
        "fuzz_dissect_ipv6",
        "fuzz_dissect_icmp",
        "fuzz_dissect_icmpv6",
        "fuzz_dissect_udp",
        "fuzz_dissect_tcp",
        "fuzz_dissect_dns",
        "fuzz_dissect_dhcp",
        "fuzz_dissect_vlan",
        "fuzz_craft_roundtrip",
        "fuzz_scan_session",
        "fuzz_http_session",
        "fuzz_pcap_reader",
        "fuzz_pcap_roundtrip",
        "fuzz_pcapng_reader",
        "fuzz_pcapng_roundtrip",
        "fuzz_mut_strategies",
        "fuzz_prober_session",
        "fuzz_app_session",
        "fuzz_h2_frame_decoder",
        "fuzz_hpack",
        "fuzz_h2_session",
        "fuzz_frag_reassembly",
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

// --- HP3-e rails: suite-time ratchet + API-surface ratchet ----------------

/// The committed suite-time baseline (the man-page pattern: regenerate
/// with `cargo xtask suitetime --update`, review the diff, commit).
const SUITETIME_BASELINE: &str = "xtask/suitetime-baseline.json";

/// Run the workspace tests with captured output, recording per-suite
/// wall-clock, then ratchet against the committed baseline.
///
/// The gate (>2x the recorded time, a pointed suite name) is
/// noise-robust by design: absolute wall-clock varies across runners,
/// and the doctrine's >20% class renders as a printed warning, not a
/// red CI. `--update` rewrites the baseline.
fn suitetime(root: &Path, update: bool) {
    let out = Command::new("cargo")
        .args(["test", "--workspace", "--all-features"])
        .current_dir(root)
        // The parse below reads cargo's plain-text "Running …" status
        // lines; CI exports CARGO_TERM_COLOR=always, whose ANSI escapes
        // precede the prefix and break strip_prefix (the born-red HP3-e
        // run). Force plain output for the measured invocation.
        .env("CARGO_TERM_COLOR", "never")
        .env("PROPTEST_RNG_SEED", PROPTEST_RNG_SEED)
        .output()
        .expect("spawn cargo test");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        eprint!("{stdout}{stderr}");
        eprintln!("xtask: stage failed: workspace tests");
        std::process::exit(out.status.code().unwrap_or(1));
    }
    // cargo prints the per-binary "Running …" status lines on stderr;
    // libtest's "test result: … finished in" lands on stdout; binaries
    // run SERIALLY, so the two ordered lists zip 1:1.
    let times = parse_suite_times(&stdout, &stderr);
    assert!(
        !times.is_empty(),
        "no per-suite timings parsed from cargo test"
    );
    let path = root.join(SUITETIME_BASELINE);
    if update {
        let mut map = std::collections::BTreeMap::new();
        for (suite, t) in &times {
            map.insert(suite.clone(), *t);
        }
        std::fs::write(&path, serde_json::to_string_pretty(&map).unwrap() + "\n")
            .expect("write baseline");
        println!(
            "suite-time baseline rewritten ({} suites) — review the diff and commit",
            times.len()
        );
        return;
    }
    let baseline: std::collections::BTreeMap<String, f64> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let mut slow = Vec::new();
    let mut warnings = 0;
    let mut new_suites = 0;
    for (suite, t) in &times {
        match baseline.get(suite) {
            None => {
                new_suites += 1;
                println!("suitetime: NEW suite {suite}: {t:.1}s (baseline with --update)");
            }
            Some(b) => {
                // Sub-100ms baselines are noise-only: skip (a 40ms suite
                // "doubling" is scheduler jitter, not bloat — and the
                // 2x gate against a ~0.0s baseline trips on any jitter).
                // The suite's *size class* is the baseline's, not the
                // measurement's.
                if *b < 0.1 {
                    continue;
                }
                if *t > b * 2.0 {
                    slow.push(format!("{suite}: {t:.1}s (baseline {b:.1}s)"));
                } else if *t > b * 1.2 {
                    warnings += 1;
                    println!("suitetime: {suite} grew >20%: {t:.1}s (baseline {b:.1}s)");
                }
            }
        }
    }
    for suite in baseline.keys() {
        if !times.iter().any(|(s, _)| s == suite) {
            println!("suitetime: stale baseline entry `{suite}` (suite gone)");
        }
    }
    println!(
        "suitetime: {} suites, {warnings} growth warnings, {new_suites} new",
        times.len()
    );
    if !slow.is_empty() {
        eprintln!(
            "suitetime RATCHET FAILED (>2x baseline — move the suite to the extended gate \
             or re-baseline deliberately):\n  {}",
            slow.join("\n  ")
        );
        std::process::exit(1);
    }
}

/// Parse libtest's per-binary sections out of a `cargo test` run:
/// stderr carries the ordered `Running <x> (target/.../deps/<stem>)`
/// status lines, stdout the ordered `… finished in N.NNs` results —
/// binaries run serially, so the two lists zip 1:1. Suite key = the
/// binary stem with the hash stripped (integration tests) or the
/// crate stem for unittest binaries.
fn parse_suite_times(stdout: &str, stderr: &str) -> Vec<(String, f64)> {
    let keys: Vec<String> = stderr
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("Running ")?;
            let binary = rest.split('(').nth(1)?.split(')').next()?;
            // target/debug/deps/<stem>-<hash> (or <stem>-<hash>.exe)
            let file = binary.rsplit('/').next()?;
            let stem = file.strip_suffix(".exe").unwrap_or(file);
            stem.rsplit_once('-').map(|(name, _)| name.to_string())
        })
        .collect();
    let times: Vec<f64> = stdout
        .lines()
        .filter_map(|line| {
            let at = line.find("finished in ")?;
            line[at + "finished in ".len()..]
                .trim()
                .strip_suffix('s')
                .and_then(|s| s.parse::<f64>().ok())
        })
        .collect();
    keys.into_iter().zip(times).collect()
}

/// The per-crate public-API snapshot dir (the man-page pattern).
const API_SNAPSHOTS: &str = "xtask/api-snapshots";

/// Regenerate (or check) the per-crate public-API snapshots via
/// `cargo public-api` (needs a nightly toolchain for rustdoc JSON —
/// skip-with-notice when unavailable, the doctrine's advisory-first
/// posture; CI installs the tool explicitly).
fn api_snapshot(root: &Path, check: bool) {
    let tool = Command::new("cargo")
        .arg("public-api")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !tool {
        eprintln!(
            "xtask api-snapshot: SKIPPED (advisory): cargo-public-api not installed \
             (cargo install cargo-public-api --locked; needs nightly rustdoc)"
        );
        return;
    }
    let dir = root.join(API_SNAPSHOTS);
    if !check {
        std::fs::create_dir_all(&dir).expect("mkdir snapshots");
    }
    let mut drift = Vec::new();
    let mut written = 0;
    for pkg in workspace_packages(root) {
        let out = Command::new("cargo")
            .args(["public-api", "-p", &pkg, "--all-features"])
            .current_dir(root)
            .output()
            .unwrap_or_else(|e| panic!("spawn cargo public-api -p {pkg}: {e}"));
        if !out.status.success() {
            eprintln!(
                "xtask api-snapshot: {pkg} FAILED: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            std::process::exit(1);
        }
        let api = String::from_utf8_lossy(&out.stdout).to_string();
        let path = dir.join(format!("{pkg}.txt"));
        if check {
            match std::fs::read_to_string(&path) {
                Ok(committed) if committed == api => {}
                _ => drift.push(pkg),
            }
        } else {
            std::fs::write(&path, &api).expect("write snapshot");
            written += 1;
        }
    }
    if check {
        if drift.is_empty() {
            println!(
                "api-snapshot: {} crates, no drift",
                workspace_packages(root).len()
            );
        } else {
            eprintln!(
                "api-snapshot DRIFT (regenerate with `cargo xtask api-snapshot` and review):\n  {}",
                drift.join("\n  ")
            );
            std::process::exit(1);
        }
    } else {
        println!("api-snapshot: wrote {written} snapshots to {API_SNAPSHOTS}/");
    }
}

/// Every workspace member crate EXCEPT the binary-only dev tooling
/// (`xtask` has no library target — no public API to snapshot).
fn workspace_packages(root: &Path) -> Vec<String> {
    let out = Command::new("cargo")
        .arg("metadata")
        .arg("--no-deps")
        .arg("--format-version")
        .arg("1")
        .current_dir(root)
        .output()
        .expect("cargo metadata");
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).expect("metadata json");
    let mut names: Vec<String> = meta["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .filter_map(|p| {
            let name = p["name"].as_str()?;
            // Binary-only members (the xtask dev tool) have no lib
            // target — cargo public-api rejects them and they carry
            // no SDK surface anyway.
            let has_lib = p["targets"].as_array()?.iter().any(|t| {
                t["kind"]
                    .as_array()
                    .is_some_and(|k| k.iter().any(|x| x == "lib"))
            });
            has_lib.then(|| name.to_string())
        })
        .collect();
    names.sort();
    names
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
