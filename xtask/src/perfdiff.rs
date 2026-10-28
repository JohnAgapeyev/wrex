//! Performance differentials vs the reference tools (tshark / dig /
//! curl / nmap) — the *timing* sibling of the logical differentials:
//! the same bytes through both tools with equivalent output, wall
//! clock reported. Informational only (the `hotpaths.rs` posture):
//! numbers land in the run logs and `target/perfdiff/report.json`,
//! and no gate ever reads them.
//!
//! `cargo xtask perf-diff [--only SUBSTR] [--reps N] [--no-sandbox]`.
//! The driver builds wrex in release first (dev-profile numbers
//! measure debug-assertions, not wrex — the `assert_release_profile`
//! precedent) and re-execs under `unshare -Urn` (the corpus-capture
//! pattern): every scan row needs CAP_NET_RAW, and one uniform
//! environment keeps all rows comparable. `--no-sandbox` stays
//! outside and skips those rows (the dns rows ride kernel sockets
//! since perf-pass 3b and run either way).
//!
//! Methodology per row: one discarded warmup run per side (page
//! cache, dynamic loading), then `--reps` runs interleaved
//! ours/theirs so scheduler drift lands on both sides of every rep;
//! median + min reported, ratio = ours/theirs. The report prints
//! every row's exact commands (reproduction) and an attribution note
//! — the measured home of "key things they do that we don't".
//!
//! Fixtures are harness-owned so the far side is never the measured
//! bottleneck and nothing external is touched: synthetic pcaps
//! cycled from the committed golden corpus (classic + pcapng),
//! dnsmasq on a free loopback port (the scen-dns recipe), an
//! in-process HTTP/1.1 keep-alive stub (the http_differential.rs
//! spawn_stub pattern), and a loopback listener farm whose accept
//! threads close completed handshakes immediately (a full accept
//! queue makes the kernel drop the final ACK and scans stall on
//! retransmits — corrupted timing).

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use wrex_pcap::{PcapWriter, PcapngWriter};
use wrex_test::corpus::Corpus;

use crate::scenarios::have_tool;

/// Fixture frame counts: the cold row is startup-dominated (one
/// 16-frame corpus capture — the corpus import cap), the big rows
/// carry the hot-loop workload (25k cycled corpus frames, both
/// container formats).
const COLD_FRAMES: usize = 16;
const BIG_FRAMES: usize = 25_000;

/// The scan farm: burst rows probe 1000 ports (100 open + 900
/// closed); the defaults row probes a 200-port subset (wrex's seeded
/// 100pps default would make a 1000-port defaults row a 10s row).
const FARM_PORTS: usize = 100;
const BURST_CLOSED: usize = 900;
const DEFAULTS_OPEN: usize = 20;
const DEFAULTS_CLOSED: usize = 180;

/// Run every wanted row, print the report, write the JSON artifact.
/// Advisory by charter: the exit code stays 0 — a failed command dies
/// loudly (a harness bug or environment problem is never a silent
/// skip), but the *numbers* never gate anything.
pub fn run(root: &Path, only: Option<&str>, reps: u32, sandboxed: bool) {
    assert!(reps >= 1, "perf-diff: --reps must be >= 1");
    if sandboxed {
        // The driver-test recipe: a fresh user-namespace netns leaves
        // `lo` down, and the dns/scan rows probe loopback.
        sh("ip link set lo up");
    }
    let dir = root.join("target/perfdiff");
    std::fs::create_dir_all(&dir).expect("mkdir target/perfdiff");
    let wrex = wrex_bin(root);
    let want = |name: &str| only.is_none_or(|s| name.contains(s));

    let mut rows = Vec::new();
    rows.extend(dissect_rows(&wrex, &dir, reps, &want));
    rows.extend(dns_rows(&wrex, &dir, reps, &want));
    rows.extend(http_rows(&wrex, &dir, reps, &want));
    rows.extend(scan_rows(&wrex, &dir, reps, sandboxed, &want));
    if rows.is_empty() {
        println!("perf-diff: no rows ran (filter {only:?} or missing tools)");
        return;
    }
    let env = environment(&wrex, sandboxed);
    render(&rows, &env, reps);
    let report = dir.join("report.json");
    write_report(&rows, &env, reps, &report);
    println!(
        "\nperf-diff: report written to {} (+ per-row last-run stdout .ours.out/.theirs.out)",
        report.display()
    );
}

/// The release binary the driver built before the sandbox re-exec —
/// never target/debug (dev-profile numbers measure debug-assertions,
/// not wrex).
fn wrex_bin(root: &Path) -> String {
    let p = root.join("target/release/wrex");
    assert!(
        p.is_file(),
        "target/release/wrex missing (the driver builds it before the re-exec)"
    );
    p.to_str().expect("utf-8 workspace path").to_string()
}

fn sh(line: &str) {
    let status = Command::new("sh")
        .arg("-ec")
        .arg(line)
        .status()
        .unwrap_or_else(|e| panic!("spawn `{line}`: {e}"));
    assert!(
        status.success(),
        "perf-diff setup failed: `{line}` ({status})"
    );
}

// --- rows ----------------------------------------------------------------

/// One row of measured work: per-side samples, the exact commands,
/// the attribution note, and (for dissect/scan rows) the workload
/// the throughput rates derive from.
struct Row {
    name: &'static str,
    note: &'static str,
    ours_cmd: String,
    theirs_cmd: String,
    ours_ms: Vec<f64>,
    theirs_ms: Vec<f64>,
    /// Last-run stdout artifact sizes (rendering volume — an
    /// attribution datum: unequal output volume is unequal work).
    ours_bytes: u64,
    theirs_bytes: u64,
    workload: Option<Workload>,
}

/// The count/bytes a throughput rate derives from (`unit` labels it:
/// frames per second for dissect rows, ports per second for scans).
#[derive(Clone, Copy)]
struct Workload {
    unit: &'static str,
    count: u64,
    bytes: u64,
}

fn dissect_rows(wrex: &str, dir: &Path, reps: u32, want: &dyn Fn(&str) -> bool) -> Vec<Row> {
    if !have_tool("tshark") {
        println!("perf-diff: dissect rows SKIPPED (no tshark)");
        return vec![];
    }
    const NAMES: &[&str] = &[
        "dissect/cold-16-classic",
        "dissect/text-25k-classic",
        "dissect/text-25k-pcapng",
        "dissect/jsonl-25k-classic",
        "dissect/json-25k-classic",
    ];
    if !NAMES.iter().any(|n| want(n)) {
        return vec![];
    }
    let frames = corpus_frames();
    assert!(
        !frames.is_empty(),
        "the committed corpus is empty — the dissect rows have no workload"
    );
    let cold = dir.join("cold-16-classic.pcap");
    write_fixture(&cold, &frames[..COLD_FRAMES.min(frames.len())], false);
    let big = cycle(&frames, BIG_FRAMES);
    let classic = dir.join("big-25k-classic.pcap");
    let classic_bytes = write_fixture(&classic, &big, false);
    let pcapng = dir.join("big-25k-pcapng.pcapng");
    write_fixture(&pcapng, &big, true);
    println!(
        "perf-diff: fixtures — cold {} frames, big {} frames cycled from {} corpus frames",
        COLD_FRAMES.min(frames.len()),
        big.len(),
        frames.len()
    );
    let cold = cold.to_str().expect("utf-8 path");
    let classic = classic.to_str().expect("utf-8 path");
    let pcapng = pcapng.to_str().expect("utf-8 path");
    let text = Workload {
        unit: "frames",
        count: big.len() as u64,
        bytes: classic_bytes,
    };
    let mut rows = Vec::new();
    if want("dissect/cold-16-classic") {
        rows.push(duel_row(
            dir,
            reps,
            "dissect/cold-16-classic",
            cmd(wrex, &["replay", "--format", "text", cold]),
            cmd("tshark", &["-r", cold, "-n", "-V"]),
            "startup-dominated: process spawn + 16 frames. tshark -V renders the full per-frame \
             field tree (our text render's counterpart); -n keeps name resolution off (wrex \
             resolves none yet — the T24 name tables)",
            None,
        ));
    }
    if want("dissect/text-25k-classic") {
        rows.push(duel_row(
            dir,
            reps,
            "dissect/text-25k-classic",
            cmd(wrex, &["replay", "--format", "text", classic]),
            cmd("tshark", &["-r", classic, "-n", "-V"]),
            "hot loop: full per-frame tree, text render, classic container.",
            Some(text),
        ));
    }
    if want("dissect/text-25k-pcapng") {
        rows.push(duel_row(
            dir,
            reps,
            "dissect/text-25k-pcapng",
            cmd(wrex, &["replay", "--format", "text", pcapng]),
            cmd("tshark", &["-r", pcapng, "-n", "-V"]),
            "same 25k frames through the pcapng container — reader-side cost isolated.",
            Some(text),
        ));
    }
    if want("dissect/jsonl-25k-classic") {
        rows.push(duel_row(
            dir,
            reps,
            "dissect/jsonl-25k-classic",
            cmd(wrex, &["replay", "--format", "jsonl", classic]),
            cmd("tshark", &["-r", classic, "-n", "-T", "ek"]),
            "structured output, streaming: tshark -T ek writes one NDJSON doc (+ bulk-index line) \
             per frame — its closest match to our jsonl default.",
            Some(text),
        ));
    }
    if want("dissect/json-25k-classic") {
        rows.push(duel_row(
            dir,
            reps,
            "dissect/json-25k-classic",
            cmd(wrex, &["replay", "--format", "jsonl", classic]),
            cmd("tshark", &["-r", classic, "-n", "-T", "json"]),
            "tshark's canonical machine mode (-T json) buffers the whole array before writing; \
             ours streams jsonl — both honest, formats noted.",
            Some(text),
        ));
    }
    rows
}

fn dns_rows(wrex: &str, dir: &Path, reps: u32, want: &dyn Fn(&str) -> bool) -> Vec<Row> {
    let missing: Vec<&str> = ["dnsmasq", "dig"]
        .into_iter()
        .filter(|t| !have_tool(t))
        .collect();
    if !missing.is_empty() {
        println!("perf-diff: dns rows SKIPPED (missing {missing:?})");
        return vec![];
    }
    let want_tcp = want("dns/tcp-cold");
    let want_udp = want("dns/udp-cold");
    if !want_tcp && !want_udp {
        return vec![];
    }
    let dns = Dnsmasq::spawn(dir);
    let port = dns.port.to_string();
    let mut rows = Vec::new();
    if want_tcp {
        rows.push(duel_row(
            dir,
            reps,
            "dns/tcp-cold",
            cmd(
                wrex,
                &[
                    "query",
                    "--tcp",
                    "--server",
                    "127.0.0.1",
                    "--port",
                    &port,
                    "--seed",
                    "7",
                    "wrex.test",
                ],
            ),
            cmd(
                "dig",
                &[
                    "@127.0.0.1",
                    "-p",
                    &port,
                    "+time=1",
                    "+tries=1",
                    "+tcp",
                    "wrex.test",
                    "A",
                ],
            ),
            "RFC 7766 DNS over TCP: fresh kernel connection per attempt on both sides — startup + \
             handshake + one exchange, the CLI experience.",
            None,
        ));
    }
    if want_udp {
        rows.push(duel_row(
            dir,
            reps,
            "dns/udp-cold",
            cmd(
                wrex,
                &[
                    "query",
                    "--server",
                    "127.0.0.1",
                    "--port",
                    &port,
                    "--seed",
                    "7",
                    "wrex.test",
                ],
            ),
            cmd(
                "dig",
                &[
                    "@127.0.0.1",
                    "-p",
                    &port,
                    "+time=1",
                    "+tries=1",
                    "wrex.test",
                    "A",
                ],
            ),
            "default transport: both sides ride kernel UDP sockets (perf-pass 3b — the first \
             baseline measured wrex's raw-IP send + AF_PACKET reply tap at ~15-19ms fixed cost \
             per invocation: the tap's protocol-hook add/remove waits on an RCU grace period, \
             ~14ms bind + ~4ms close on 32 CPUs; wrex was 2.2x slower than dig). The kernel \
             socket is the dig-parity fix; wrex still crafts the dns message itself (seeded \
             id) — the transport cost is what was measured here.",
            None,
        ));
    }
    rows
}

fn http_rows(wrex: &str, dir: &Path, reps: u32, want: &dyn Fn(&str) -> bool) -> Vec<Row> {
    if !have_tool("curl") {
        println!("perf-diff: http rows SKIPPED (no curl)");
        return vec![];
    }
    const NAMES: &[&str] = &["http/cold-1kib", "http/cold-1mib", "http/keepalive-100"];
    if !NAMES.iter().any(|n| want(n)) {
        return vec![];
    }
    let stub = HttpStub::spawn();
    let k1 = format!("http://{}/k1", stub.addr);
    let m1 = format!("http://{}/m1", stub.addr);
    // 100 URLs in one process: both tools queue them over one
    // keep-alive connection (wrex tranche 9a; curl's default reuse).
    let urls: Vec<String> = (0..100).map(|_| k1.clone()).collect();
    let mut ours_args = vec!["http"];
    let mut curl_args = vec!["-s"];
    for u in &urls {
        ours_args.push(u.as_str());
        curl_args.push(u.as_str());
    }
    let mut rows = Vec::new();
    if want("http/cold-1kib") {
        rows.push(duel_row(
            dir,
            reps,
            "http/cold-1kib",
            cmd(wrex, &["http", "GET", &k1]),
            cmd("curl", &["-s", &k1]),
            "one GET, 1KiB body: wrex prints status line + headers + body (curl -i's shape), \
             curl -s prints the body — equivalent consumed work; startup + connect + exchange.",
            None,
        ));
    }
    if want("http/cold-1mib") {
        rows.push(duel_row(
            dir,
            reps,
            "http/cold-1mib",
            cmd(wrex, &["http", "GET", &m1]),
            cmd("curl", &["-s", &m1]),
            "same with a 1MiB body — the response read path dominates over startup.",
            None,
        ));
    }
    if want("http/keepalive-100") {
        rows.push(duel_row(
            dir,
            reps,
            "http/keepalive-100",
            cmd(wrex, &ours_args),
            cmd("curl", &curl_args),
            "100 URLs, ONE process, one keep-alive connection each — the sustained client; \
             per-exchange cost = total minus startup.",
            None,
        ));
    }
    rows
}

fn scan_rows(
    wrex: &str,
    dir: &Path,
    reps: u32,
    sandboxed: bool,
    want: &dyn Fn(&str) -> bool,
) -> Vec<Row> {
    if !have_tool("nmap") {
        println!("perf-diff: scan rows SKIPPED (no nmap)");
        return vec![];
    }
    if !sandboxed {
        println!(
            "perf-diff: scan rows SKIPPED (raw-socket rows need the sandbox; --no-sandbox passed)"
        );
        return vec![];
    }
    const NAMES: &[&str] = &[
        "scan/connect-burst-1000",
        "scan/syn-burst-1000",
        "scan/connect-defaults-200",
    ];
    if !NAMES.iter().any(|n| want(n)) {
        return vec![];
    }
    let farm = Farm::spawn(FARM_PORTS);
    let closed = free_ports(BURST_CLOSED, &farm.ports);
    let mut burst = farm.ports.clone();
    burst.extend_from_slice(&closed);
    let mut defaults: Vec<u16> = farm.ports[..DEFAULTS_OPEN].to_vec();
    defaults.extend_from_slice(&closed[..DEFAULTS_CLOSED]);
    let burst_list = port_list(&burst);
    let defaults_list = port_list(&defaults);
    let thousand = Workload {
        unit: "ports",
        count: 1000,
        bytes: 0,
    };
    let two_hundred = Workload {
        unit: "ports",
        count: 200,
        bytes: 0,
    };
    let mut rows = Vec::new();
    if want("scan/connect-burst-1000") {
        rows.push(duel_row(
            dir,
            reps,
            "scan/connect-burst-1000",
            cmd(
                wrex,
                &[
                    "scan",
                    "-i",
                    "lo",
                    "--mode",
                    "connect",
                    "--rate",
                    "0",
                    "--seed",
                    "7",
                    "--ports",
                    &burst_list,
                    "127.0.0.1",
                ],
            ),
            cmd(
                "nmap",
                &[
                    "-n",
                    "-Pn",
                    "-sT",
                    "-T4",
                    "--min-rate",
                    "1000",
                    "-p",
                    &burst_list,
                    "127.0.0.1",
                ],
            ),
            "full throttle: 1000 ports (100 open farm + 900 closed), connect mode — wrex --rate 0 \
             vs nmap -T4 --min-rate 1000. Measured attribution of the gap (tcpdump + strace \
             cross-reference): the tap's kernel-default receive buffer (212992 B ≈ 222 frames) \
             silently dropped the initial burst's reply tail — 256 in-flight − 222 capacity = \
             exactly the 34 probes that classified 'filtered' — and every drop paid the double \
             1s timeout (the flat 2s wall). nmap's TPACKET ring never drops. Fixed by the tap's \
             SO_RCVBUF bump (wrex-io rx.rs); the scan_driver burst test is the tripwire.",
            Some(thousand),
        ));
    }
    if want("scan/syn-burst-1000") {
        rows.push(duel_row(
            dir,
            reps,
            "scan/syn-burst-1000",
            cmd(
                wrex,
                &[
                    "scan",
                    "-i",
                    "lo",
                    "--mode",
                    "syn",
                    "--rate",
                    "0",
                    "--seed",
                    "7",
                    "--ports",
                    &burst_list,
                    "127.0.0.1",
                ],
            ),
            cmd(
                "nmap",
                &[
                    "-n",
                    "-Pn",
                    "-sS",
                    "-T4",
                    "--min-rate",
                    "1000",
                    "-p",
                    &burst_list,
                    "127.0.0.1",
                ],
            ),
            "same list, SYN mode: raw probes both sides (CAP_NET_RAW — the sandbox), the \
             scanner RSTs half-opens closed itself — the same receive-buffer drop mechanism \
             as the connect row governs wrex's burst (see that row's attribution).",
            Some(thousand),
        ));
    }
    if want("scan/connect-defaults-200") {
        rows.push(duel_row(
            dir,
            reps,
            "scan/connect-defaults-200",
            cmd(
                wrex,
                &[
                    "scan",
                    "-i",
                    "lo",
                    "--mode",
                    "connect",
                    "--seed",
                    "7",
                    "--ports",
                    &defaults_list,
                    "127.0.0.1",
                ],
            ),
            cmd(
                "nmap",
                &["-n", "-Pn", "-sT", "-p", &defaults_list, "127.0.0.1"],
            ),
            "out-of-the-box knobs: since perf-pass 3c wrex bursts uncapped, bounded by \
             --concurrent 256 (nmap's parallelism model — the first baseline measured the old \
             seeded 100pps default ~80x slower out of the box); the seeded --rate/--interval/\
             --jitter are the opt-in pacing knobs. nmap's -T3 self-tunes parallelism.",
            Some(two_hundred),
        ));
    }
    rows
}

// --- measurement core ----------------------------------------------------

/// A command plus its reportable string form.
fn cmd(program: &str, args: &[&str]) -> (Command, String) {
    let mut c = Command::new(program);
    c.args(args);
    let display = format!("{program} {}", args.join(" "));
    (c, display)
}

/// One row: warmup + interleaved reps of both sides, samples kept.
fn duel_row(
    dir: &Path,
    reps: u32,
    name: &'static str,
    ours: (Command, String),
    theirs: (Command, String),
    note: &'static str,
    workload: Option<Workload>,
) -> Row {
    println!("perf-diff: {name} — running {reps} reps…");
    let tag = name.replace('/', "-");
    let (ours_ms, theirs_ms) = duel(reps, ours.0, theirs.0, dir, &tag);
    Row {
        name,
        note,
        workload,
        ours_cmd: ours.1,
        theirs_cmd: theirs.1,
        ours_ms,
        theirs_ms,
        ours_bytes: file_len(dir, &format!("{tag}.ours.out")),
        theirs_bytes: file_len(dir, &format!("{tag}.theirs.out")),
    }
}

fn duel(
    reps: u32,
    mut ours: Command,
    mut theirs: Command,
    dir: &Path,
    tag: &str,
) -> (Vec<f64>, Vec<f64>) {
    // One warmup run per side, discarded (page cache, dynamic loading,
    // allocator state) — then the reps interleave ours/theirs so
    // scheduler drift lands on both sides of every rep equally.
    let _ = run_once(&mut ours, dir, tag, Side::Ours);
    let _ = run_once(&mut theirs, dir, tag, Side::Theirs);
    let mut ours_ms = Vec::with_capacity(reps as usize);
    let mut theirs_ms = Vec::with_capacity(reps as usize);
    for _ in 0..reps {
        ours_ms.push(run_once(&mut ours, dir, tag, Side::Ours).as_secs_f64() * 1e3);
        theirs_ms.push(run_once(&mut theirs, dir, tag, Side::Theirs).as_secs_f64() * 1e3);
    }
    (ours_ms, theirs_ms)
}

enum Side {
    Ours,
    Theirs,
}

/// One timed subprocess: stdout → the row's artifact file (the last
/// run's output stays for eyeballing), stderr → a capture file
/// printed on failure. Dies loudly on a nonzero exit — a failed
/// command is a harness bug or environment problem, never a silent
/// skip.
fn run_once(cmd: &mut Command, dir: &Path, tag: &str, side: Side) -> Duration {
    let err_path = dir.join(format!("{tag}.stderr"));
    let out_path = match side {
        Side::Ours => dir.join(format!("{tag}.ours.out")),
        Side::Theirs => dir.join(format!("{tag}.theirs.out")),
    };
    let out = std::fs::File::create(&out_path).expect("artifact file");
    let err = std::fs::File::create(&err_path).expect("stderr capture");
    let start = Instant::now();
    let status = cmd
        .stdout(out)
        .stderr(err)
        .status()
        .unwrap_or_else(|e| panic!("perf-diff: spawn {cmd:?}: {e}"));
    let elapsed = start.elapsed();
    if !status.success() {
        let stderr = std::fs::read_to_string(&err_path).unwrap_or_default();
        panic!("perf-diff: command failed ({status}): {cmd:?}\n  stderr: {stderr}");
    }
    elapsed
}

fn median(samples: &mut [f64]) -> f64 {
    samples.sort_by(|a, b| a.total_cmp(b));
    let mid = samples.len() / 2;
    if samples.len() % 2 == 1 {
        samples[mid]
    } else {
        (samples[mid - 1] + samples[mid]) / 2.0
    }
}

/// Per-side summary stats + the ours/theirs ratio.
struct RowStats {
    ours_median: f64,
    ours_min: f64,
    theirs_median: f64,
    theirs_min: f64,
    ratio: f64,
}

fn stats(row: &Row) -> RowStats {
    let mut ours = row.ours_ms.clone();
    let mut theirs = row.theirs_ms.clone();
    let ours_median = median(&mut ours);
    let theirs_median = median(&mut theirs);
    RowStats {
        ours_median,
        ours_min: ours.first().copied().unwrap_or(f64::NAN),
        theirs_median,
        theirs_min: theirs.first().copied().unwrap_or(f64::NAN),
        ratio: ours_median / theirs_median,
    }
}

fn fmt_ms(v: f64) -> String {
    if v < 10.0 {
        format!("{v:.2}ms")
    } else {
        format!("{v:.1}ms")
    }
}

fn fmt_rate(rate: f64, unit: &str) -> String {
    if rate >= 1000.0 {
        format!("{:.1}k {unit}/s", rate / 1000.0)
    } else {
        format!("{rate:.1} {unit}/s")
    }
}

fn verdict(ratio: f64) -> String {
    if ratio <= 1.0 / 1.5 {
        format!("wrex ~{:.1}x faster", 1.0 / ratio)
    } else if ratio >= 1.5 {
        format!("wrex ~{ratio:.1}x slower")
    } else {
        "same ballpark".to_string()
    }
}

fn file_len(dir: &Path, name: &str) -> u64 {
    std::fs::metadata(dir.join(name))
        .map(|m| m.len())
        .unwrap_or(0)
}

// --- report ---------------------------------------------------------------

struct Environment {
    wrex: String,
    tools: BTreeMap<String, String>,
    cpus: usize,
    kernel: String,
    sandboxed: bool,
}

fn environment(wrex_bin: &str, sandboxed: bool) -> Environment {
    let mut tools = BTreeMap::new();
    for (name, args) in [
        ("tshark", &["--version"][..]),
        ("dig", &["-v"][..]),
        ("curl", &["--version"][..]),
        ("nmap", &["--version"][..]),
    ] {
        tools.insert(name.to_string(), first_line(name, args));
    }
    Environment {
        wrex: first_line(wrex_bin, &["--version"]),
        tools,
        cpus: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        kernel: first_line("uname", &["-r"]),
        sandboxed,
    }
}

/// First stdout line of `program args` — provenance ("unknown" when
/// the tool is absent; its rows skip with a notice anyway).
fn first_line(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().next().map(str::to_string))
        .unwrap_or_else(|| "unknown".into())
}

fn render(rows: &[Row], env: &Environment, reps: u32) {
    println!(
        "\nperf-diff: wrex vs the reference tools — INFORMATIONAL (no gate reads these numbers)"
    );
    println!("  wrex:   {}", env.wrex);
    for (name, version) in &env.tools {
        // curl's banner is a paragraph; the report header wants one
        // line (the JSON artifact keeps the full string).
        let shown = if version.len() > 72 {
            format!("{}…", &version[..72])
        } else {
            version.clone()
        };
        println!("  {name}: {shown}");
    }
    println!(
        "  host:   {} CPUs, linux {}, sandbox: {}",
        env.cpus,
        env.kernel,
        if env.sandboxed {
            "unshare -Urn"
        } else {
            "none (--no-sandbox)"
        }
    );
    println!(
        "  method: reps={reps} (1 warmup per side discarded, ours/theirs interleaved), median [min] ms, ratio = ours/theirs\n"
    );
    let name_w = rows.iter().map(|r| r.name.len()).max().unwrap_or(10).max(4);
    println!(
        "{:<name_w$}  {:>22}  {:>22}  {:>7}  verdict",
        "row", "ours median [min]", "theirs median [min]", "ratio"
    );
    for row in rows {
        let s = stats(row);
        println!(
            "{:<name_w$}  {:>22}  {:>22}  {:>7}  {}",
            row.name,
            format!("{} [{}]", fmt_ms(s.ours_median), fmt_ms(s.ours_min)),
            format!("{} [{}]", fmt_ms(s.theirs_median), fmt_ms(s.theirs_min)),
            format!("{:.2}x", s.ratio),
            verdict(s.ratio),
        );
    }
    let throughput: Vec<&Row> = rows.iter().filter(|r| r.workload.is_some()).collect();
    if !throughput.is_empty() {
        println!("\nthroughput (per side, from the medians):");
        for row in throughput {
            let w = row.workload.as_ref().expect("filtered on workload");
            let s = stats(row);
            let ours = w.count as f64 / (s.ours_median / 1e3);
            let theirs = w.count as f64 / (s.theirs_median / 1e3);
            let bytes = if w.bytes > 0 {
                format!(
                    "  (ours {:.1} MiB/s, theirs {:.1} MiB/s)",
                    w.bytes as f64 / (s.ours_median / 1e3) / (1024.0 * 1024.0),
                    w.bytes as f64 / (s.theirs_median / 1e3) / (1024.0 * 1024.0)
                )
            } else {
                String::new()
            };
            println!(
                "  {:<name_w$}  ours {}  theirs {}{bytes}",
                row.name,
                fmt_rate(ours, w.unit),
                fmt_rate(theirs, w.unit),
            );
        }
    }
    println!("\ncommands (the exact pairs, for reproduction):");
    for row in rows {
        println!(
            "  {}:\n    ours:   {}\n    theirs: {}",
            row.name, row.ours_cmd, row.theirs_cmd
        );
    }
    println!("\nattribution notes:");
    for row in rows {
        println!("  [{}] {}", row.name, row.note);
    }
}

fn write_report(rows: &[Row], env: &Environment, reps: u32, path: &Path) {
    let rows_json: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let s = stats(r);
            serde_json::json!({
                "name": r.name,
                "note": r.note,
                "ours_cmd": r.ours_cmd,
                "theirs_cmd": r.theirs_cmd,
                "ours_ms": r.ours_ms,
                "theirs_ms": r.theirs_ms,
                "ours_median_ms": s.ours_median,
                "ours_min_ms": s.ours_min,
                "theirs_median_ms": s.theirs_median,
                "theirs_min_ms": s.theirs_min,
                "ratio_ours_over_theirs": s.ratio,
                "ours_stdout_bytes": r.ours_bytes,
                "theirs_stdout_bytes": r.theirs_bytes,
                "workload": r.workload.as_ref().map(|w| serde_json::json!({
                    "unit": w.unit,
                    "count": w.count,
                    "bytes": w.bytes,
                })),
            })
        })
        .collect();
    let report = serde_json::json!({
        "generated": iso_now(),
        "purpose": "informational performance differentials vs tshark/dig/curl/nmap (advisory; no gate reads this)",
        "environment": {
            "wrex": env.wrex,
            "tools": env.tools,
            "cpus": env.cpus,
            "kernel": env.kernel,
            "sandboxed": env.sandboxed,
        },
        "method": {
            "reps": reps,
            "warmup_per_side": 1,
            "ordering": "interleaved ours/theirs",
            "stats": "median + min",
            "ratio": "ours/theirs",
        },
        "rows": rows_json,
    });
    std::fs::write(
        path,
        serde_json::to_string_pretty(&report).expect("serialize report") + "\n",
    )
    .expect("write report.json");
}

fn iso_now() -> String {
    Command::new("date")
        .arg("+%Y-%m-%dT%H:%M:%SZ")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

// --- fixtures ---------------------------------------------------------------

/// Every committed corpus frame (the golden dissection corpus the
/// hotpaths bench also rides).
fn corpus_frames() -> Vec<Vec<u8>> {
    let mut frames = Vec::new();
    for corpus in Corpus::load_all() {
        for f in &corpus.frames {
            frames.push(f.bytes.clone());
        }
    }
    frames
}

/// `frames` cycled to `n` (the corpus is a seed set, not an archive —
/// cycling keeps every codec's frame classes in the mix).
fn cycle(frames: &[Vec<u8>], n: usize) -> Vec<Vec<u8>> {
    (0..n).map(|i| frames[i % frames.len()].clone()).collect()
}

/// Write frames as a classic or pcapng pcap; returns the file size.
/// Fixed timestamps — the fixtures are byte-deterministic.
fn write_fixture(path: &Path, frames: &[Vec<u8>], pcapng: bool) -> u64 {
    let ts = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let mut buf = Vec::new();
    if pcapng {
        let mut w = PcapngWriter::new(&mut buf).expect("pcapng writer");
        for f in frames {
            w.write_record(ts, f, 65535).expect("write record");
        }
        w.flush().expect("flush");
    } else {
        let mut w = PcapWriter::new(&mut buf).expect("pcap writer");
        for f in frames {
            w.write_record(ts, f, 65535).expect("write record");
        }
        w.flush().expect("flush");
    }
    std::fs::write(path, &buf).expect("write fixture pcap");
    buf.len() as u64
}

// --- harness-owned servers -------------------------------------------------

/// dnsmasq as a tracked child (the scen-dns recipe, on a free
/// loopback port): answers `wrex.test` from its host-record table.
/// `Drop` kills the child — never a `pkill` (it can race unrelated
/// instances).
struct Dnsmasq {
    child: Child,
    port: u16,
}

impl Dnsmasq {
    fn spawn(dir: &Path) -> Dnsmasq {
        // A free TCP port, then hand it to dnsmasq (bind-interfaces:
        // it listens on UDP and TCP alike).
        let probe = TcpListener::bind("127.0.0.1:0").expect("probe bind");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        let log = std::fs::File::create(dir.join("dnsmasq.log")).expect("dnsmasq log");
        let child = Command::new("dnsmasq")
            .args([
                "--no-daemon",
                "--listen-address=127.0.0.1",
                "--bind-interfaces",
                &format!("--port={port}"),
                "--host-record=wrex.test,192.0.2.10",
                "--pid-file=",
            ])
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap_or_else(|e| panic!("perf-diff: spawn dnsmasq: {e}"));
        // Readiness (the scenario precedent): the row commands would
        // otherwise race the listener.
        std::thread::sleep(Duration::from_millis(500));
        Dnsmasq { child, port }
    }
}

impl Drop for Dnsmasq {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// In-process HTTP/1.1 stub (the http_differential.rs spawn_stub
/// pattern as a harness server): canned keep-alive responses, body by
/// path — both clients hit byte-identical responses, and the server
/// is never the measured bottleneck.
struct HttpStub {
    addr: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
}

impl HttpStub {
    fn spawn() -> HttpStub {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind http stub");
        let addr = listener.local_addr().expect("stub addr");
        listener.set_nonblocking(true).expect("stub nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let accept_stop = stop.clone();
        std::thread::spawn(move || {
            while !accept_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        std::thread::spawn(move || serve_http(stream));
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        HttpStub { addr, stop }
    }
}

impl Drop for HttpStub {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

const HEAD_END: &[u8] = b"\r\n\r\n";

/// Serve keep-alive GETs on one connection until the client closes.
/// `/k1` → 1KiB body, `/m1` → 1MiB body, anything else → 1KiB.
///
/// `TCP_NODELAY` + a single response write: a multi-segment response
/// from a Nagle'd server into a delayed-ACK client stalls ~40ms per
/// exchange (measured: 100 exchanges took 4s for BOTH tools until
/// this fix — the stall was the stub's, not the clients').
fn serve_http(mut stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut head: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    loop {
        // Accumulate a whole request head (GETs carry no body).
        let end = loop {
            if let Some(at) = find_head_end(&head) {
                break at;
            }
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => head.extend_from_slice(&chunk[..n]),
            }
            if head.len() > 64 * 1024 {
                return; // head budget: never a memory hazard
            }
        };
        let first = String::from_utf8_lossy(&head[..end])
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        let path = first.split_whitespace().nth(1).unwrap_or("/");
        let body_len: usize = if path.starts_with("/m1") {
            1024 * 1024
        } else {
            1024
        };
        let mut resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
             Content-Length: {body_len}\r\nConnection: keep-alive\r\n\r\n"
        )
        .into_bytes();
        resp.resize(resp.len() + body_len, 0x42);
        if stream.write_all(&resp).is_err() {
            return;
        }
        // Consume this head; keep any pipelined bytes.
        head.drain(..end + HEAD_END.len());
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(HEAD_END.len()).position(|w| w == HEAD_END)
}

/// The scan farm: loopback listeners whose ports classify open. The
/// accept threads close completed handshakes immediately so the
/// accept queue never fills (a full queue makes the kernel drop the
/// final ACK and scans stall on retransmit — corrupted timing).
struct Farm {
    ports: Vec<u16>,
    stop: Arc<AtomicBool>,
}

impl Farm {
    fn spawn(k: usize) -> Farm {
        let stop = Arc::new(AtomicBool::new(false));
        let mut ports = Vec::with_capacity(k);
        for _ in 0..k {
            let l = TcpListener::bind("127.0.0.1:0").expect("bind farm listener");
            l.set_nonblocking(true).expect("farm nonblocking");
            ports.push(l.local_addr().expect("farm addr").port());
            let accept_stop = stop.clone();
            std::thread::spawn(move || {
                while !accept_stop.load(Ordering::Relaxed) {
                    match l.accept() {
                        Ok((stream, _)) => drop(stream),
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            });
        }
        Farm { ports, stop }
    }
}

impl Drop for Farm {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// `n` ports proven free right now: bind-test ascending candidates,
/// dropping each successful bind (the farm's in-use listeners make
/// any collision bind-fail → skipped, so open and closed sets stay
/// disjoint by construction).
fn free_ports(n: usize, avoid: &[u16]) -> Vec<u16> {
    let out: Vec<u16> = (2048..65500u16)
        .filter(|p| !avoid.contains(p))
        .filter(|p| TcpListener::bind(("127.0.0.1", *p)).is_ok())
        .take(n)
        .collect();
    assert_eq!(out.len(), n, "cannot find {n} free loopback ports");
    out
}

fn port_list(ports: &[u16]) -> String {
    let mut p = ports.to_vec();
    p.sort_unstable();
    p.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    //! The pure helpers (the orchestration is exercised by running the
    //! harness; these are the parts cargo-mutants can reason about).

    use super::*;

    #[test]
    fn median_odd_even_and_ordering() {
        assert_eq!(median(&mut [3.0, 1.0, 2.0]), 2.0, "odd: the middle");
        assert_eq!(
            median(&mut [4.0, 1.0, 3.0, 2.0]),
            2.5,
            "even: the mean of the middle pair"
        );
        assert_eq!(median(&mut [42.0]), 42.0);
    }

    #[test]
    fn verdict_thresholds() {
        assert_eq!(verdict(1.0 / 3.0), "wrex ~3.0x faster");
        assert_eq!(verdict(0.99), "same ballpark");
        assert_eq!(verdict(1.49), "same ballpark");
        assert_eq!(verdict(3.0), "wrex ~3.0x slower");
    }

    #[test]
    fn ms_and_rate_formatting() {
        assert_eq!(fmt_ms(0.156), "0.16ms", "sub-10ms keeps two decimals");
        assert_eq!(fmt_ms(42.0), "42.0ms");
        assert_eq!(fmt_rate(12.5, "ports"), "12.5 ports/s");
        assert_eq!(fmt_rate(2500.0, "frames"), "2.5k frames/s");
    }

    #[test]
    fn head_end_search() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\n"), Some(14));
        assert_eq!(find_head_end(b"no complete head"), None);
        // A CRLR that is not the double: not a terminator.
        assert_eq!(find_head_end(b"\r\n lone"), None);
    }

    #[test]
    fn cycle_repeats_the_seed_frames() {
        let frames = vec![vec![1u8], vec![2], vec![3]];
        let out = cycle(&frames, 7);
        assert_eq!(out.len(), 7);
        assert_eq!(out[4], vec![2], "index 4 wraps to frames[1]");
        assert_eq!(out[6], vec![1]);
    }

    #[test]
    fn port_list_sorts_and_joins() {
        assert_eq!(port_list(&[3000, 2048, 80]), "80,2048,3000");
    }
}
