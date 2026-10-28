//! HP3-b oracle-capture scenarios: foreign-lineage traffic committed as
//! corpus artifacts (the verification doctrine's G5 — one real
//! foreign frame per codec breaks the self-confirmation loop; the SHB
//! BOM and mf-bug classes were both invisible until a foreign capture
//! disagreed).
//!
//! A scenario is a table row: *(foreign server, foreign client
//! invocation, network setup, tool optionality, expected frame
//! classes)* — one declarative harness, not N scripts. The capture
//! container is written by **tcpdump** (keeps `wrex-pcap` continuously
//! tested against the libpcap writer lineage), the client bytes come
//! from **foreign tools** (ping/dig/curl/arping — never wrex), and the
//! imported frames + expectations land under
//! `crates/wrex-test/corpus/scen-<name>/` where every existing gate
//! sweeps them automatically (population, identity sweep, normalize
//! fixed point, reassemble, the tshark differential).
//!
//! Expectations are reviewed against tshark before commit: the harness
//! prints the one-line foreign dissection per frame (the review
//! artifact) and the manifest records the tool versions. Foreign
//! quirks are annotated spec-vs-quirk in the manifest so they never
//! silently become contract.
//!
//! Runs inside the `unshare -Urn` sandbox (CAP_NET_ADMIN + CAP_NET_RAW
//! in the user namespace — veth pairs, tcpdump, arping all work);
//! `cargo xtask corpus-capture` re-execs itself there when needed.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

/// Run one scenario step, dying loudly on failure (a failed setup is
/// never a silent partial capture).
fn sh(dir: &Path, line: &str) {
    let status = Command::new("sh")
        .arg("-ec")
        .arg(line)
        .current_dir(dir)
        .status()
        .unwrap_or_else(|e| panic!("spawn `{line}`: {e}"));
    if !status.success() {
        panic!("scenario setup failed: `{line}` ({status})");
    }
}

fn tool_version(name: &str) -> String {
    Command::new(name)
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().next().map(str::to_string))
        .or_else(|| {
            Command::new(name)
                .arg("-V")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| s.lines().next().map(str::to_string))
        })
        .unwrap_or_else(|| "unknown".into())
}

/// Which tool must exist for a scenario to run (skip-with-notice when
/// absent — the doctrine's tool-optionality rule).
fn have_tool(name: &str) -> bool {
    Command::new("sh")
        .arg("-ec")
        .arg(format!("command -v {name} >/dev/null"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// One tcpdump capture session over `iface` into `out` (the container
/// lineage: pcap written by libpcap, not by wrex).
struct Capture {
    child: Child,
    path: PathBuf,
}

fn start_capture(dir: &Path, iface: &str, out: &str) -> Capture {
    let path = dir.join(out);
    let _ = std::fs::remove_file(&path);
    // Spawned through sh -c 'exec tcpdump …' — the exact context the
    // manual captures ran under: a directly-spawned tcpdump under the
    // rust process in the sandbox never read a packet off the ring
    // ("19 received by filter, 0 captured", while the identical
    // flags from a shell background job captured everything — the
    // libpcap ring-read path is sensitive to the spawn context in
    // this environment).
    let child = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "exec tcpdump --immediate-mode -i {iface} -s 0 -w {}",
            path.display()
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn tcpdump: {e}"));
    // Let tcpdump open the interface and set the filter before the
    // client traffic starts (a race would drop the first frames — the
    // SYN/ARP-of-interest class).
    std::thread::sleep(std::time::Duration::from_millis(400));
    Capture { child, path }
}

impl Capture {
    fn stop(mut self) -> PathBuf {
        // SIGTERM, not SIGKILL: tcpdump's clean-exit path FLUSHES the
        // pcap before exiting — a killed capture loses everything
        // still sitting in the userspace buffer (the first DNS round's
        // 24-byte pcaps: "5 received by filter, 0 captured", diagnosed
        // live). SIGTERM → wait for the clean exit.
        let pid = self.child.id();
        let _ = Command::new("sh")
            .arg("-ec")
            .arg(format!("kill -TERM {pid} 2>/dev/null; true"))
            .status();
        let _ = self.child.wait();
        std::thread::sleep(std::time::Duration::from_millis(150));
        self.path
    }
}

/// The sandbox-internal network every scenario shares: a veth pair
/// (10.9.9.1/2 + fd00::1/2) and loopback, MTU 1500 — MTU-sensitive
/// scenarios fragment on real hardware semantics, not a loopback trick
/// (the doctrine's veth-pair rule).
/// The far-end namespace holder's PID file — the scenarios share one
/// far netns (created in [`net_setup`], killed at [`net_teardown`]).
const FAR_PID_FILE: &str = "/tmp/scen-far.pid";

/// Run `line` inside the FAR network namespace (the veth1 side: the
/// foreign server end). Dies loudly on failure.
fn far(line: &str) {
    let pid = std::fs::read_to_string(FAR_PID_FILE)
        .expect("far namespace running (net_setup)")
        .trim()
        .to_string();
    let status = Command::new("nsenter")
        .arg(format!("--net=/proc/{pid}/ns/net"))
        .arg("sh")
        .arg("-ec")
        .arg(line)
        .status()
        .unwrap_or_else(|e| panic!("spawn nsenter for `{line}`: {e}"));
    if !status.success() {
        panic!("far-side setup failed: `{line}` ({status})");
    }
}

/// The sandbox-internal network every scenario shares: a veth pair
/// SPLIT ACROSS TWO NETWORK NAMESPACES. Both ends in one namespace
/// route local→local traffic through `lo` (the first capture round's
/// 0-frame frag scenarios, diagnosed live: `ip route get 10.9.9.2` →
/// `local … dev lo` — L3 traffic never touched the wire, only
/// arping's L2 requests did). The far end (10.9.9.2 / fd00::2) lives
/// in its own netns held by a sleep process; the near end captures on
/// veth0, and every client packet traverses the pair for real.
fn net_setup() {
    sh(Path::new("/"), "ip link set lo up");
    // The far namespace: a child netns held by a sleeping process
    // (a user-namespace root can unshare further net namespaces —
    // CAP_SYS_ADMIN in the sandbox's own userns). `$!` from the
    // spawning shell IS the holder: unshare execs the inner sh which
    // execs sleep — one PID through the whole exec chain (the first
    // round's pgrep matched a stale holder from a cancelled run).
    let spawned = Command::new("sh")
        .arg("-ec")
        .arg(
            "unshare -n sh -c 'ip link set lo up; exec sleep 600' >/dev/null 2>&1 & \\
             echo $! > /tmp/scen-far.spawned",
        )
        .output()
        .expect("spawn far ns");
    assert!(spawned.status.success(), "far-ns spawn failed");
    std::thread::sleep(std::time::Duration::from_millis(300));
    let far_pid = std::fs::read_to_string("/tmp/scen-far.spawned")
        .expect("the spawning shell wrote the holder pid")
        .trim()
        .to_string();
    assert!(!far_pid.is_empty(), "empty holder pid");
    std::fs::write(FAR_PID_FILE, &far_pid).expect("write far pid");
    sh(
        Path::new("/"),
        "ip link add veth0 type veth peer name veth1",
    );
    sh(Path::new("/"), "ip link set veth0 up mtu 1500");
    sh(
        Path::new("/"),
        &format!("ip link set veth1 netns {far_pid}"),
    );
    sh(Path::new("/"), "ip addr add 10.9.9.1/24 dev veth0");
    // v6: `nodad` — a freshly added address sits in tentative DAD
    // state for ~1s and every ping inside that window is lost.
    sh(Path::new("/"), "ip -6 addr add fd00::1/64 dev veth0 nodad");
    far("ip link set veth1 up mtu 1500");
    far("ip addr add 10.9.9.2/24 dev veth1");
    far("ip -6 addr add fd00::2/64 dev veth1 nodad");
    // Disable veth TX/RX checksum offload on BOTH ends: an offloaded
    // frame crosses the pair with the L4 checksum field left
    // unmaterialized (the receive path validates without filling it),
    // so captured packets carry garbage where the checksum belongs —
    // the classic tcpdump-on-veth "bad checksum" artifact. With the
    // offload off, the kernel writes REAL checksums on the wire and
    // the corpus is wire-honest (diagnosed from the scenario round's
    // 30 false udp/tcp/icmpv6 checksum anomalies — every kernel-SENT
    // frame, regardless of protocol).
    let off = "ethtool -K IFACE tx off rx off tso off gso off gro off >/dev/null 2>&1 || true";
    if have_tool("ethtool") {
        sh(Path::new("/"), &off.replace("IFACE", "veth0"));
        far(&off.replace("IFACE", "veth1"));
    }
}

/// Tear down the far namespace (its holder process) after all
/// scenarios ran.
fn net_teardown() {
    let _ = Command::new("sh")
        .arg("-ec")
        .arg(format!(
            "kill $(cat {FAR_PID_FILE}) 2>/dev/null; rm -f {FAR_PID_FILE} /tmp/scen-far.sh.pid; true"
        ))
        .status();
}

/// A scenario row: name, required tools, the setup (network + optional
/// server spawn), the client invocations whose traffic gets captured,
/// and the manifest annotation (spec-vs-quirk notes included).
struct Scenario {
    name: &'static str,
    tools: &'static [&'static str],
    /// The doc line committed to the manifest.
    about: &'static str,
    /// Network-side setup run INSIDE the sandbox before the capture.
    setup: &'static [&'static str],
    /// Far-namespace setup (the foreign server end) before the
    /// capture — run via nsenter into the far netns.
    far_setup: &'static [&'static str],
    /// Client invocations (foreign lineage) run while capturing.
    clients: &'static [&'static str],
    /// The interface tcpdump listens on.
    iface: &'static str,
    /// spec-vs-quirk annotations for the manifest.
    quirks: &'static str,
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "scen-frag-v4",
        tools: &["ping", "tcpdump"],
        about: "IPv4 fragmentation (the mf bug's own corpus): kernel-carved \
                fragments of a 3000-byte ICMP echo over a 1500-MTU veth — \
                the mf bit at its RFC 791 wire position, from the kernel's \
                own fragmenter.",
        setup: &[],
        far_setup: &[],
        clients: &["ping -4 -n -c 2 -W 1 -M want -s 3000 10.9.9.2"],
        iface: "veth0",
        quirks: "kernel-carved fragments: frag0 carries the full ICMP header; \
                sizes are kernel-MTU-derived (quirk, not contract)",
    },
    Scenario {
        name: "scen-frag-v6",
        tools: &["ping", "tcpdump"],
        about: "IPv6 fragmentation: ping6 -M want fragments a 3000-byte \
                ICMPv6 echo over the veth pair — the frag header + \
                next-header rewrite, real-kernel lineage.",
        setup: &[],
        far_setup: &[],
        clients: &["ping -6 -n -c 2 -W 1 -M want -s 3000 fd00::2"],
        iface: "veth0",
        quirks: "the T18a-recorded v6 pseudo-header convention may show a \
                pointed checksum anomaly on frag0 (upper_start vs RFC 8200 \
                §8.1) — that recorded trigger gets its own pass if so",
    },
    Scenario {
        name: "scen-icmp-echo",
        tools: &["ping", "tcpdump"],
        about: "ICMP echo variety: request/reply pairs over the veth pair \
                (the kernel's own ICMP implementation — type/code/seq \
                conventions).",
        setup: &[],
        far_setup: &[],
        clients: &[
            "ping -4 -n -c 2 -W 1 10.9.9.2",
            "ping -6 -n -c 2 -W 1 fd00::2",
        ],
        iface: "veth0",
        quirks: "icmpv6 echo carries an NDP slla option on-link (quirk of \
                the veth link-local path, not contract)",
    },
    Scenario {
        name: "scen-arp",
        tools: &["arping", "tcpdump"],
        about: "ARP on veth: arping's request/reply exchange (the third \
                lineage beside the arp codec and the io::ndp hand-roll).",
        setup: &[],
        far_setup: &[],
        clients: &["arping -c 2 -w 2 -I veth0 10.9.9.2"],
        iface: "veth0",
        quirks: "arping pads to 46-byte frames (EtherType-era minimum, \
                RFC-permitted)",
    },
    Scenario {
        name: "scen-dns",
        tools: &["dnsmasq", "dig", "tcpdump"],
        about: "Real DNS: dig against dnsmasq (both foreign lineages — the \
                client the resolver world actually uses), A + AAAA \
                questions and replies over UDP 53.",
        setup: &[],
        far_setup: &[
            "dnsmasq --no-daemon --listen-address=10.9.9.2 --bind-interfaces \
             --port=53 --host-record=wrex.test,192.0.2.10 --host-record=v6.wrex.test,fd00::2 \
             --pid-file= >/tmp/scen-dnsmasq.log 2>&1 &",
            "sleep 0.4",
        ],
        clients: &[
            "dig +time=1 +tries=1 @10.9.9.2 wrex.test A",
            "dig +time=1 +tries=1 @10.9.9.2 v6.wrex.test AAAA",
            "dig +time=1 +tries=1 +tcp @10.9.9.2 wrex.test A",
        ],
        iface: "veth0",
        quirks: "dnsmasq answers from its host-record table (A/AAAA both \
                queried over separate exchanges); dig sends EDNS with a \
                4096 udp-size by default (quirk, not contract)",
    },
    Scenario {
        name: "scen-kernel-tcp",
        tools: &["nc", "curl", "tcpdump"],
        about: "Kernel TCP conversations: curl's three-way handshake + \
                HTTP GET + data + orderly close against an nc listener — \
                the kernel's own options (mss/ws/sack/ts) on the wire \
                (the T22 read-side-typing + T30 fingerprint pre-stage).",
        setup: &[],
        far_setup: &["(nc -l -p 8080 >/tmp/scen-nc.out) &", "sleep 0.3"],
        clients: &["curl -s --max-time 2 http://10.9.9.2:8080/hello"],
        iface: "veth0",
        quirks: "the kernel's SYN options set (mss, ws, sackok, ts) varies \
                by sysctl — quirk of the generating kernel, not contract",
    },
];

/// Capture the scenarios (inside the sandbox; see the module doc for
/// the re-exec). `only` restricts to one scenario by name.
pub fn capture(root: &Path, only: Option<&str>) {
    net_setup();
    let mut ran = 0;
    for s in SCENARIOS {
        if let Some(name) = only
            && name != s.name
        {
            continue;
        }
        if !s.tools.iter().all(|t| have_tool(t)) {
            println!(
                "scenario {}: SKIPPED (missing tools: {:?})",
                s.name, s.tools
            );
            continue;
        }
        println!("scenario {}: capturing…", s.name);
        for line in s.setup {
            sh(Path::new("/"), line);
        }
        for line in s.far_setup {
            far(line);
        }
        let cap = start_capture(Path::new("/tmp"), s.iface, &format!("{}.pcap", s.name));
        for client in s.clients {
            let out = Command::new("sh")
                .arg("-ec")
                .arg(client)
                .current_dir("/")
                .output();
            match out {
                Ok(o) => eprintln!(
                    "scenario {}: client `{client}` exit {:?} ({} bytes out)",
                    s.name,
                    o.status.code(),
                    o.stdout.len()
                ),
                Err(e) => panic!("scenario {}: client spawn failed: {e}", s.name),
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(400));
        let pcap = cap.stop();
        eprintln!(
            "scenario {}: pcap {} bytes",
            s.name,
            std::fs::metadata(&pcap).map(|m| m.len()).unwrap_or(0)
        );
        // stop background servers (dnsmasq/nc): everything listening in
        // this sandbox dies with it, but the next scenario wants clean
        // ports.
        let _ = Command::new("sh")
            .arg("-ec")
            .arg("pkill dnsmasq 2>/dev/null; pkill nc 2>/dev/null; true")
            .status();
        let frames = import_with_manifest(root, &pcap, s);
        println!(
            "scenario {}: {frames} frames imported ({} tools: {})",
            s.name,
            s.tools.join(", "),
            tool_version(s.tools[0]),
        );
        review_with_tshark(root, s.name);
        ran += 1;
    }
    net_teardown();
    println!("scenarios captured: {ran}");
    if ran == 0 {
        eprintln!("no scenarios ran (missing tools?)");
    }
}

/// Import the tcpdump capture through the corpus machinery (frames +
/// wrex-generated expected.json + manifest), then REWRITE the manifest
/// with the scenario's declarative row: client commands, tool
/// versions, sysctls, spec-vs-quirk annotations.
fn import_with_manifest(_root: &Path, pcap: &Path, s: &Scenario) -> usize {
    let dir = wrex_test::corpus::import(pcap, s.name).unwrap_or_else(|e| {
        panic!(
            "scenario {}: import failed: {e} (tcpdump wrote nothing?)",
            s.name
        );
    });
    // The scenario row: everything the doctrine's manifest carries.
    let versions: Vec<String> = s
        .tools
        .iter()
        .map(|t| format!("{t}: {}", tool_version(t)))
        .collect();
    let manifest = format!(
        "source_url = \"oracle-capture scenario {name:?} (tcpdump on {iface}; the HP3-b harness)\"\n\
         imported = {today:?}\n\
         start = \"auto\"\n\
         frames = {frames:?}\n\
         \n\
         [scenario]\n\
         about = {about:?}\n\
         clients = {clients:?}\n\
         tools = {tools:?}\n\
         quirks = {quirks:?}\n\
         review = \"tshark eyeball + the map differential over every frame (see xtask/scenarios.rs)\"\n",
        name = s.name,
        iface = s.iface,
        today = chrono_today(),
        frames = frame_names(&dir),
        about = s.about,
        clients = s.clients,
        tools = versions,
        quirks = s.quirks,
    );
    std::fs::write(dir.join("manifest.toml"), manifest).expect("write manifest");
    frame_names(&dir).len()
}

fn frame_names(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir.join("frames")) {
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "bin"))
            .filter_map(|e| {
                e.path()
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
            })
            .collect();
        names.sort();
        out = names;
    }
    out
}

fn chrono_today() -> String {
    // The corpus importer's own date convention (no chrono dep here).
    Command::new("date")
        .arg("+%Y-%m-%d")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

/// The tshark review artifact: one-line dissections of every frame —
/// the human review prints here, the expectations were generated from
/// OUR engine, so the review is the point where the two lineages meet
/// (any disagreement is a bug to file, not a fixture to massage).
fn review_with_tshark(root: &Path, name: &str) {
    if !have_tool("tshark") {
        println!("scenario {name}: review SKIPPED (no tshark)");
        return;
    }
    let dir = corpus_dir(root, name);
    for fname in frame_names(&dir) {
        let bin = dir.join("frames").join(format!("{fname}.bin"));
        let mut pcap = wrex_test::oracle::PcapWriter::new();
        let bytes = std::fs::read(&bin).expect("frame");
        pcap.push_frame(&bytes);
        std::fs::write("/tmp/scen-review.pcap", pcap.finish()).expect("review pcap");
        let out = Command::new("tshark")
            .args(["-r", "/tmp/scen-review.pcap"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default();
        let line = out.lines().next().unwrap_or("(no dissection)");
        println!("  {name}/{fname}: {line}");
    }
}

fn corpus_dir(root: &Path, name: &str) -> PathBuf {
    root.join("crates/wrex-test/corpus").join(name)
}
