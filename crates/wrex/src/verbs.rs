//! Verb implementations: craft / dissect / send / recv / iface / fields,
//! plus the exit-code mapping (0 success, 1 runtime, 2 usage).

use std::io::Write;
use std::time::{Duration, Instant};

use clap::ArgMatches;

use crate::cli::{Cli, Cmd, Common};
use crate::spec::packet_spec_from_matches;
use wrex_core::dissect::dissect;
use wrex_core::encode::EncodeOpts;
use wrex_core::render::{dissect_to_json, dissect_to_jsonl, dissect_to_text};
use wrex_core::value::Value;
use wrex_core::{Filter, FilterError, PacketSpec, Registry, SpecError, encode};
use wrex_io::driver::{Driver, DriverError, RawEthDriver, RawIpDriver};
use wrex_io::iface::IfTable;

pub const MAX_STDIN: usize = 64 * 1024 * 1024;
const DEFAULT_WAIT_TIMEOUT: Duration = Duration::from_secs(2);

/// CLI failure → exit code (see the pinned exit table).
#[derive(Debug)]
pub enum CliError {
    /// Malformed user request → exit 2.
    Usage(Vec<String>),
    /// Runtime/data outcome → exit 1.
    Runtime(String),
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::Usage(_) => 2,
            CliError::Runtime(_) => 1,
        }
    }

    pub fn lines(&self) -> Vec<String> {
        match self {
            CliError::Usage(lines) => lines.clone(),
            CliError::Runtime(line) => vec![line.clone()],
        }
    }
}

impl From<SpecError> for CliError {
    fn from(e: SpecError) -> Self {
        CliError::Usage(vec![e.to_string()])
    }
}

impl From<wrex_core::EncodeError> for CliError {
    fn from(e: wrex_core::EncodeError) -> Self {
        CliError::Usage(vec![e.to_string()])
    }
}

impl From<FilterError> for CliError {
    fn from(e: FilterError) -> Self {
        CliError::Usage(vec![e.to_string()])
    }
}

impl From<DriverError> for CliError {
    fn from(e: DriverError) -> Self {
        CliError::Runtime(e.to_string())
    }
}

fn usage(msg: impl Into<String>) -> CliError {
    CliError::Usage(vec![msg.into()])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Raw,
    Hex,
    Text,
    Json,
    Jsonl,
}

impl Format {
    pub fn parse(common: &Common, default: Format) -> Result<Format, CliError> {
        match common.format.as_deref() {
            None => Ok(default),
            Some("raw") => Ok(Format::Raw),
            Some("hex") => Ok(Format::Hex),
            Some("text") => Ok(Format::Text),
            Some("json") => Ok(Format::Json),
            Some("jsonl") => Ok(Format::Jsonl),
            Some(other) => Err(usage(format!(
                "unknown format `{other}` (raw|hex|text|json|jsonl)"
            ))),
        }
    }

    /// The capture tee: no `--format` means no stdout output at all
    /// (the pcap file is the product; the tee is opt-in).
    pub fn parse_opt(common: &Common) -> Result<Option<Format>, CliError> {
        match common.format.as_deref() {
            None => Ok(None),
            Some(_) => Ok(Some(Format::parse(common, Format::Jsonl)?)),
        }
    }
}

pub fn dispatch(cli: &Cli, matches: &ArgMatches) -> Result<(), CliError> {
    let registry = crate::standard();
    match &cli.cmd {
        Cmd::Craft(args) => craft(&registry, &args.common, sub_matches(matches, "craft")),
        Cmd::Dissect(args) => dissect_cmd(
            &registry,
            &args.common,
            args.start.as_deref().unwrap_or("auto"),
        ),
        Cmd::Send(args) => send(
            &registry,
            &args.common,
            sub_matches(matches, "send"),
            args.count.unwrap_or(1),
            args.interval.as_deref(),
            args.timeout.as_deref(),
            args.wait_reply,
            args.filter.as_deref(),
        ),
        Cmd::Recv(args) => recv(
            &registry,
            &args.common,
            args.count,
            args.timeout.as_deref(),
            args.filter.as_deref(),
            args.promisc,
        ),
        Cmd::Capture(args) => capture(&registry, &args.common, args),
        Cmd::Replay(args) => replay(&registry, &args.common, args),
        Cmd::Scan(args) => scan(&registry, args),
        Cmd::Mut(args) => mut_verb(&registry, &args.common, args),
        Cmd::Fuzz(args) => fuzz(&registry, args),
        Cmd::Http(args) => http(args),
        Cmd::Query(args) => query(&registry, args),
        Cmd::Iface(args) => iface(&args.common, args.name.as_deref()),
        Cmd::Fields(args) => fields_cmd(&registry, &args.common, args.kind.as_deref()),
        Cmd::Completions(args) => {
            let mut cmd = crate::cli::build_cli();
            clap_complete::generate(args.shell, &mut cmd, "wrex", &mut std::io::stdout());
            Ok(())
        }
    }
}

/// The `ArgMatches` of one verb, parsed from the same command.
fn sub_matches<'a>(matches: &'a ArgMatches, name: &str) -> &'a ArgMatches {
    matches
        .subcommand_matches(name)
        .expect("parsed from the same command")
}

fn encode_opts(common: &Common) -> EncodeOpts {
    EncodeOpts {
        autofill: !common.no_autofill,
        strict: common.strict,
        ..Default::default()
    }
}

fn check_strict(common: &Common, encoded: &wrex_core::encode::Encoded) -> Result<(), CliError> {
    if common.strict && !encoded.violations.is_empty() {
        let mut lines = Vec::new();
        for v in &encoded.violations {
            lines.push(format!("{}: {}", v.path, v.message));
        }
        lines.push("craft/send --strict: packet failed validation".into());
        return Err(CliError::Usage(lines));
    }
    Ok(())
}

fn write_stdout(bytes: &[u8]) -> Result<(), CliError> {
    let mut out = std::io::stdout().lock();
    out.write_all(bytes)
        .map_err(|e| CliError::Runtime(format!("stdout: {e}")))?;
    out.flush()
        .map_err(|e| CliError::Runtime(format!("stdout: {e}")))?;
    Ok(())
}

// --- craft -------------------------------------------------------------------

fn craft(registry: &Registry, common: &Common, matches: &ArgMatches) -> Result<(), CliError> {
    let spec = packet_spec_from_matches(registry, matches)?;
    let format = Format::parse(common, Format::Raw)?;
    let encoded = encode(registry, &spec, &encode_opts(common))?;
    check_strict(common, &encoded)?;
    match format {
        Format::Raw => write_stdout(&encoded.bytes)?,
        Format::Hex => {
            let mut line = hex::encode(&encoded.bytes);
            line.push('\n');
            write_stdout(line.as_bytes())?;
        }
        Format::Text => {
            let mut out = String::new();
            render_spec_text(&spec, &mut out);
            write_stdout(out.as_bytes())?;
        }
        Format::Json | Format::Jsonl => {
            let json =
                serde_json::to_string(&spec).map_err(|e| usage(format!("spec json: {e}")))?;
            let mut line = json;
            line.push('\n');
            write_stdout(line.as_bytes())?;
        }
    }
    Ok(())
}

/// `text` rendering of a spec: kind lines with indented field values.
fn render_spec_text(spec: &PacketSpec, out: &mut String) {
    for layer in &spec.layers {
        out.push_str(&format!("{}\n", layer.kind));
        for (k, v) in &layer.fields {
            let rendered = match v {
                Value::Bytes(b) => hex::encode(b),
                other => crate::spec::render_value_flat(other),
            };
            out.push_str(&format!("  {k}: {rendered}\n"));
        }
    }
    if let Some(p) = &spec.payload {
        let rendered = match p {
            Value::Bytes(b) => hex::encode(b),
            other => crate::spec::render_value_flat(other),
        };
        out.push_str(&format!("payload: {rendered}\n"));
    }
}

// --- dissect -----------------------------------------------------------------

fn read_stdin_capped() -> Result<Vec<u8>, CliError> {
    use std::io::Read;
    let mut buf = Vec::new();
    let mut stdin = std::io::stdin().lock();
    let mut chunk = [0u8; 65536];
    loop {
        let n = stdin
            .read(&mut chunk)
            .map_err(|e| CliError::Runtime(format!("stdin: {e}")))?;
        if n == 0 {
            break;
        }
        if buf.len() + n > MAX_STDIN {
            return Err(usage(format!("input exceeds the {} byte cap", MAX_STDIN)));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    if buf.is_empty() {
        return Err(usage("empty input (nothing on stdin)"));
    }
    Ok(buf)
}

fn dissect_cmd(registry: &Registry, common: &Common, start: &str) -> Result<(), CliError> {
    let format = Format::parse(common, Format::Text)?;
    // Validate the start kind upfront (auto passes through).
    if start != "auto" && registry.get(start).is_none() {
        return Err(usage(format!(
            "unknown start `{start}` (auto or {})",
            registry.kinds().join(", ")
        )));
    }
    let input = read_stdin_capped()?;
    match format {
        // Byte-transparent passthrough (raw pipeline checks).
        Format::Raw => {
            write_stdout(&input)?;
            return Ok(());
        }
        Format::Hex => {
            let mut out = hex::encode(&input);
            out.push('\n');
            write_stdout(out.as_bytes())?;
            return Ok(());
        }
        _ => {}
    }
    let packet = dissect(registry, &input, start);
    match format {
        Format::Text => {
            let mut out = dissect_to_text(&packet);
            out.push('\n');
            write_stdout(out.as_bytes())?;
        }
        Format::Json => {
            let mut out = serde_json::to_string_pretty(&dissect_to_json(&packet))
                .map_err(|e| usage(format!("json: {e}")))?;
            out.push('\n');
            write_stdout(out.as_bytes())?;
        }
        Format::Jsonl => {
            let mut out = dissect_to_jsonl(&packet);
            out.push('\n');
            write_stdout(out.as_bytes())?;
        }
        Format::Raw | Format::Hex => unreachable!("handled above"),
    }
    if common.strict && !packet.anomalies.is_empty() {
        let mut lines: Vec<String> = packet
            .anomalies
            .iter()
            .map(|a| format!("{}: {}", a.path, a.message))
            .collect();
        lines.push(format!(
            "dissect --strict: {} anomal{} found",
            packet.anomalies.len(),
            if packet.anomalies.len() == 1 {
                "y"
            } else {
                "ies"
            }
        ));
        return Err(CliError::Runtime(lines.join("\n")));
    }
    Ok(())
}

// --- iface / fields ----------------------------------------------------------

fn iface(common: &Common, name: Option<&str>) -> Result<(), CliError> {
    let format = Format::parse(common, Format::Text)?;
    let table = IfTable::from_system()
        .map_err(|e| CliError::Runtime(format!("reading interfaces: {e}")))?;
    let entries: Vec<wrex_io::IfEntry> = match name {
        Some(n) => {
            let e = table.get(n).cloned().ok_or_else(|| {
                CliError::Runtime(format!(
                    "unknown iface `{n}` (available: {})",
                    table.names().join(", ")
                ))
            })?;
            vec![e]
        }
        None => table.entries().cloned().collect(),
    };
    match format {
        Format::Json | Format::Jsonl => {
            let json = serde_json::to_string(&entries).map_err(|e| usage(format!("json: {e}")))?;
            let mut out = json;
            out.push('\n');
            write_stdout(out.as_bytes())?;
        }
        _ => {
            let mut out = String::new();
            out.push_str("name  mac                 mtu      up  ipv4\n");
            for e in &entries {
                let ip = if e.ipv4s.is_empty() {
                    "-".to_string()
                } else {
                    e.ipv4s
                        .iter()
                        .map(std::net::Ipv4Addr::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                };
                out.push_str(&format!(
                    "{:<6}{:<20}{:<9}{:<4}{}\n",
                    e.name,
                    wrex_core::mac_string(e.mac),
                    e.mtu,
                    if e.up { "yes" } else { "no" },
                    ip
                ));
            }
            write_stdout(out.as_bytes())?;
        }
    }
    Ok(())
}

fn fields_cmd(registry: &Registry, common: &Common, kind: Option<&str>) -> Result<(), CliError> {
    let format = Format::parse(common, Format::Text)?;
    let kinds: Vec<&'static str> = match kind {
        Some(k) => {
            let canonical = if k == "ip" { "ipv4" } else { k };
            match registry.get(canonical) {
                Some(c) => vec![c.schema().kind],
                None => {
                    return Err(usage(format!(
                        "unknown layer `{k}` (known: {})",
                        registry.kinds().join(", ")
                    )));
                }
            }
        }
        None => registry.kinds().to_vec(),
    };
    match format {
        Format::Json | Format::Jsonl => {
            let mut arr = serde_json::Map::new();
            for &k in &kinds {
                let schema = registry.schema(k).unwrap();
                let fields: Vec<serde_json::Value> = schema
                    .fields
                    .iter()
                    .map(|f| {
                        serde_json::json!({
                            "name": f.name,
                            "kind": f.kind.type_name(),
                            "bit_names": f.bit_names,
                            "default": crate::spec::render_value_flat(&f.default),
                            "required": f.required,
                            "doc": f.doc,
                        })
                    })
                    .collect();
                let records: Vec<serde_json::Value> = schema
                    .records
                    .iter()
                    .map(|rec| {
                        let fields: Vec<serde_json::Value> = rec
                            .fields
                            .iter()
                            .map(|f| {
                                serde_json::json!({
                                    "name": f.name,
                                    "kind": f.kind.type_name(),
                                    "default": crate::spec::render_value_flat(&f.default),
                                    "doc": f.doc,
                                })
                            })
                            .collect();
                        serde_json::json!({
                            "name": rec.name,
                            "settable": rec.settable,
                            "max": rec.max,
                            "doc": rec.doc,
                            "fields": fields,
                        })
                    })
                    .collect();
                arr.insert(
                    k.to_string(),
                    serde_json::json!({
                        "rank": schema.rank,
                        "doc": schema.doc,
                        "fields": fields,
                        "records": records
                    }),
                );
            }
            let mut out = serde_json::to_string(&serde_json::Value::Object(arr))
                .map_err(|e| usage(format!("json: {e}")))?;
            out.push('\n');
            write_stdout(out.as_bytes())?;
        }
        _ => {
            let mut out = String::new();
            for &k in &kinds {
                let schema = registry.schema(k).unwrap();
                out.push_str(&format!("{k} (rank {})\n", schema.rank));
                if !schema.doc.is_empty() {
                    out.push_str(&format!("  {}\n", schema.doc));
                }
                for f in schema.fields {
                    let bits = if f.bit_names.is_empty() {
                        String::new()
                    } else {
                        format!(" bits=[{}]", f.bit_names.join(","))
                    };
                    out.push_str(&format!(
                        "  {:<12}{:<8}default={}{}{}\n",
                        f.name,
                        f.kind.type_name(),
                        crate::spec::render_value_flat(&f.default),
                        if f.required { " required" } else { "" },
                        bits
                    ));
                    if !f.doc.is_empty() {
                        out.push_str(&format!("    {}\n", f.doc));
                    }
                }
                for rec in schema.records {
                    let setting = if rec.settable {
                        match rec.max {
                            Some(n) => format!("settable, max {n}"),
                            None => "settable".to_string(),
                        }
                    } else {
                        "dissect-only".to_string()
                    };
                    out.push_str(&format!("  record {} ({})\n", rec.name, setting));
                    if !rec.doc.is_empty() {
                        out.push_str(&format!("    {}\n", rec.doc));
                    }
                    for f in rec.fields {
                        out.push_str(&format!(
                            "    {:<12}{:<8}default={}\n",
                            f.name,
                            f.kind.type_name(),
                            crate::spec::render_value_flat(&f.default)
                        ));
                        if !f.doc.is_empty() {
                            out.push_str(&format!("      {}\n", f.doc));
                        }
                    }
                    out.push_str(&format!(
                        "    paths: {}.0.{}, {}.1.{}, …\n",
                        rec.name,
                        rec.fields.first().map(|f| f.name).unwrap_or("field"),
                        rec.name,
                        rec.fields.first().map(|f| f.name).unwrap_or("field")
                    ));
                }
            }
            write_stdout(out.as_bytes())?;
        }
    }
    Ok(())
}

// --- send / recv --------------------------------------------------------------

fn duration_arg(raw: Option<&str>) -> Result<Option<Duration>, CliError> {
    match raw {
        None => Ok(None),
        Some(r) => wrex_core::parse_duration(r)
            .map(Some)
            .map_err(|e| usage(format!("bad duration `{r}`: {e}"))),
    }
}

/// CLI-side autofill: eth.src ← interface MAC, ipv4.src ← interface IPv4.
fn apply_iface_autofill(spec: &mut PacketSpec, entry: &wrex_io::IfEntry, autofill: bool) {
    if !autofill {
        return;
    }
    for layer in &mut spec.layers {
        match layer.kind {
            "eth" => {
                if !layer.fields.contains_key("src") {
                    layer
                        .fields
                        .insert("src".to_string(), Value::Mac(entry.mac));
                }
            }
            "ipv4" => {
                if !layer.fields.contains_key("src")
                    && let Some(ip) = entry.ipv4s.first()
                {
                    layer.fields.insert("src".to_string(), Value::Ipv4(*ip));
                }
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn send(
    registry: &Registry,
    common: &Common,
    matches: &ArgMatches,
    count: u64,
    interval_raw: Option<&str>,
    timeout_raw: Option<&str>,
    wait_reply: bool,
    filter_raw: Option<&str>,
) -> Result<(), CliError> {
    use std::io::IsTerminal;
    let Some(iface) = common.iface.as_deref() else {
        return Err(usage("send requires -i/--iface"));
    };
    let interval = duration_arg(interval_raw)?;
    let timeout = duration_arg(timeout_raw)?;
    let table = IfTable::from_system()
        .map_err(|e| CliError::Runtime(format!("reading interfaces: {e}")))?;
    let entry = table
        .get(iface)
        .ok_or_else(|| {
            CliError::Runtime(format!(
                "unknown iface `{iface}` (available: {})",
                table.names().join(", ")
            ))
        })?
        .clone();

    let mut driver = RawEthDriver::open(iface, false, &table)?;

    // Frame source: field flags (--layer/--payload/--<kind>-<field>), or
    // raw stdin bytes (byte-transparent). Presence test against the same
    // registry-derived arg set clap parsed.
    let has_field_args = crate::cli::field_args(registry)
        .iter()
        .any(|arg| matches.contains_id(arg.get_id().as_str()));
    let frame: Vec<u8> = if has_field_args {
        let mut spec = packet_spec_from_matches(registry, matches)?;
        if spec.layers.first().map(|l| l.kind) != Some("eth") {
            return Err(usage(
                "AF_PACKET send requires an eth (link-layer) stack start",
            ));
        }
        apply_iface_autofill(&mut spec, &entry, !common.no_autofill);
        let encoded = encode(registry, &spec, &encode_opts(common))?;
        check_strict(common, &encoded)?;
        encoded.bytes.to_vec()
    } else if !std::io::stdin().is_terminal() {
        read_stdin_capped()?
    } else {
        return Err(usage(
            "send needs field flags (or piped stdin for raw bytes)",
        ));
    };

    for i in 0..count {
        driver
            .send(&frame)
            .map_err(|e| CliError::Runtime(format!("send: {e}")))?;
        if let Some(d) = interval
            && i + 1 < count
        {
            std::thread::sleep(d);
        }
    }

    if wait_reply {
        let filter = match filter_raw {
            Some(f) => Some(Filter::parse(registry, f)?),
            None => None,
        };
        let deadline = Instant::now() + timeout.unwrap_or(DEFAULT_WAIT_TIMEOUT);
        loop {
            if Instant::now() >= deadline {
                return Err(CliError::Runtime(format!(
                    "no reply within {}",
                    hum_duration(timeout.unwrap_or(DEFAULT_WAIT_TIMEOUT))
                )));
            }
            let Some(fr) = driver
                .recv(deadline)
                .map_err(|e| CliError::Runtime(format!("recv: {e}")))?
            else {
                return Err(CliError::Runtime(format!(
                    "no reply within {}",
                    hum_duration(timeout.unwrap_or(DEFAULT_WAIT_TIMEOUT))
                )));
            };
            let packet = dissect(registry, &fr.bytes, "auto");
            let matched = filter.as_ref().map(|f| f.matches(&packet)).unwrap_or(true);
            if !matched {
                continue;
            }
            let mut out = dissect_to_text(&packet);
            out.push('\n');
            write_stdout(out.as_bytes())?;
            return Ok(());
        }
    }
    Ok(())
}

fn hum_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms >= 1000 {
        format!("{:.1}s", d.as_secs_f64())
    } else {
        format!("{ms}ms")
    }
}

fn recv(
    registry: &Registry,
    common: &Common,
    count: Option<u64>,
    timeout_raw: Option<&str>,
    filter_raw: Option<&str>,
    promisc: bool,
) -> Result<(), CliError> {
    let Some(iface) = common.iface.as_deref() else {
        return Err(usage("recv requires -i/--iface"));
    };
    let format = Format::parse(common, Format::Jsonl)?;
    let timeout = duration_arg(timeout_raw)?;
    let filter = match filter_raw {
        Some(f) => Some(Filter::parse(registry, f)?),
        None => None,
    };
    let table = IfTable::from_system()
        .map_err(|e| CliError::Runtime(format!("reading interfaces: {e}")))?;
    let mut driver = RawEthDriver::open(iface, promisc, &table)?;
    let mut seen: u64 = 0;
    let deadline = timeout.map(|d| Instant::now() + d);
    loop {
        let next_deadline = deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));
        let Some(frame) = driver
            .recv(next_deadline)
            .map_err(|e| CliError::Runtime(format!("recv: {e}")))?
        else {
            // Timeout end → success (exit 0).
            return Ok(());
        };
        let packet = dissect(registry, &frame.bytes, "auto");
        if let Some(f) = &filter
            && !f.matches(&packet)
        {
            continue;
        }
        seen += 1;
        match format {
            Format::Jsonl => {
                let mut line = dissect_to_jsonl(&packet);
                line.push('\n');
                write_stdout(line.as_bytes())?;
            }
            Format::Raw => {
                write_stdout(&frame.bytes)?;
            }
            Format::Text => {
                let mut out = dissect_to_text(&packet);
                out.push('\n');
                write_stdout(out.as_bytes())?;
            }
            Format::Json => {
                let mut out = serde_json::to_string(&dissect_to_json(&packet))
                    .map_err(|e| usage(format!("json: {e}")))?;
                out.push('\n');
                write_stdout(out.as_bytes())?;
            }
            Format::Hex => {
                let mut line = hex::encode(&frame.bytes);
                line.push('\n');
                write_stdout(line.as_bytes())?;
            }
        }
        if let Some(c) = count
            && seen >= c
        {
            return Ok(());
        }
    }
}

// --- capture / replay (tranche 5) ---------------------------------------------

/// Per-frame output in the shared `--format` family (recv, the capture
/// tee and offline replay all print the same shapes).
fn print_frame(
    format: Format,
    packet: &wrex_core::dissect::DissectedPacket,
    raw: &[u8],
) -> Result<(), CliError> {
    match format {
        Format::Jsonl => {
            let mut line = dissect_to_jsonl(packet);
            line.push('\n');
            write_stdout(line.as_bytes())?;
        }
        Format::Raw => {
            write_stdout(raw)?;
        }
        Format::Text => {
            let mut out = dissect_to_text(packet);
            out.push('\n');
            write_stdout(out.as_bytes())?;
        }
        Format::Json => {
            let mut out = serde_json::to_string(&dissect_to_json(packet))
                .map_err(|e| usage(format!("json: {e}")))?;
            out.push('\n');
            write_stdout(out.as_bytes())?;
        }
        Format::Hex => {
            let mut line = hex::encode(raw);
            line.push('\n');
            write_stdout(line.as_bytes())?;
        }
    }
    Ok(())
}

/// Default stored bytes per capture record (`--snaplen` overrides).
const CAPTURE_DEFAULT_SNAPLEN: usize = 65535;

/// `wrex capture`: AF_PACKET recv loop into a classic pcap file, with an
/// optional `--format` tee to stdout (the same per-frame shapes as
/// recv). Stop conditions and exit codes mirror recv: count/timeout → 0.
fn capture(
    registry: &Registry,
    common: &Common,
    args: &crate::cli::CaptureArgs,
) -> Result<(), CliError> {
    let Some(iface) = common.iface.as_deref() else {
        return Err(usage("capture requires -i/--iface"));
    };
    // The tee is opt-in: no --format means the pcap file is the product.
    let tee = Format::parse_opt(common)?;
    let timeout = duration_arg(args.timeout.as_deref())?;
    let filter = match args.filter.as_deref() {
        Some(f) => Some(Filter::parse(registry, f)?),
        None => None,
    };
    let snaplen = args.snaplen.unwrap_or(CAPTURE_DEFAULT_SNAPLEN);

    let table = IfTable::from_system()
        .map_err(|e| CliError::Runtime(format!("reading interfaces: {e}")))?;
    let mut driver = RawEthDriver::open(iface, args.promisc, &table)?;
    let file = std::fs::File::create(&args.write)
        .map_err(|e| CliError::Runtime(format!("capture: cannot create `{}`: {e}", args.write)))?;
    let mut writer = wrex_pcap::PcapWriter::new(std::io::BufWriter::new(file))
        .map_err(|e| CliError::Runtime(format!("capture: {}: {e}", args.write)))?;

    let mut seen: u64 = 0;
    let deadline = timeout.map(|d| Instant::now() + d);
    loop {
        let next_deadline = deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));
        let Some(frame) = driver
            .recv(next_deadline)
            .map_err(|e| CliError::Runtime(format!("recv: {e}")))?
        else {
            // Timeout end → success (exit 0), pcap valid as-is.
            writer
                .flush()
                .map_err(|e| CliError::Runtime(format!("capture: {}: {e}", args.write)))?;
            return Ok(());
        };
        let packet = dissect(registry, &frame.bytes, "auto");
        if let Some(f) = &filter
            && !f.matches(&packet)
        {
            continue;
        }
        writer
            .write_record(frame.ts, &frame.bytes, snaplen)
            .map_err(|e| CliError::Runtime(format!("capture: {}: {e}", args.write)))?;
        if let Some(fmt) = tee {
            print_frame(fmt, &packet, &frame.bytes)?;
        }
        seen += 1;
        if let Some(c) = args.count
            && seen >= c
        {
            writer
                .flush()
                .map_err(|e| CliError::Runtime(format!("capture: {}: {e}", args.write)))?;
            return Ok(());
        }
    }
}

/// A replay-eligible frame: the captured bytes, their dissection and
/// the capture timestamp (send-mode pacing).
struct ReplayFrame {
    ts: std::time::SystemTime,
    bytes: Vec<u8>,
    packet: wrex_core::dissect::DissectedPacket,
}

/// Seeded step: base pacing +/- jitter, clamped non-negative.
fn jittered_step(base: Duration, jitter: Duration, rng: &mut wrex_io::Rng) -> Duration {
    let secs = base.as_secs_f64() + rng.jitter_secs(jitter);
    if secs <= 0.0 {
        Duration::ZERO
    } else {
        Duration::from_secs_f64(secs)
    }
}

/// `wrex replay`: offline dissection (default) or verbatim re-send on
/// an interface (`-i`). Pacing: capture-delta by default, or the T2
/// timing vocabulary (`--rate`/`--interval` override, seeded `--jitter`).
fn replay(
    registry: &Registry,
    common: &Common,
    args: &crate::cli::ReplayArgs,
) -> Result<(), CliError> {
    // Grammar gates before any file/socket work (usage → exit 2).
    if args.rate.is_some() && args.interval.is_some() {
        return Err(usage(
            "replay: --rate and --interval are mutually exclusive",
        ));
    }
    if args.jitter.is_some() && common.iface.is_none() {
        return Err(usage("replay: --jitter is send-mode pacing (-i IFACE)"));
    }
    if args.rate.is_some() && common.iface.is_none() {
        return Err(usage("replay: --rate is send-mode pacing (-i IFACE)"));
    }
    if args.interval.is_some() && common.iface.is_none() {
        return Err(usage("replay: --interval is send-mode pacing (-i IFACE)"));
    }

    // Read + dissect: filter/count apply to both modes identically so
    // the offline print and the wire send see the same frames.
    let pcap_bytes = std::fs::read(&args.pcap)
        .map_err(|e| CliError::Runtime(format!("replay: cannot read `{}`: {e}", args.pcap)))?;
    let file = wrex_pcap::read(&pcap_bytes)
        .map_err(|e| CliError::Runtime(format!("replay: `{}`: {e}", args.pcap)))?;
    let filter = match args.filter.as_deref() {
        Some(f) => Some(Filter::parse(registry, f)?),
        None => None,
    };
    let mut frames: Vec<ReplayFrame> = Vec::with_capacity(file.records.len());
    for rec in &file.records {
        let packet = dissect(registry, &rec.bytes, "auto");
        if let Some(f) = &filter
            && !f.matches(&packet)
        {
            continue;
        }
        frames.push(ReplayFrame {
            ts: rec.ts,
            bytes: rec.bytes.clone(),
            packet,
        });
    }
    if let Some(c) = args.count {
        frames.truncate(c as usize);
    }

    let Some(iface) = common.iface.as_deref() else {
        // Offline mode: dissect-and-print (jsonl default, like recv).
        let format = Format::parse(common, Format::Jsonl)?;
        for f in &frames {
            print_frame(format, &f.packet, &f.bytes)?;
        }
        return Ok(());
    };

    // Send mode: verbatim re-send with pacing.
    let format = Format::parse_opt(common)?;
    let jitter = duration_arg(args.jitter.as_deref())?.unwrap_or(Duration::ZERO);
    let seed = args.seed.unwrap_or_else(time_seed);
    let mut rng = wrex_io::Rng::new(seed);

    let table = IfTable::from_system()
        .map_err(|e| CliError::Runtime(format!("reading interfaces: {e}")))?;
    let mut driver = RawEthDriver::open(iface, false, &table)?;

    // Pace schedule: fixed interval (--rate/--interval) or the original
    // capture deltas; jitter is seeded on top in both shapes.
    let mut prev_ts: Option<std::time::SystemTime> = None;
    for (i, f) in frames.iter().enumerate() {
        let base = if args.rate.is_some() || args.interval.is_some() {
            let step = match (args.rate, args.interval.as_deref()) {
                (Some(0), _) => Duration::ZERO,
                (Some(r), _) => Duration::from_secs_f64(1.0 / r as f64),
                (None, Some(raw)) => duration_arg(Some(raw))?.unwrap_or(Duration::ZERO),
                (None, None) => unreachable!("gated above"),
            };
            if i == 0 { Duration::ZERO } else { step }
        } else if i == 0 {
            Duration::ZERO
        } else {
            // Capture delta (ts[i] - ts[i-1]); before-epoch / non-monotonic
            // captures clamp to an immediate send.
            match prev_ts {
                Some(prev) => f.ts.duration_since(prev).unwrap_or(Duration::ZERO),
                None => Duration::ZERO,
            }
        };
        prev_ts = Some(f.ts);
        let sleep = jittered_step(base, jitter, &mut rng);
        if !sleep.is_zero() {
            std::thread::sleep(sleep);
        }
        driver
            .send(&f.bytes)
            .map_err(|e| CliError::Runtime(format!("replay: send: {e}")))?;
        if let Some(fmt) = format {
            print_frame(fmt, &f.packet, &f.bytes)?;
        }
    }
    Ok(())
}

// --- scan ----------------------------------------------------------------------

/// Scan defaults (mirror `wrex_scan`'s; spelled here for the help text).
const SCAN_DEFAULT_TIMEOUT: Duration = Duration::from_secs(1);

/// Time-derived seed (pin reproducibility with `--seed`).
fn time_seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ (u64::from(std::process::id()) << 32)
}

/// `wrex scan`: build a [`wrex_scan::ScanSession`] over a
/// [`RawIpDriver`] and run it under the sans-IO runtime loop.
fn scan(registry: &Registry, args: &crate::cli::ScanArgs) -> Result<(), CliError> {
    use wrex_scan::{DEFAULT_RATE, ScanConfig, ScanMode};

    let common = &args.common;
    let Some(iface) = common.iface.as_deref() else {
        return Err(usage("scan requires -i/--iface"));
    };
    let mode = ScanMode::parse(args.mode.as_deref()).map_err(usage)?;
    // Registry gating up front (usage → exit 2).
    for kind in mode.needs() {
        if registry.get(kind).is_none() {
            return Err(usage(format!(
                "{kind} layer not registered (registered: {})",
                registry.kinds().join(", ")
            )));
        }
    }

    // Pacing: --rate and --interval are mutually exclusive; default rate
    // 100/s (`--rate 0` / `--interval 0` = uncapped burst).
    let interval = match (args.rate, args.interval.as_deref()) {
        (Some(_), Some(_)) => {
            return Err(usage("scan: --rate and --interval are mutually exclusive"));
        }
        (Some(rate), None) => {
            if rate == 0 {
                Duration::ZERO
            } else {
                Duration::from_secs_f64(1.0 / rate as f64)
            }
        }
        (None, Some(raw)) => {
            let d = duration_arg(Some(raw))?;
            d.unwrap_or(Duration::ZERO)
        }
        (None, None) => Duration::from_secs_f64(1.0 / DEFAULT_RATE as f64),
    };
    let jitter = duration_arg(args.jitter.as_deref())?.unwrap_or(Duration::ZERO);
    let timeout = duration_arg(args.timeout.as_deref())?.unwrap_or(SCAN_DEFAULT_TIMEOUT);
    let retries = args.retries.unwrap_or(1);
    let concurrent = args.concurrent.unwrap_or(256);
    let seed = args.seed.unwrap_or_else(time_seed);

    let cfg = ScanConfig::build(
        mode,
        &args.targets,
        args.ports.as_deref(),
        interval,
        jitter,
        seed,
        retries,
        timeout,
        concurrent,
    )
    .map_err(|e| usage(format!("scan: {e}")))?;

    // Formats: text (default) / json (pretty array) / jsonl (per line);
    // raw/hex carry no scan results → reject before doing any work.
    let format = Format::parse(common, Format::Text)?;
    if matches!(format, Format::Raw | Format::Hex) {
        return Err(usage(
            "scan --format supports text|json|jsonl (raw/hex carry no scan results)",
        ));
    }

    // Interface + source address + driver (family follows the targets:
    // kernel-routed v4 via IP_HDRINCL, AF_PACKET frame injection for v6).
    let table = IfTable::from_system()
        .map_err(|e| CliError::Runtime(format!("reading interfaces: {e}")))?;
    let entry = table
        .get(iface)
        .ok_or_else(|| {
            CliError::Runtime(format!(
                "unknown iface `{iface}` (available: {})",
                table.names().join(", ")
            ))
        })?
        .clone();
    let src = match cfg.family() {
        wrex_scan::Family::V4 => entry
            .ipv4s
            .first()
            .copied()
            .map(wrex_scan::ScanAddr::V4)
            .ok_or_else(|| {
                CliError::Runtime(format!("iface `{iface}` has no IPv4 source address"))
            })?,
        wrex_scan::Family::V6 => entry
            .ipv6s
            .first()
            .copied()
            .map(wrex_scan::ScanAddr::V6)
            .ok_or_else(|| {
                CliError::Runtime(format!("iface `{iface}` has no IPv6 source address"))
            })?,
    };

    let mut session =
        wrex_scan::ScanSession::new(registry, cfg, src, Instant::now()).map_err(usage)?;
    let results = match src {
        wrex_scan::ScanAddr::V4(_) => {
            let mut driver = RawIpDriver::open(iface, &table)?;
            wrex_session::run(&mut session, &mut driver, &wrex_io::SystemClock)
                .map_err(|e| CliError::Runtime(format!("scan: {e}")))?
        }
        wrex_scan::ScanAddr::V6(_) => {
            let mut driver = wrex_io::RawIpv6Driver::open(iface, &table)?;
            wrex_session::run(&mut session, &mut driver, &wrex_io::SystemClock)
                .map_err(|e| CliError::Runtime(format!("scan: {e}")))?
        }
    };

    let mut out = String::new();
    match format {
        Format::Json => {
            let json = serde_json::to_string_pretty(&results)
                .map_err(|e| CliError::Runtime(format!("json: {e}")))?;
            out.push_str(&json);
            out.push('\n');
        }
        Format::Text => {
            for r in &results {
                out.push_str(&r.text_line());
                if let Some(rtt) = r.rtt_hum() {
                    out.push_str(&format!("  ({rtt})"));
                }
                out.push('\n');
            }
        }
        Format::Jsonl => {
            for r in &results {
                let json = serde_json::to_string(r)
                    .map_err(|e| CliError::Runtime(format!("json: {e}")))?;
                out.push_str(&json);
                out.push('\n');
            }
        }
        Format::Raw | Format::Hex => unreachable!("rejected above"),
    }
    write_stdout(out.as_bytes())?;
    // Scan completed → exit 0 regardless of findings.
    Ok(())
}

// --- mut / fuzz (tranche 6) ----------------------------------------------------

/// Default mutants per `wrex mut` invocation.
const MUT_DEFAULT_COUNT: u64 = 8;
/// Default stored bytes per mut pcap record (matches capture).
const MUT_DEFAULT_SNAPLEN: usize = 65535;

/// `wrex mut`: seeded, dissect-aware frame mutation → stdout (and
/// optionally a pcap). Seeds: positional hex frames, `-r` pcaps and
/// raw stdin; grammar errors are usage (exit 2) before any output.
fn mut_verb(
    registry: &Registry,
    common: &Common,
    args: &crate::cli::MutArgs,
) -> Result<(), CliError> {
    use wrex_mut::{Mutator, Strategy};

    let format = Format::parse(common, Format::Hex)?;
    let strategy = Strategy::parse(args.strategy.as_deref()).map_err(usage)?;
    let count = args.count.unwrap_or(MUT_DEFAULT_COUNT);
    let seed = args.seed.unwrap_or_else(time_seed);

    // Seed frames: positional hex, then every -r pcap record, then
    // raw stdin (when piped). Empty seed set → usage error.
    let mut seeds: Vec<Vec<u8>> = Vec::new();
    for raw in &args.frames {
        let bytes = wrex_core::value::parse_hex_bytes(raw)
            .map_err(|e| usage(format!("bad seed frame `{raw}`: {e}")))?;
        if bytes.is_empty() {
            return Err(usage(format!("empty seed frame `{raw}`")));
        }
        seeds.push(bytes);
    }
    for path in &args.read {
        let pcap_bytes = std::fs::read(path)
            .map_err(|e| CliError::Runtime(format!("mut: cannot read `{path}`: {e}")))?;
        let file = wrex_pcap::read(&pcap_bytes)
            .map_err(|e| CliError::Runtime(format!("mut: `{path}`: {e}")))?;
        for rec in &file.records {
            if !rec.bytes.is_empty() {
                seeds.push(rec.bytes.clone());
            }
        }
    }
    {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() && args.frames.is_empty() && args.read.is_empty() {
            seeds.push(read_stdin_capped()?);
        }
    }

    let mut mutator = Mutator::new(registry, seeds, strategy, seed).map_err(usage)?;
    let mut writer = match &args.write {
        Some(path) => {
            let file = std::fs::File::create(path)
                .map_err(|e| CliError::Runtime(format!("mut: cannot create `{path}`: {e}")))?;
            Some(
                wrex_pcap::PcapWriter::new(std::io::BufWriter::new(file))
                    .map_err(|e| CliError::Runtime(format!("mut: `{path}`: {e}")))?,
            )
        }
        None => None,
    };

    for _ in 0..count {
        let mutant = mutator.next_mutant();
        if let Some(w) = writer.as_mut() {
            w.write_record(std::time::SystemTime::now(), &mutant, MUT_DEFAULT_SNAPLEN)
                .map_err(|e| CliError::Runtime(format!("mut: write: {e}")))?;
        }
        match format {
            Format::Hex => {
                let mut line = hex::encode(&mutant);
                line.push('\n');
                write_stdout(line.as_bytes())?;
            }
            Format::Raw => write_stdout(&mutant)?,
            Format::Text | Format::Json | Format::Jsonl => {
                // The mutant dissected: what the mutation actually did.
                let packet = dissect(registry, &mutant, "auto");
                print_frame(format, &packet, &mutant)?;
            }
        }
    }
    if let Some(w) = writer.as_mut() {
        w.flush()
            .map_err(|e| CliError::Runtime(format!("mut: write: {e}")))?;
    }
    Ok(())
}

/// `wrex fuzz`: the stateful recording prober — baseline + mutated
/// probes over a [`RawIpDriver`], one finding per probe.
fn fuzz(registry: &Registry, args: &crate::cli::FuzzArgs) -> Result<(), CliError> {
    use wrex_fuzz::{DEFAULT_ROUNDS, FuzzConfig, ProbeMode};
    use wrex_mut::Strategy;

    let common = &args.common;
    let Some(iface) = common.iface.as_deref() else {
        return Err(usage("fuzz requires -i/--iface"));
    };
    let mode = ProbeMode::parse(args.mode.as_deref()).map_err(usage)?;
    // Registry gating up front (usage → exit 2).
    for kind in mode.needs() {
        if registry.get(kind).is_none() {
            return Err(usage(format!(
                "{kind} layer not registered (registered: {})",
                registry.kinds().join(", ")
            )));
        }
    }
    let strategy = Strategy::parse(args.strategy.as_deref()).map_err(usage)?;

    // Pacing (same vocabulary as scan): --rate/--interval exclusive;
    // default 100/s (`--rate 0` = uncapped burst).
    let interval = match (args.rate, args.interval.as_deref()) {
        (Some(_), Some(_)) => {
            return Err(usage("fuzz: --rate and --interval are mutually exclusive"));
        }
        (Some(rate), None) => {
            if rate == 0 {
                Duration::ZERO
            } else {
                Duration::from_secs_f64(1.0 / rate as f64)
            }
        }
        (None, Some(raw)) => duration_arg(Some(raw))?.unwrap_or(Duration::ZERO),
        (None, None) => Duration::from_secs_f64(1.0 / wrex_scan::DEFAULT_RATE as f64),
    };
    let jitter = duration_arg(args.jitter.as_deref())?.unwrap_or(Duration::ZERO);
    let timeout = duration_arg(args.timeout.as_deref())?.unwrap_or(SCAN_DEFAULT_TIMEOUT);
    let retries = args.retries.unwrap_or(1);
    let concurrent = args.concurrent.unwrap_or(256);
    let rounds = args.rounds.unwrap_or(DEFAULT_ROUNDS);
    let seed = args.seed.unwrap_or_else(time_seed);

    let cfg = FuzzConfig::build(
        mode,
        &args.targets,
        args.ports.as_deref(),
        rounds,
        args.baseline,
        strategy,
        interval,
        jitter,
        seed,
        retries,
        timeout,
        concurrent,
    )
    .map_err(|e| usage(format!("fuzz: {e}")))?;

    // Formats: raw/hex carry no findings → reject before any socket.
    let format = Format::parse(common, Format::Text)?;
    if matches!(format, Format::Raw | Format::Hex) {
        return Err(usage(
            "fuzz --format supports text|json|jsonl (raw/hex carry no findings)",
        ));
    }

    // Interface + source address (kernel routes on the datagram dst).
    let table = IfTable::from_system()
        .map_err(|e| CliError::Runtime(format!("reading interfaces: {e}")))?;
    let entry = table
        .get(iface)
        .ok_or_else(|| {
            CliError::Runtime(format!(
                "unknown iface `{iface}` (available: {})",
                table.names().join(", ")
            ))
        })?
        .clone();
    let src = match cfg.family() {
        wrex_scan::Family::V4 => entry
            .ipv4s
            .first()
            .copied()
            .map(wrex_scan::ScanAddr::V4)
            .ok_or_else(|| {
                CliError::Runtime(format!("iface `{iface}` has no IPv4 source address"))
            })?,
        wrex_scan::Family::V6 => entry
            .ipv6s
            .first()
            .copied()
            .map(wrex_scan::ScanAddr::V6)
            .ok_or_else(|| {
                CliError::Runtime(format!("iface `{iface}` has no IPv6 source address"))
            })?,
    };

    let mut session =
        wrex_fuzz::ProberSession::new(registry, cfg, src, Instant::now()).map_err(usage)?;
    let findings = match src {
        wrex_scan::ScanAddr::V4(_) => {
            let mut driver = RawIpDriver::open(iface, &table)?;
            wrex_session::run(&mut session, &mut driver, &wrex_io::SystemClock)
                .map_err(|e| CliError::Runtime(format!("fuzz: {e}")))?
        }
        wrex_scan::ScanAddr::V6(_) => {
            let mut driver = wrex_io::RawIpv6Driver::open(iface, &table)?;
            wrex_session::run(&mut session, &mut driver, &wrex_io::SystemClock)
                .map_err(|e| CliError::Runtime(format!("fuzz: {e}")))?
        }
    };

    let mut out = String::new();
    match format {
        Format::Json => {
            let json = serde_json::to_string_pretty(&findings)
                .map_err(|e| CliError::Runtime(format!("json: {e}")))?;
            out.push_str(&json);
            out.push('\n');
        }
        Format::Text => {
            for f in &findings {
                out.push_str(&f.text_line());
                out.push('\n');
            }
        }
        Format::Jsonl => {
            for f in &findings {
                let json = serde_json::to_string(f)
                    .map_err(|e| CliError::Runtime(format!("json: {e}")))?;
                out.push_str(&json);
                out.push('\n');
            }
        }
        Format::Raw | Format::Hex => unreachable!("rejected above"),
    }
    write_stdout(out.as_bytes())?;
    // Probe run completed → exit 0 regardless of what the findings say.
    Ok(())
}

// --- http ---------------------------------------------------------------------

/// Default `wrex http` response budget (64 MiB, the frozen plan value).
const HTTP_DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
const HTTP_DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Body input grammar: literal text, `@FILE`, or `hex:BYTES`.
fn http_body(raw: &str) -> Result<bytes::Bytes, CliError> {
    if let Some(path) = raw.strip_prefix('@') {
        let data = std::fs::read(path).map_err(|e| usage(format!("cannot read `{path}`: {e}")))?;
        return Ok(bytes::Bytes::from(data));
    }
    if let Some(hexpart) = raw.strip_prefix("hex:") {
        let data = wrex_core::value::parse_hex_bytes(hexpart)
            .map_err(|e| usage(format!("bad hex body: {e}")))?;
        return Ok(bytes::Bytes::from(data));
    }
    Ok(bytes::Bytes::from(raw.as_bytes().to_vec()))
}

/// `wrex http`: one HTTP/1.1 exchange over a kernel TCP connection.
/// A completed exchange is exit 0 whatever the status says (--fail
/// opts 4xx/5xx into exit 1); connect/timeout/protocol failures are
/// exit 1; grammar/recipe errors exit 2 (all before any socket).
fn http(args: &crate::cli::HttpArgs) -> Result<(), CliError> {
    use wrex_http::{HttpClientSession, HttpConfig, HttpOutcome};

    let common = &args.common;
    let format = Format::parse(common, Format::Text)?;
    if matches!(format, Format::Hex) {
        return Err(usage(
            "http --format supports text|json|raw (hex carries no http sense)",
        ));
    }

    // Materialize the request up front: every usage error (recipe
    // schema, grammar, https, bad headers) surfaces before connect.
    let (spec, cfg) = build_http_request(args)?;

    // Retry loop: fresh connection per attempt (close-mode).
    let attempts = cfg.retries + 1;
    let mut last_err: Option<String> = None;
    for _ in 0..attempts {
        let peer = tcp_peer(&spec.url)?;
        let bind = tcp_bind(common, args.source_port)?;
        let driver = match wrex_io::TcpDriver::connect(peer, bind, cfg.timeout) {
            Ok(d) => d,
            Err(e) => return Err(CliError::Runtime(format!("http: {e}"))),
        };
        let mut session = HttpClientSession::new(
            &spec,
            HttpConfig {
                timeout: cfg.timeout,
                max_bytes: cfg.max_bytes as usize,
            },
            Instant::now(),
        )
        .map_err(|e| usage(format!("http: {e}")))?;
        let outcomes = wrex_session::run(&mut session, &mut { driver }, &wrex_io::SystemClock)
            .map_err(|e| CliError::Runtime(format!("http: {e}")))?;
        match outcomes.into_iter().next() {
            Some(HttpOutcome::Response(resp)) => {
                return render_http_response(&resp, format, args.fail);
            }
            Some(HttpOutcome::Malformed(detail)) => {
                last_err = Some(format!("malformed response: {detail}"));
            }
            Some(HttpOutcome::Truncated) => {
                last_err = Some("connection closed mid-response".to_string());
            }
            Some(HttpOutcome::TooLarge) => {
                return Err(CliError::Runtime(format!(
                    "http: response exceeded the {} byte budget",
                    cfg.max_bytes
                )));
            }
            Some(HttpOutcome::Timeout) => {
                last_err = Some(format!("no response within {}", hum_duration(cfg.timeout)));
            }
            None => return Err(CliError::Runtime("http: no outcome".to_string())),
        }
    }
    Err(CliError::Runtime(format!(
        "http: {}",
        last_err.unwrap_or_else(|| "exchange failed".to_string())
    )))
}

/// Resolved request + the knobs a recipe may override.
struct HttpVerbConfig {
    retries: u32,
    timeout: Duration,
    max_bytes: u64,
}

fn build_http_request(
    args: &crate::cli::HttpArgs,
) -> Result<(wrex_http::HttpRequestSpec, HttpVerbConfig), CliError> {
    use wrex_http::{HttpRequestSpec, Recipe};

    let (spec, overrides) = if let Some(path) = args.recipe.as_deref() {
        if !args.positional.is_empty() {
            return Err(usage(
                "--recipe is exclusive with METHOD/URL (the recipe carries them)",
            ));
        }
        if args.data.is_some() {
            return Err(usage("--recipe is exclusive with --data"));
        }
        let raw = std::fs::read_to_string(path)
            .map_err(|e| usage(format!("cannot read recipe `{path}`: {e}")))?;
        let recipe: Recipe =
            serde_json::from_str(&raw).map_err(|e| usage(format!("bad recipe `{path}`: {e}")))?;
        let (spec, o) = recipe
            .into_request()
            .map_err(|e| usage(format!("bad recipe `{path}`: {e}")))?;
        (spec, o)
    } else {
        // Positional grammar: [METHOD] URL. A lone argument is the URL
        // (GET implied); two arguments are method + URL; more is usage.
        let (method, url) = match args.positional.as_slice() {
            [url] => ("GET", url.as_str()),
            [method, url] => (method.as_str(), url.as_str()),
            [] => {
                return Err(usage(
                    "http needs a URL (or --recipe FILE): wrex http [METHOD] URL",
                ));
            }
            _ => {
                return Err(usage(
                    "http takes at most [METHOD] URL (use -H/--data for the rest)",
                ));
            }
        };
        if method.eq_ignore_ascii_case("get") && method != "GET" {
            return Err(usage(format!(
                "bad method `{method}` (http verbs are uppercase tokens)"
            )));
        }
        let mut headers: Vec<(&str, &str)> = Vec::with_capacity(args.header.len());
        for h in &args.header {
            let (name, value) = h
                .split_once(':')
                .ok_or_else(|| usage(format!("bad header `{h}` (expected NAME:VALUE)")))?;
            headers.push((name.trim(), value.trim()));
        }
        let body = args
            .data
            .as_deref()
            .map(http_body)
            .transpose()?
            .unwrap_or_default();
        let spec = HttpRequestSpec::build(method, url, &headers, body)
            .map_err(|e| usage(format!("http: {e}")))?;
        (spec, wrex_http::recipe::RecipeOverrides::default())
    };

    let cfg = HttpVerbConfig {
        retries: overrides.retries.unwrap_or(args.retries.unwrap_or(0)),
        timeout: overrides
            .timeout_ms
            .map(Duration::from_millis)
            .or_else(|| duration_arg(args.timeout.as_deref()).ok().flatten())
            .unwrap_or(HTTP_DEFAULT_TIMEOUT),
        max_bytes: overrides
            .max_bytes
            .or(args.max_bytes)
            .unwrap_or(HTTP_DEFAULT_MAX_BYTES),
    };
    Ok((spec, cfg))
}

/// Resolve the URI's authority to a socket address for TcpDriver.
fn tcp_peer(uri: &wrex_http::http::Uri) -> Result<std::net::SocketAddr, CliError> {
    use std::net::ToSocketAddrs;
    let authority = uri
        .authority()
        .ok_or_else(|| usage("url has no host".to_string()))?;
    let host = authority.host();
    let port = authority
        .port_u16()
        .or_else(|| uri.scheme_str().map(|_| 80))
        .unwrap_or(80);
    // Hosts are IP addresses for the driver; resolve names via std.
    let mut addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| CliError::Runtime(format!("cannot resolve `{host}`: {e}")))?;
    let addr = addrs
        .next()
        .ok_or_else(|| CliError::Runtime(format!("no address for `{host}`")))?;
    if !addr.is_ipv4() {
        return Err(CliError::Runtime(format!(
            "`{host}` resolved to a non-IPv4 address (out of charter)"
        )));
    }
    Ok(addr)
}

/// Local bind for the TCP connection: -i's address when given (multi-
/// homed determinism), with --source-port honored.
fn tcp_bind(
    common: &Common,
    source_port: Option<u16>,
) -> Result<Option<std::net::SocketAddr>, CliError> {
    let Some(iface) = common.iface.as_deref() else {
        return Ok(None);
    };
    let table = IfTable::from_system()
        .map_err(|e| CliError::Runtime(format!("reading interfaces: {e}")))?;
    let entry = table
        .get(iface)
        .ok_or_else(|| {
            CliError::Runtime(format!(
                "unknown iface `{iface}` (available: {})",
                table.names().join(", ")
            ))
        })?
        .clone();
    let ip =
        entry.ipv4s.first().copied().ok_or_else(|| {
            CliError::Runtime(format!("iface `{iface}` has no IPv4 source address"))
        })?;
    Ok(Some(std::net::SocketAddr::new(
        std::net::IpAddr::V4(ip),
        source_port.unwrap_or(0),
    )))
}

fn render_http_response(
    resp: &wrex_http::HttpResponse,
    format: Format,
    fail: bool,
) -> Result<(), CliError> {
    let status = resp.status.as_u16();
    // --fail: 4xx/5xx are still a completed exchange, but the flag opts
    // the user into a non-zero exit (the pinned 1 = outcome table).
    if fail && status >= 400 {
        return Err(CliError::Runtime(format!("http: status {status} (--fail)")));
    }
    match format {
        Format::Raw => write_stdout(&resp.body)?,
        Format::Text => {
            let mut out = format!(
                "HTTP/1.{} {} {}\r\n",
                if resp.version == wrex_http::http::Version::HTTP_10 {
                    0
                } else {
                    1
                },
                status,
                resp.reason
            );
            for (name, value) in resp.headers.iter() {
                out.push_str(&format!(
                    "{}: {}\r\n",
                    name,
                    String::from_utf8_lossy(value.as_bytes())
                ));
            }
            out.push_str("\r\n");
            write_stdout(out.as_bytes())?;
            write_stdout(&resp.body)?;
        }
        Format::Json => {
            let mut headers = serde_json::Map::new();
            for (name, value) in resp.headers.iter() {
                let key = name.as_str().to_string();
                let val = String::from_utf8_lossy(value.as_bytes()).to_string();
                match headers.get_mut(&key) {
                    Some(serde_json::Value::Array(items)) => items.push(serde_json::json!(val)),
                    Some(_) | None => {
                        headers.insert(key, serde_json::json!([val]));
                    }
                }
            }
            let json = serde_json::json!({
                "status": status,
                "reason": resp.reason,
                "version": if resp.version == wrex_http::http::Version::HTTP_10 { "HTTP/1.0" } else { "HTTP/1.1" },
                "headers": headers,
                "body_hex": hex::encode(&resp.body),
            });
            let mut out = serde_json::to_string_pretty(&json)
                .map_err(|e| CliError::Runtime(format!("json: {e}")))?;
            out.push('\n');
            write_stdout(out.as_bytes())?;
        }
        Format::Jsonl | Format::Hex => unreachable!("rejected above"),
    }
    Ok(())
}

// --- query --------------------------------------------------------------------

/// `wrex query`: one seeded DNS question over a raw UDP datagram, the
/// reply dissected to stdout. A reply is exit 0 whatever the rcode says
/// (NXDOMAIN/SERVFAIL are data); silence after all attempts is exit 1.
fn query(registry: &Registry, args: &crate::cli::QueryArgs) -> Result<(), CliError> {
    use wrex_dns::{DnsReply, DnsSession, QueryConfig};

    let common = &args.common;
    // --tcp rides kernel TCP (no iface, no caps); the raw UDP path
    // needs -i for its source address. The gate is checked after the
    // grammar below so usage errors take precedence.
    let iface = common.iface.as_deref();
    // Formats: the reply is a DissectedPacket; raw/hex make no sense.
    let format = Format::parse(common, Format::Text)?;
    if matches!(format, Format::Raw | Format::Hex) {
        return Err(usage(
            "query --format supports text|json|jsonl (raw/hex carry no reply)",
        ));
    }
    // Registry gating up front (usage → exit 2).
    for kind in ["ipv4", "udp", "dns"] {
        if registry.get(kind).is_none() {
            return Err(usage(format!(
                "{kind} layer not registered (registered: {})",
                registry.kinds().join(", ")
            )));
        }
    }
    let Some(server_raw) = args.server.as_deref() else {
        return Err(usage("query requires --server (e.g. --server 1.1.1.1)"));
    };
    let server: std::net::Ipv4Addr = server_raw
        .parse()
        .map_err(|_| usage(format!("bad server `{server_raw}` (expected IPv4)")))?;
    let timeout = duration_arg(args.timeout.as_deref())?.unwrap_or(SCAN_DEFAULT_TIMEOUT);
    let retries = args.retries.unwrap_or(1);
    let seed = args.seed.unwrap_or_else(time_seed);
    let cfg = QueryConfig {
        server,
        port: args.port.unwrap_or(53),
        name: args.name.trim().trim_end_matches('.').to_string(),
        qtype: args.qtype.clone().unwrap_or_else(|| "A".to_string()),
        qclass: args.qclass.clone().unwrap_or_else(|| "IN".to_string()),
        rd: !common.no_autofill,
        retries,
        timeout,
        seed,
    };

    // Session first: grammar/name errors surface as usage (exit 2)
    // BEFORE any socket is opened. --tcp needs no interface (kernel
    // TCP routes and picks the source); the raw UDP path needs -i.
    if args.tcp {
        let src = std::net::Ipv4Addr::LOCALHOST;
        return query_tcp(registry, cfg, args, format, src);
    }
    let Some(iface) = iface else {
        return Err(usage("query requires -i/--iface (unless --tcp)"));
    };
    let table = IfTable::from_system()
        .map_err(|e| CliError::Runtime(format!("reading interfaces: {e}")))?;
    let entry = table
        .get(iface)
        .ok_or_else(|| {
            CliError::Runtime(format!(
                "unknown iface `{iface}` (available: {})",
                table.names().join(", ")
            ))
        })?
        .clone();
    let src =
        entry.ipv4s.first().copied().ok_or_else(|| {
            CliError::Runtime(format!("iface `{iface}` has no IPv4 source address"))
        })?;
    let mut session = DnsSession::new(registry, cfg, src, Instant::now())
        .map_err(|e| usage(format!("query: {e}")))?;
    let mut driver = RawIpDriver::open(iface, &table)?;
    let outcomes = wrex_session::run(&mut session, &mut driver, &wrex_io::SystemClock)
        .map_err(|e| CliError::Runtime(format!("query: {e}")))?;

    match outcomes.into_iter().next() {
        Some(DnsReply::Reply(pkt)) => {
            let out = match format {
                Format::Text => {
                    let mut s = dissect_to_text(&pkt);
                    s.push('\n');
                    s
                }
                Format::Json => {
                    let mut s = serde_json::to_string_pretty(&dissect_to_json(&pkt))
                        .map_err(|e| CliError::Runtime(format!("json: {e}")))?;
                    s.push('\n');
                    s
                }
                Format::Jsonl => {
                    let mut s = dissect_to_jsonl(&pkt);
                    s.push('\n');
                    s
                }
                Format::Raw | Format::Hex => unreachable!("rejected above"),
            };
            write_stdout(out.as_bytes())?;
            Ok(())
        }
        Some(DnsReply::NoReply { attempts }) => Err(CliError::Runtime(format!(
            "no reply from {server} within {} x {attempts} ({})",
            hum_duration(timeout),
            args.name
        ))),
        // run() returns one outcome per session; none means the session
        // never started (gated above) — unreachable in practice.
        None => Err(CliError::Runtime("query produced no outcome".to_string())),
    }
}

/// `query --tcp`: RFC 7766 length-prefixed DNS over a fresh kernel TCP
/// connection per attempt (the UDP session retries internally; TCP
/// reconnects, per the frozen plan).
#[allow(clippy::too_many_arguments)]
fn query_tcp(
    registry: &Registry,
    cfg: wrex_dns::QueryConfig,
    args: &crate::cli::QueryArgs,
    format: Format,
    src: std::net::Ipv4Addr,
) -> Result<(), CliError> {
    use wrex_dns::{DnsTcpReply, DnsTcpSession};

    // Seeded identity comes from the same rng draw as UDP (same seed ⇒
    // same id); the TCP wire payload is the BARE dns message (the
    // kernel owns L3/L4 here — no ipv4/udp layers in the bytes).
    let mut rng = wrex_io::Rng::new(cfg.seed);
    let _sport = rng.range_u16(32768, 60999);
    let id = (rng.next_u64() & 0xffff) as u16;
    let query = wrex_dns::build_tcp_query(registry, &cfg, 0, id)
        .map_err(|e| usage(format!("query: {e}")))?;

    let server = cfg.server;
    let timeout = cfg.timeout;
    let attempts = cfg.retries + 1;
    // Kernel TCP: the stack picks the source address/port; `src` is the
    // identity seed only (the query bytes derive from it via the UDP
    // builder and stay identical on either transport).
    let _ = src;
    for attempt in 1..=attempts {
        let peer = std::net::SocketAddr::new(std::net::IpAddr::V4(server), cfg.port);
        let bind = None;
        let mut driver = wrex_io::TcpDriver::connect(peer, bind, timeout)
            .map_err(|e| CliError::Runtime(format!("query --tcp: {e}")))?;
        let mut session =
            DnsTcpSession::new(registry, cfg.clone(), query.clone(), id, Instant::now())
                .map_err(|e| usage(format!("query: {e}")))?;
        let outcomes = wrex_session::run(&mut session, &mut driver, &wrex_io::SystemClock)
            .map_err(|e| CliError::Runtime(format!("query --tcp: {e}")))?;
        match outcomes.into_iter().next() {
            Some(DnsTcpReply::Reply(pkt)) => {
                let out = match format {
                    Format::Text => {
                        let mut s = dissect_to_text(&pkt);
                        s.push('\n');
                        s
                    }
                    Format::Json => {
                        let mut s = serde_json::to_string_pretty(&dissect_to_json(&pkt))
                            .map_err(|e| CliError::Runtime(format!("json: {e}")))?;
                        s.push('\n');
                        s
                    }
                    Format::Jsonl => {
                        let mut s = dissect_to_jsonl(&pkt);
                        s.push('\n');
                        s
                    }
                    Format::Raw | Format::Hex => unreachable!("rejected in query()"),
                };
                write_stdout(out.as_bytes())?;
                return Ok(());
            }
            // Failed attempt: a fresh connection is the retry (RFC 7766).
            Some(DnsTcpReply::Truncated { .. }) | Some(DnsTcpReply::NoReply) | None => {
                if attempt < attempts {
                    eprintln!(
                        "wrex: query --tcp: attempt {attempt}/{attempts} failed; reconnecting"
                    );
                }
                continue;
            }
        }
    }
    Err(CliError::Runtime(format!(
        "no reply from {server} over tcp within {} x {attempts} ({})",
        hum_duration(timeout),
        args.name
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(duration_arg(None).unwrap(), None);
        assert_eq!(
            duration_arg(Some("500ms")).unwrap(),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            duration_arg(Some("2s")).unwrap(),
            Some(Duration::from_secs(2))
        );
        assert!(duration_arg(Some("xx")).is_err());
    }
}
