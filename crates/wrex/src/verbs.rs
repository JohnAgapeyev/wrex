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
        Cmd::Scan(args) => scan(&registry, args),
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
    let src =
        entry.ipv4s.first().copied().ok_or_else(|| {
            CliError::Runtime(format!("iface `{iface}` has no IPv4 source address"))
        })?;

    let mut driver = RawIpDriver::open(iface, &table)?;
    let mut session =
        wrex_scan::ScanSession::new(registry, cfg, src, Instant::now()).map_err(usage)?;
    let results = wrex_session::run(&mut session, &mut driver, &wrex_io::SystemClock)
        .map_err(|e| CliError::Runtime(format!("scan: {e}")))?;

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

// --- query --------------------------------------------------------------------

/// `wrex query`: one seeded DNS question over a raw UDP datagram, the
/// reply dissected to stdout. A reply is exit 0 whatever the rcode says
/// (NXDOMAIN/SERVFAIL are data); silence after all attempts is exit 1.
fn query(registry: &Registry, args: &crate::cli::QueryArgs) -> Result<(), CliError> {
    use wrex_dns::{DnsReply, DnsSession, QueryConfig};

    let common = &args.common;
    let Some(iface) = common.iface.as_deref() else {
        return Err(usage("query requires -i/--iface"));
    };
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

    // Interface + source address (the kernel routes on the datagram dst).
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

    // Session first: grammar/name errors surface as usage (exit 2)
    // BEFORE any raw socket is opened.
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
