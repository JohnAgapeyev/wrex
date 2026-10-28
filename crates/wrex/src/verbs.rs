//! Verb implementations: craft / dissect / send / recv / iface / fields,
//! plus the exit-code mapping (0 success, 1 runtime, 2 usage).

use std::time::{Duration, Instant};

use clap::ArgMatches;

use crate::cli::{Cli, Cmd, Common};
use crate::spec::packet_spec_from_matches;
use wrex_core::dissect::dissect;
use wrex_core::encode::EncodeOpts;
use wrex_core::render::{
    dissect_to_json_spans, dissect_to_jsonl, dissect_to_jsonl_spans, dissect_to_text,
    dissect_to_text_spans,
};
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
            args.spans,
            args.frame,
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
        Cmd::Patch(args) => patch_verb(&registry, &args.common, args),
        Cmd::Fuzz(args) => fuzz(&registry, args),
        Cmd::Http(args) => http(args),
        Cmd::Query(args) => query(&registry, args),
        Cmd::Diff(args) => diff(&args.common, &args.files),
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
    write_all_flush(&mut out, bytes)
}

/// The write-and-flush core of [`write_stdout`] (factored for fault
/// testing): any writer error — EPIPE on a closed stdout included —
/// maps to `CliError::Runtime` (exit 1), never a panic.
fn write_all_flush<W: std::io::Write>(out: &mut W, bytes: &[u8]) -> Result<(), CliError> {
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

fn dissect_cmd(
    registry: &Registry,
    common: &Common,
    start: &str,
    spans: bool,
    frame: bool,
) -> Result<(), CliError> {
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
            let mut out = dissect_to_text_spans(&packet, spans, frame);
            out.push('\n');
            write_stdout(out.as_bytes())?;
        }
        Format::Json => {
            let mut out =
                serde_json::to_string_pretty(&dissect_to_json_spans(&packet, spans, frame))
                    .map_err(|e| usage(format!("json: {e}")))?;
            out.push('\n');
            write_stdout(out.as_bytes())?;
        }
        Format::Jsonl => {
            let mut out = dissect_to_jsonl_spans(&packet, spans, frame);
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
                    layer.fields.insert("src".into(), Value::Mac(entry.mac));
                }
            }
            "ipv4" => {
                if !layer.fields.contains_key("src")
                    && let Some(ip) = entry.ipv4s.first()
                {
                    layer.fields.insert("src".into(), Value::Ipv4(*ip));
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
        // Dissect on demand: raw/hex output with no filter never reads
        // the packet — the recv hot loop skips the whole dissect cost.
        let packet = if filter.is_some() || !matches!(format, Format::Raw | Format::Hex) {
            Some(dissect(registry, &frame.bytes, "auto"))
        } else {
            None
        };
        if let (Some(f), Some(p)) = (&filter, &packet)
            && !f.matches(p)
        {
            continue;
        }
        seen += 1;
        match format {
            Format::Jsonl => {
                let mut line = dissect_to_jsonl(packet.as_ref().expect("dissected for output"));
                line.push('\n');
                write_stdout(line.as_bytes())?;
            }
            Format::Raw => {
                write_stdout(&frame.bytes)?;
            }
            Format::Text => {
                let mut out = dissect_to_text(packet.as_ref().expect("dissected for output"));
                out.push('\n');
                write_stdout(out.as_bytes())?;
            }
            Format::Json => {
                let mut out = serde_json::to_string(packet.as_ref().expect("dissected for output"))
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
            // Direct serializer (no intermediate tree) — identical bytes.
            let mut out = serde_json::to_string(packet).map_err(|e| usage(format!("json: {e}")))?;
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

/// The pcap sink shared by capture (tranche 5/8b) and patch (tranche
/// 14): classic pcap (default) or pcapng (`--pcapng`) — both writers
/// share the `write_record`/`write_record_orig`/`flush` shape.
enum FrameWriter {
    Classic(wrex_pcap::PcapWriter<std::io::BufWriter<std::fs::File>>),
    Ng(wrex_pcap::PcapngWriter<std::io::BufWriter<std::fs::File>>),
}

impl FrameWriter {
    /// Create the sink: writes the global headers on open (the file is
    /// valid the moment the writer exists). `ns` picks the pcapng
    /// `if_tsresol` 9 IDB (tranche T18b; ignored without `pcapng`).
    fn new(pcapng: bool, ns: bool, path: &str) -> Result<FrameWriter, CliError> {
        let file = std::fs::File::create(path)
            .map_err(|e| CliError::Runtime(format!("cannot create `{path}`: {e}")))?;
        let buf = std::io::BufWriter::new(file);
        if pcapng {
            let writer = if ns {
                wrex_pcap::PcapngWriter::with_resol(buf, wrex_pcap::TsResol::Nanos)
            } else {
                wrex_pcap::PcapngWriter::new(buf)
            }
            .map_err(|e| CliError::Runtime(format!("`{path}`: {e}")))?;
            Ok(FrameWriter::Ng(writer))
        } else {
            Ok(FrameWriter::Classic(
                wrex_pcap::PcapWriter::new(buf)
                    .map_err(|e| CliError::Runtime(format!("`{path}`: {e}")))?,
            ))
        }
    }

    fn write_record(
        &mut self,
        ts: std::time::SystemTime,
        frame: &[u8],
        snaplen: usize,
    ) -> std::io::Result<()> {
        match self {
            FrameWriter::Classic(w) => w.write_record(ts, frame, snaplen),
            FrameWriter::Ng(w) => w.write_record(ts, frame, snaplen),
        }
    }

    /// The tranche-14 passthrough record: an explicit `orig_len` keeps
    /// a snaplen-truncated capture's wire length annotation intact.
    fn write_record_orig(
        &mut self,
        ts: std::time::SystemTime,
        frame: &[u8],
        orig_len: u32,
        snaplen: usize,
    ) -> std::io::Result<()> {
        match self {
            FrameWriter::Classic(w) => w.write_record_orig(ts, frame, orig_len, snaplen),
            FrameWriter::Ng(w) => w.write_record_orig(ts, frame, orig_len, snaplen),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            FrameWriter::Classic(w) => w.flush(),
            FrameWriter::Ng(w) => w.flush(),
        }
    }
}

/// `wrex capture`: AF_PACKET recv loop into a pcap file (classic by
/// default, pcapng with `--pcapng`), with an optional `--format` tee to
/// stdout (the same per-frame shapes as recv). Stop conditions and exit
/// codes mirror recv: count/timeout → 0.
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
    let mut writer = FrameWriter::new(args.pcapng, args.pcapng_ns, &args.write)?;

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
        // Dissect on demand: no filter and no tee → the capture hot
        // loop never dissects (raw pcap writing only).
        let packet = if filter.is_some() || tee.is_some() {
            Some(dissect(registry, &frame.bytes, "auto"))
        } else {
            None
        };
        if let (Some(f), Some(p)) = (&filter, &packet)
            && !f.matches(p)
        {
            continue;
        }
        writer
            .write_record(frame.ts, &frame.bytes, snaplen)
            .map_err(|e| CliError::Runtime(format!("capture: {}: {e}", args.write)))?;
        if let (Some(fmt), Some(p)) = (&tee, &packet) {
            print_frame(*fmt, p, &frame.bytes)?;
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
    if args.reassemble && common.iface.is_some() {
        return Err(usage(
            "replay: --reassemble is offline dissection (-i IFACE sends fragments verbatim)",
        ));
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
        if args.reassemble {
            // Tranche T18a: feed the fragment stream (file order) through
            // the reassembler — complete datagrams re-dissect and print
            // in stream order, non-fragments pass through, residual
            // incomplete datagrams report as notes (data, exit 0).
            let mut re = wrex_frag::Reassembler::default();
            for f in &frames {
                match wrex_frag::classify(&f.packet) {
                    Some(frag) => {
                        let now =
                            f.ts.duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_micros() as u64)
                                .unwrap_or(0);
                        match re.push(frag, now) {
                            wrex_frag::Push::Complete(bytes) => {
                                let packet = dissect(registry, &bytes, "auto");
                                print_frame(format, &packet, &bytes)?;
                            }
                            wrex_frag::Push::Overrun => {
                                eprintln!("! reassembly: budget overrun, datagram dropped")
                            }
                            wrex_frag::Push::Pending => {}
                        }
                    }
                    None => print_frame(format, &f.packet, &f.bytes)?,
                }
            }
            for note in re.incomplete() {
                eprintln!("! reassembly: {note}");
            }
            return Ok(());
        }
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

// --- patch (tranche 14) --------------------------------------------------------

/// Default stored bytes per patch pcap record (matches capture/mut).
const PATCH_DEFAULT_SNAPLEN: usize = 65535;

/// `wrex patch` (tranche 14): the CLI door into the span-patch engine —
/// deterministic surgical edits of real frames. Seeds: positional hex,
/// `-r` pcaps (classic or pcapng) and raw stdin — the mut grammar, kept
/// as one ordered stream. `--index`/`--filter` select which frames get
/// patched; everything else passes through byte-identical with its
/// capture timestamp (and `orig_len`) kept. The whole stream (patched +
/// passthrough) lands on stdout per `--format` and, with `-w`, in a
/// pcap file. Grammar errors are usage (exit 2) before any file is
/// read; frame-level failures are pointed runtime errors (exit 1)
/// naming the frame.
fn patch_verb(
    registry: &Registry,
    common: &Common,
    args: &crate::cli::PatchArgs,
) -> Result<(), CliError> {
    use crate::edit;
    use wrex_core::patch::patch;

    // Grammar gates first (usage → exit 2, before any I/O): the whole
    // edit set validates against the registry here, so a bad flag never
    // lands mid-stream.
    let scope = edit::parse_scope(args.scope.as_deref(), args.no_recompute).map_err(patch_usage)?;
    let indices = match args.index.as_deref() {
        Some(raw) => Some(edit::parse_indices(raw).map_err(patch_usage)?),
        None => None,
    };
    let filter = match args.filter.as_deref() {
        Some(f) => Some(Filter::parse(registry, f)?),
        None => None,
    };
    let edit_set = edit::parse_edits(registry, &scope, &args.set, &args.insert, &args.delete)
        .map_err(patch_usage)?;
    let format = Format::parse(common, Format::Hex)?;

    // Seed stream (the mut order): positional hex, then every -r pcap
    // record with its timestamp and orig_len (passthrough fidelity),
    // then raw stdin when piped and nothing else feeds.
    let now = std::time::SystemTime::now();
    let mut frames: Vec<(std::time::SystemTime, Vec<u8>, u32)> = Vec::new();
    for raw in &args.frames {
        let bytes = wrex_core::value::parse_hex_bytes(raw)
            .map_err(|e| usage(format!("bad seed frame `{raw}`: {e}")))?;
        if bytes.is_empty() {
            return Err(usage(format!("empty seed frame `{raw}`")));
        }
        let orig = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        frames.push((now, bytes, orig));
    }
    for path in &args.read {
        let pcap_bytes = std::fs::read(path)
            .map_err(|e| CliError::Runtime(format!("patch: cannot read `{path}`: {e}")))?;
        let file = wrex_pcap::read(&pcap_bytes)
            .map_err(|e| CliError::Runtime(format!("patch: `{path}`: {e}")))?;
        for rec in &file.records {
            frames.push((rec.ts, rec.bytes.clone(), rec.orig_len));
        }
    }
    {
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() && args.frames.is_empty() && args.read.is_empty() {
            let bytes = read_stdin_capped()?;
            let orig = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
            frames.push((now, bytes, orig));
        }
    }
    if frames.is_empty() {
        return Err(usage(
            "patch: no seed frames given (positional hex, -r FILE.pcap or stdin)",
        ));
    }

    let mut writer = match &args.write {
        Some(path) => Some(FrameWriter::new(args.pcapng, false, path)?),
        None => None,
    };

    for (i, (ts, bytes, orig_len)) in frames.iter().enumerate() {
        let ordinal = i + 1;
        // Selection: --index picks 1-based ordinals; --filter matches a
        // read-only dissection (the replay/recv engine — selecting never
        // patches). Both given = intersection.
        let mut packet = None;
        let mut selected = indices.as_ref().is_none_or(|s| s.contains(&ordinal));
        if let Some(f) = &filter {
            let p = dissect(registry, bytes, "auto");
            if f.matches(&p) {
                packet = Some(p);
            } else {
                selected = false;
            }
        }
        let out: Vec<u8> = if selected {
            let p = packet.unwrap_or_else(|| dissect(registry, bytes, "auto"));
            let edits = edit_set
                .materialize(&p)
                .map_err(|e| patch_runtime(ordinal, e))?;
            patch(registry, &p, &edits, &scope)
                .map_err(|e| CliError::Runtime(format!("frame {ordinal}: {e}")))?
                .to_vec()
        } else {
            bytes.clone()
        };
        if let Some(w) = writer.as_mut() {
            // Patched frames carry their own length; passthrough keeps
            // the source annotation (truncated captures included).
            let orig = if selected {
                u32::try_from(out.len()).unwrap_or(u32::MAX)
            } else {
                *orig_len
            };
            w.write_record_orig(*ts, &out, orig, PATCH_DEFAULT_SNAPLEN)
                .map_err(|e| CliError::Runtime(format!("patch: write: {e}")))?;
        }
        match format {
            Format::Hex => {
                let mut line = hex::encode(&out);
                line.push('\n');
                write_stdout(line.as_bytes())?;
            }
            Format::Raw => {
                write_stdout(&out)?;
            }
            Format::Text | Format::Json | Format::Jsonl => {
                let p = dissect(registry, &out, "auto");
                print_frame(format, &p, &out)?;
            }
        }
    }
    if let Some(w) = writer.as_mut() {
        w.flush()
            .map_err(|e| CliError::Runtime(format!("patch: write: {e}")))?;
    }
    Ok(())
}

/// Map the edit grammar onto the CLI exit classes with the `patch:`
/// context: usage (exit 2) for static grammar errors, runtime (exit 1)
/// for frame-level ones (the verb names the frame).
fn patch_usage(e: crate::edit::EditError) -> CliError {
    CliError::Usage(vec![format!("patch: {e}")])
}

fn patch_runtime(ordinal: usize, e: crate::edit::EditError) -> CliError {
    CliError::Runtime(format!("frame {ordinal}: {e}"))
}

/// `wrex fuzz`: the stateful recording prober — baseline + mutated
/// probes over a [`RawIpDriver`], one finding per probe. The tranche-9b
/// app modes (`http`/`dns`) ride the kernel `TcpDriver` instead (no
/// raw sockets, no `-i`): one fresh connection per probe.
fn fuzz(registry: &Registry, args: &crate::cli::FuzzArgs) -> Result<(), CliError> {
    use wrex_fuzz::{DEFAULT_ROUNDS, FuzzConfig, ProbeMode};
    use wrex_mut::Strategy;

    let common = &args.common;
    let mode = ProbeMode::parse(args.mode.as_deref()).map_err(usage)?;
    // Raw modes need the capture interface; the app modes ride the
    // kernel stream driver instead (validated later, once ports are).
    if !mode.is_app() && common.iface.is_none() {
        return Err(usage("fuzz requires -i/--iface (unless --mode http|dns)"));
    }
    // Registry gating up front (usage → exit 2). The app modes need no
    // codecs (the seed is verb-side; mutation is request-bytes level).
    let family = wrex_scan::target::parse_targets(&args.targets)
        .map_err(usage)?
        .first()
        .map(|t| t.family())
        .unwrap_or(wrex_scan::Family::V4);
    for kind in mode.needs_for(family) {
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
        args.tls,
    )
    .map_err(|e| usage(format!("fuzz: {e}")))?;

    // Formats: raw/hex carry no findings → reject before any socket.
    let format = Format::parse(common, Format::Text)?;
    if matches!(format, Format::Raw | Format::Hex) {
        return Err(usage(
            "fuzz --format supports text|json|jsonl (raw/hex carry no findings)",
        ));
    }

    // Tranche 9b: the application-layer modes ride the kernel stream
    // driver (plain sockets, no -i, no capabilities); tranche 13b:
    // --tls swaps in the T8a rustls adapter (https / DoT).
    if mode.is_app() {
        // TLS knobs are app-mode-only by config validation (--tls on
        // a raw mode never reaches here); --tls-insecure/--tls-ca
        // without --tls are inert (there is nothing to wrap).
        let tls_knobs = if args.tls {
            let ca_der = match &args.tls_ca {
                Some(path) => {
                    Some(wrex_tls::load_ca_file(path).map_err(|e| usage(format!("fuzz: {e}")))?)
                }
                None => None,
            };
            Some(TlsKnobs {
                insecure: args.tls_insecure,
                ca_der,
            })
        } else {
            None
        };
        let findings = fuzz_app_probes(registry, &cfg, tls_knobs.as_ref())?;
        write_stdout(render_findings(&findings, format)?.as_bytes())?;
        return Ok(());
    }

    // Raw modes: the interface is required (validated above) and the
    // capture driver needs it.
    let iface = common.iface.as_deref().expect("checked above");

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

    write_stdout(render_findings(&findings, format)?.as_bytes())?;
    // Probe run completed → exit 0 regardless of what the findings say.
    Ok(())
}

/// `wrex diff` (tranche 12): offline findings differential — two
/// findings JSONL files into a structured report (per-probe outcome
/// deltas, reply-presence changes, divergent reply bytes, one-sided
/// probes). Pure offline data plumbing: no codecs, no sockets, exit 0
/// whatever the report says.
fn diff(common: &Common, files: &[String]) -> Result<(), CliError> {
    use wrex_fuzz::{DiffEntry, diff_findings, parse_findings};

    if files.len() != 2 {
        return Err(usage("diff takes exactly two findings JSONL files"));
    }
    let format = Format::parse(common, Format::Text)?;
    if matches!(format, Format::Raw | Format::Hex) {
        return Err(usage(
            "diff --format supports text|json|jsonl (raw/hex carry no diff report)",
        ));
    }
    let mut sides: [Vec<wrex_fuzz::FindingRecord>; 2] = [Vec::new(), Vec::new()];
    for (i, path) in files.iter().enumerate() {
        let text = std::fs::read_to_string(path)
            .map_err(|e| CliError::Runtime(format!("diff: cannot read `{path}`: {e}")))?;
        sides[i] =
            parse_findings(path, &text).map_err(|e| CliError::Usage(vec![format!("diff: {e}")]))?;
    }
    let entries = diff_findings(&sides[0], &sides[1]);

    let mut out = String::new();
    match format {
        Format::Json => {
            let json = serde_json::to_string_pretty(&entries)
                .map_err(|e| CliError::Runtime(format!("json: {e}")))?;
            out.push_str(&json);
            out.push('\n');
        }
        Format::Text => {
            for e in &entries {
                out.push_str(&DiffEntry::text_line(e));
                out.push('\n');
            }
        }
        Format::Jsonl => {
            for e in &entries {
                let json = serde_json::to_string(e)
                    .map_err(|e| CliError::Runtime(format!("json: {e}")))?;
                out.push_str(&json);
                out.push('\n');
            }
        }
        Format::Raw | Format::Hex => unreachable!("rejected above"),
    }
    write_stdout(out.as_bytes())?;
    // The report is data: any completed diff is exit 0.
    Ok(())
}
fn render_findings(findings: &[wrex_fuzz::Finding], format: Format) -> Result<String, CliError> {
    let mut out = String::new();
    match format {
        Format::Json => {
            let json = serde_json::to_string_pretty(&findings)
                .map_err(|e| CliError::Runtime(format!("json: {e}")))?;
            out.push_str(&json);
            out.push('\n');
        }
        Format::Text => {
            for f in findings {
                out.push_str(&f.text_line());
                out.push('\n');
            }
        }
        Format::Jsonl => {
            for f in findings {
                let json = serde_json::to_string(f)
                    .map_err(|e| CliError::Runtime(format!("json: {e}")))?;
                out.push_str(&json);
                out.push('\n');
            }
        }
        Format::Raw | Format::Hex => unreachable!("rejected above"),
    }
    Ok(out)
}

/// Tranche 13b: the TLS knobs shared by every app probe connection
/// (the `--tls-insecure`/`--tls-ca` contract); the per-target
/// [`wrex_tls::TlsConfig`] derives its `server_name` from the target.
struct TlsKnobs {
    insecure: bool,
    ca_der: Option<Vec<Vec<u8>>>,
}

/// Tranche 9b: run the app-mode probe table — per (target, port) slot,
/// an optional baseline then `--rounds` mutated rounds, one finding
/// each. Every probe is one fresh kernel-TCP connection (mirroring
/// `query --tcp`); retransmissions repeat the exact mutated bytes on a
/// new connection; a connect failure or empty run is silence.
/// Tranche 13b: `tls` swaps the kernel `TcpDriver` for the T8a
/// `TlsDriver` (https / DoT) — the `AppSession` contract is unchanged,
/// only the transport differs (one fresh TLS connection per probe, the
/// handshake driven lazily inside the first send/recv pump under the
/// probe deadline; a verification failure is an attempt spent →
/// silence, never a crash).
#[allow(clippy::too_many_arguments)]
fn fuzz_app_probes(
    registry: &Registry,
    cfg: &wrex_fuzz::FuzzConfig,
    tls: Option<&TlsKnobs>,
) -> Result<Vec<wrex_fuzz::Finding>, CliError> {
    use std::net::IpAddr;
    use wrex_fuzz::{AppConfig, AppOutcome, AppSession, Outcome};
    use wrex_scan::ScanAddr;

    // Tranche 10a: both families. The kernel TcpDriver is dual-family;
    // the probe table keeps the scan's family-homogeneous target list.
    let targets: Vec<ScanAddr> = cfg.targets.clone();

    let mut rng = wrex_io::Rng::new(cfg.seed);
    let mut findings = Vec::new();

    for &target in &targets {
        // The scan target grammar guarantees a family; the app probes
        // speak either one through the kernel driver.
        let target_ip: IpAddr = match target {
            ScanAddr::V4(a) => IpAddr::V4(a),
            ScanAddr::V6(a) => IpAddr::V6(a),
        };
        for &port in &cfg.ports {
            // Tranche 13b: the per-target TLS config (SNI = the target
            // IP string — brackets never appear in a bare Display).
            let tls_cfg = tls.map(|k| wrex_tls::TlsConfig {
                server_name: target.to_string(),
                insecure: k.insecure,
                ca_der: k.ca_der.clone(),
                alpn_protocols: vec![],
            });
            // The unmutated seed request (verb-side; transport framing
            // is well-formed so mutations land on the request bytes).
            let seed: bytes::Bytes = match cfg.mode {
                wrex_fuzz::ProbeMode::Http => {
                    // v6 literals need brackets in a URL (RFC 3986);
                    // --tls speaks https (SNI from the URL host).
                    let scheme = if cfg.tls { "https" } else { "http" };
                    let url = match target {
                        ScanAddr::V4(_) => format!("{scheme}://{target}/"),
                        ScanAddr::V6(_) => format!("{scheme}://[{target}]/"),
                    };
                    let spec =
                        wrex_http::HttpRequestSpec::build("GET", &url, &[], bytes::Bytes::new())
                            .map_err(|e| usage(format!("fuzz: http seed: {e}")))?;
                    spec.serialize()
                        .map_err(|e| usage(format!("fuzz: http seed: {e}")))?
                }
                wrex_fuzz::ProbeMode::Dns => {
                    // One RFC 7766 length-prefixed A query.
                    let qcfg = wrex_dns::QueryConfig {
                        server: target_ip,
                        port,
                        name: "example.com.".to_string(),
                        qtype: "A".to_string(),
                        qclass: "IN".to_string(),
                        rd: true,
                        retries: 0,
                        timeout: cfg.timeout,
                        seed: cfg.seed,
                    };
                    // Same seeded draws as the query verb (sport,
                    // then id): a pinned --seed reproduces the same
                    // probe bytes. The bare dns message, length-prefixed.
                    let mut rng = wrex_io::Rng::new(qcfg.seed);
                    let sport = rng.range_u16(32768, 60999);
                    let id = (rng.next_u64() & 0xffff) as u16;
                    let query = wrex_dns::build_tcp_query(registry, &qcfg, sport, id)
                        .map_err(|e| usage(format!("fuzz: dns seed: {e}")))?;
                    let mut framed = Vec::with_capacity(2 + query.len());
                    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
                    framed.extend_from_slice(&query);
                    bytes::Bytes::from(framed)
                }
                // The raw modes never reach here (the verb routes them).
                _ => unreachable!("app probe table is http|dns only"),
            };

            // Baseline first (when asked), then the mutated rounds.
            let mut rounds: Vec<Option<u32>> = Vec::new();
            if cfg.baseline {
                rounds.push(None);
            }
            rounds.extend((1..=cfg.rounds).map(Some));
            for round in rounds {
                let (probe_bytes, strategy): (bytes::Bytes, &str) = match round {
                    None => (seed.clone(), "baseline"),
                    Some(r) => {
                        // A per-probe deterministic mutation stream
                        // (the same shape as ProberSession's rounds).
                        let mut_seed = rng.next_u64() ^ (u64::from(r) << 32);
                        let mut mutator = wrex_mut::Mutator::new(
                            registry,
                            vec![seed.to_vec()],
                            cfg.strategy,
                            mut_seed,
                        )
                        .map_err(usage)?;
                        (
                            bytes::Bytes::from(mutator.next_mutant()),
                            cfg.strategy.as_str(),
                        )
                    }
                };

                // One fresh connection per attempt; a reply is whatever
                // the peer sends before orderly EOF (budget capped).
                // Tranche 13b: --tls wraps the same stream conventions
                // in rustls (the T8a adapter); a connect or handshake
                // failure spends the attempt as silence either way.
                let mut outcome = Outcome::Silence;
                let mut reply_hex: Option<String> = None;
                let mut rtt_ms: Option<u64> = None;
                let mut attempts = 0u32;
                for _ in 0..=cfg.retries {
                    attempts += 1;
                    let peer = std::net::SocketAddr::new(target_ip, port);
                    let mut driver: Box<dyn wrex_io::Driver> = match &tls_cfg {
                        Some(tcfg) => {
                            match wrex_tls::TlsDriver::connect(peer, None, cfg.timeout, tcfg) {
                                Ok(d) => Box::new(d),
                                Err(_) => continue, // refused/unreachable: silence, attempt spent
                            }
                        }
                        None => match wrex_io::TcpDriver::connect(peer, None, cfg.timeout) {
                            Ok(d) => Box::new(d),
                            Err(_) => continue,
                        },
                    };
                    let t_start = Instant::now();
                    let mut session = AppSession::new(
                        probe_bytes.clone(),
                        AppConfig {
                            timeout: cfg.timeout,
                            max_bytes: wrex_fuzz::app::DEFAULT_MAX_BYTES,
                        },
                        t_start,
                    );
                    let Ok(outs) =
                        wrex_session::run(&mut session, driver.as_mut(), &wrex_io::SystemClock)
                    else {
                        continue; // io/reset/tls-verify: silence, attempt spent
                    };
                    if let Some(AppOutcome::Reply(reply)) = outs.into_iter().next() {
                        outcome = Outcome::Reply;
                        reply_hex = Some(hex::encode(&reply));
                        rtt_ms = Some(t_start.elapsed().as_millis() as u64);
                        break;
                    }
                }

                findings.push(wrex_fuzz::Finding {
                    target,
                    port: Some(port),
                    proto: cfg.mode.as_str(),
                    round,
                    strategy,
                    outcome,
                    attempts,
                    rtt_ms,
                    probe_hex: hex::encode(&probe_bytes),
                    reply_hex,
                });

                // Pacing between probes (seeded jitter, the scan shape).
                if !cfg.interval.is_zero() {
                    let step = if cfg.jitter.is_zero() {
                        cfg.interval
                    } else {
                        let off = rng.jitter_secs(cfg.jitter);
                        if off > 0.0 {
                            cfg.interval + Duration::from_secs_f64(off)
                        } else {
                            cfg.interval.saturating_sub(Duration::from_secs_f64(-off))
                        }
                    };
                    std::thread::sleep(step.max(Duration::from_millis(1)));
                }
            }
        }
    }
    Ok(findings)
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

/// `wrex http`: HTTP/1.1 exchanges over a kernel TCP connection —
/// one request (close-mode) or an ordered keep-alive queue (multiple
/// URLs / a recipe array, tranche 9a). A completed run is exit 0
/// whatever the statuses say (--fail opts 4xx/5xx into exit 1);
/// connect/timeout/protocol failures are exit 1; grammar/recipe
/// errors exit 2 (all before any socket).
fn http(args: &crate::cli::HttpArgs) -> Result<(), CliError> {
    use wrex_http::{HttpClientSession, HttpConfig, HttpOutcome};

    let common = &args.common;
    let format = Format::parse(common, Format::Text)?;
    if matches!(format, Format::Hex) {
        return Err(usage(
            "http --format supports text|json|raw (hex carries no http sense)",
        ));
    }

    // Materialize every request up front: usage errors (recipe schema,
    // grammar, bad headers) surface before connect.
    let (specs, cfgs) = build_http_requests(args)?;
    debug_assert_eq!(specs.len(), cfgs.len());

    // One transport per queue: mixed http/https is a usage error.
    let scheme = specs[0].url.scheme_str().unwrap_or("http");
    if specs.iter().any(|s| s.url.scheme_str() != Some(scheme)) {
        return Err(usage(
            "http queue: one scheme per connection (split mixed http/https runs)",
        ));
    }

    // HTTP/2 (tranche 15): one pick per queue — mixed versions are a
    // usage error. Tranche 16b: `http` + `--http-version 2` is cleartext
    // **prior knowledge** (RFC 9113 §3.4 — the preface straight over
    // the kernel TCP stream); `https` + 2 keeps the T15 ALPN rule.
    let want_h2 = match cfgs.first().and_then(|c| c.http_version.as_deref()) {
        None | Some("1.1") => false,
        Some("2") => true,
        Some(other) => {
            return Err(usage(format!(
                "bad http-version `{other}` (expected 1.1 or 2)"
            )));
        }
    };
    if want_h2 && cfgs.iter().any(|c| c.http_version.as_deref() != Some("2")) {
        return Err(usage(
            "http queue: one http-version per connection (split mixed 1.1/2 runs)",
        ));
    }

    // Send-side HPACK policy (tranche 16a): indexed (default) or the
    // T15-parity literal. One policy per connection (one encoder);
    // mixed recipe policies are a usage error. Inert on 1.1 runs.
    let hpack_policy = match cfgs.first().and_then(|c| c.hpack.as_deref()) {
        None => wrex_h2::HpackEncodePolicy::default(),
        Some("indexed") => wrex_h2::HpackEncodePolicy::Indexed,
        Some("literal") => wrex_h2::HpackEncodePolicy::Literal,
        Some(other) => {
            return Err(usage(format!(
                "bad hpack policy `{other}` (expected indexed or literal)"
            )));
        }
    };
    if cfgs
        .iter()
        .any(|c| c.hpack.as_deref().is_some() && c.hpack != cfgs[0].hpack)
    {
        return Err(usage(
            "http queue: one hpack policy per connection (split mixed indexed/literal runs)",
        ));
    }

    // TLS transport (https://): the driver is the only thing that
    // differs — retry/render/--fail/budget handling stay identical.
    // SNI comes from the URL host (an IP literal matches the cert's
    // IP SAN); roots: system store plus the recipe/CLI --tls-ca adds.
    // The knobs are per-connection: the first request's cfg wins.
    let tls_cfg = if scheme == "https" {
        // SNI from the URL host; brackets on v6 literals strip (rustls
        // parses the bare IP for the IP-SAN match, the T8a rule).
        let host_raw = specs[0]
            .url
            .authority()
            .map(|a| a.host())
            .ok_or_else(|| usage("https url has no host".to_string()))?;
        let host = if host_raw.starts_with('[') && host_raw.ends_with(']') {
            &host_raw[1..host_raw.len() - 1]
        } else {
            host_raw
        }
        .to_string();
        let ca_der = match &cfgs[0].tls_ca {
            Some(path) => {
                Some(wrex_tls::load_ca_file(path).map_err(|e| usage(format!("http: {e}")))?)
            }
            None => None,
        };
        Some(wrex_tls::TlsConfig {
            server_name: host,
            insecure: cfgs[0].tls_insecure,
            ca_der,
            // ALPN offer (tranche 15): h2 with an http/1.1 fallback —
            // the server's pick decides the session (auto-downgrade,
            // the T15 planning decision).
            alpn_protocols: if want_h2 {
                vec!["h2".to_string(), "http/1.1".to_string()]
            } else {
                vec![]
            },
        })
    } else {
        None
    };

    // Retry loop: fresh connection per attempt, whole queue replayed
    // (a keep-alive queue that breaks mid-flight restarts cleanly).
    let attempts = cfgs[0].retries + 1;
    let mut last_err: Option<String> = None;
    for _ in 0..attempts {
        let peer = tcp_peer(&specs[0].url)?;
        // The bind picks the iface address of the peer's family (10a).
        let bind = tcp_bind(common, args.source_port, peer.ip())?;
        let queue_cfgs: Vec<HttpConfig> = cfgs
            .iter()
            .map(|c| HttpConfig {
                timeout: c.timeout,
                max_bytes: c.max_bytes as usize,
            })
            .collect();

        // Transport pick + session run. The 1.1 session is the same
        // machine in every branch; the h2 session (concurrent streams,
        // one `HttpOutcome` per queued request) swaps in only when the
        // server negotiated `h2`.
        let outcomes = {
            if let Some(tcfg) = &tls_cfg {
                let mut driver = wrex_tls::TlsDriver::connect(peer, bind, cfgs[0].timeout, tcfg)
                    .map_err(|e| CliError::Runtime(format!("http: {e}")))?;
                let use_h2 = if want_h2 {
                    let negotiated = driver
                        .complete_handshake(Instant::now() + cfgs[0].timeout)
                        .map_err(|e| CliError::Runtime(format!("http: {e}")))?;
                    if negotiated == Some("h2") {
                        true
                    } else {
                        // Auto-downgrade (the T15 planning decision): a
                        // pointed note, then the 1.1 session.
                        let what = negotiated.unwrap_or("no ALPN protocol");
                        eprintln!("note: server negotiated `{what}` — falling back to HTTP/1.1");
                        false
                    }
                } else {
                    false
                };
                if use_h2 {
                    let mut session = wrex_h2::H2Session::with_policy(
                        &specs,
                        &queue_cfgs,
                        Instant::now(),
                        hpack_policy,
                    )
                    .map_err(|e| usage(format!("http: {e}")))?;
                    wrex_session::run(&mut session, &mut driver, &wrex_io::SystemClock)
                } else {
                    let mut session =
                        HttpClientSession::with_requests(&specs, &queue_cfgs, Instant::now())
                            .map_err(|e| usage(format!("http: {e}")))?;
                    wrex_session::run(&mut session, &mut driver, &wrex_io::SystemClock)
                }
            } else {
                // Cleartext transport: 1.1 keep-alive, or — tranche 16b —
                // h2c **prior knowledge** (the same `H2Session` on the
                // kernel `TcpDriver`, no TLS, no ALPN, no `Upgrade:`).
                let mut driver = wrex_io::TcpDriver::connect(peer, bind, cfgs[0].timeout)
                    .map_err(|e| CliError::Runtime(format!("http: {e}")))?;
                if want_h2 {
                    let mut session = wrex_h2::H2Session::with_policy(
                        &specs,
                        &queue_cfgs,
                        Instant::now(),
                        hpack_policy,
                    )
                    .map_err(|e| usage(format!("http: {e}")))?;
                    wrex_session::run(&mut session, &mut driver, &wrex_io::SystemClock)
                } else {
                    let mut session =
                        HttpClientSession::with_requests(&specs, &queue_cfgs, Instant::now())
                            .map_err(|e| usage(format!("http: {e}")))?;
                    wrex_session::run(&mut session, &mut driver, &wrex_io::SystemClock)
                }
            }
            .map_err(|e| CliError::Runtime(format!("http: {e}")))?
        };

        if outcomes.len() == specs.len()
            && outcomes
                .iter()
                .all(|o| matches!(o, HttpOutcome::Response(_)))
        {
            let responses: Vec<wrex_http::HttpResponse> = outcomes
                .into_iter()
                .map(|o| match o {
                    HttpOutcome::Response(r) => r,
                    _ => unreachable!("checked above"),
                })
                .collect();
            render_http_responses(&responses, format)?;
            // --fail: completed exchanges stay data (printed above),
            // the flag opts into a non-zero exit.
            if args.fail && responses.iter().any(|r| r.status.as_u16() >= 400) {
                let status = responses
                    .iter()
                    .map(|r| r.status.as_u16())
                    .find(|&s| s >= 400)
                    .unwrap_or(0);
                return Err(CliError::Runtime(format!("http: status {status} (--fail)")));
            }
            return Ok(());
        }

        // Some exchange failed: map the first failure, then retry.
        let first = outcomes
            .iter()
            .find(|o| !matches!(o, HttpOutcome::Response(_)));
        last_err = Some(match first {
            Some(HttpOutcome::Malformed(detail)) => format!("malformed response: {detail}"),
            // Handled by the `all(Response)` check above; the wildcard
            // keeps future outcome kinds from breaking the retry.
            Some(HttpOutcome::Response(_)) => unreachable!("filtered above"),
            Some(HttpOutcome::Truncated) => "connection closed mid-response".to_string(),
            Some(HttpOutcome::TooLarge) => {
                return Err(CliError::Runtime(format!(
                    "http: response exceeded the {} byte budget",
                    cfgs[0].max_bytes
                )));
            }
            Some(HttpOutcome::Timeout) => {
                format!("no response within {}", hum_duration(cfgs[0].timeout))
            }
            Some(HttpOutcome::Closed) => {
                "connection closed before a queued request was sent".to_string()
            }
            // All responses but the run came up short: the connection
            // died before the last exchange resolved.
            None => "connection closed mid-queue".to_string(),
        });
    }
    Err(CliError::Runtime(format!(
        "http: {}",
        last_err.unwrap_or_else(|| "exchange failed".to_string())
    )))
}

/// Resolved request + the knobs a recipe may override.
#[derive(Clone)]
struct HttpVerbConfig {
    retries: u32,
    timeout: Duration,
    max_bytes: u64,
    /// Accept any TLS certificate (https urls; recipe wins, mirroring
    /// retries/timeout_ms/max_bytes).
    tls_insecure: bool,
    /// Extra CA bundle path (https urls; recipe wins).
    tls_ca: Option<String>,
    /// HTTP/2 requested (recipe `http_version: "2"` or
    /// `--http-version 2`; recipe wins over the CLI flag).
    http_version: Option<String>,
    /// Send-side HPACK policy (recipe `hpack` or `--hpack`; recipe wins
    /// — the recipe/CLI precedence direction, transposed).
    hpack: Option<String>,
}

/// One per queued request: the CLI defaults + that request's recipe
/// overrides (a recipe array may tune every request independently).
fn http_verb_cfg(
    args: &crate::cli::HttpArgs,
    overrides: wrex_http::recipe::RecipeOverrides,
) -> Result<HttpVerbConfig, CliError> {
    // Recipe wins over the CLI flag (the retries/timeout_ms/max_bytes
    // precedence direction, transposed).
    let http_version = overrides.http_version.or_else(|| args.http_version.clone());
    Ok(HttpVerbConfig {
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
        // Recipe tls knobs are additive overrides of the CLI flags
        // (same precedence direction as retries/timeout_ms/max_bytes).
        tls_insecure: overrides.tls_insecure.unwrap_or(args.tls_insecure),
        tls_ca: overrides.tls_ca.clone().or_else(|| args.tls_ca.clone()),
        http_version,
        hpack: overrides.hpack.clone().or_else(|| args.hpack.clone()),
    })
}

/// Materialize the whole request queue: `--recipe FILE` (a single
/// object, a top-level array, or `{"requests": [...]}`) or the
/// positional `[METHOD] URL...` grammar (a URL-looking first token ⇒
/// GET + a URL list; otherwise the first token is the METHOD).
fn build_http_requests(
    args: &crate::cli::HttpArgs,
) -> Result<(Vec<wrex_http::HttpRequestSpec>, Vec<HttpVerbConfig>), CliError> {
    use wrex_http::{HttpRequestSpec, Recipe};

    if let Some(path) = args.recipe.as_deref() {
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
        let recipes =
            Recipe::parse_recipes(&raw).map_err(|e| usage(format!("bad recipe `{path}`: {e}")))?;
        let mut specs = Vec::with_capacity(recipes.len());
        let mut cfgs = Vec::with_capacity(recipes.len());
        for recipe in recipes {
            let (spec, overrides) = recipe
                .into_request()
                .map_err(|e| usage(format!("bad recipe `{path}`: {e}")))?;
            specs.push(spec);
            cfgs.push(http_verb_cfg(args, overrides)?);
        }
        return Ok((specs, cfgs));
    }

    // Positional grammar: [METHOD] URL... — a URL-looking first token
    // implies GET for every positional; otherwise the first is METHOD.
    let (method, urls): (&str, Vec<&str>) = match args.positional.as_slice() {
        [] => {
            return Err(usage(
                "http needs a URL (or --recipe FILE): wrex http [METHOD] URL...",
            ));
        }
        // A URL-looking first token ⇒ GET + a URL list (tranche 9a);
        // both schemes — an `https://` list must not fall into the
        // METHOD slot (caught by the T15 CLI suite).
        [first, rest @ ..]
            if rest.is_empty() || first.starts_with("http://") || first.starts_with("https://") =>
        {
            ("GET", args.positional.iter().map(|s| s.as_str()).collect())
        }
        [first, rest @ ..] => (first.as_str(), rest.iter().map(|s| s.as_str()).collect()),
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
    // -H/--data apply to every URL (a shared request recipe).
    let mut specs = Vec::with_capacity(urls.len());
    for url in &urls {
        let spec = HttpRequestSpec::build(method, url, &headers, body.clone())
            .map_err(|e| usage(format!("http: {e}")))?;
        specs.push(spec);
    }
    let cfg = http_verb_cfg(args, wrex_http::recipe::RecipeOverrides::default())?;
    let cfgs = vec![cfg; specs.len()];
    Ok((specs, cfgs))
}

/// Resolve the URI's authority to a socket address for TcpDriver.
/// Tranche 10a: family-aware — bracketed v6 literals (RFC 3986) and
/// v6-resolving names pick `AF_INET6` peers.
fn tcp_peer(uri: &wrex_http::http::Uri) -> Result<std::net::SocketAddr, CliError> {
    use std::net::ToSocketAddrs;
    let authority = uri
        .authority()
        .ok_or_else(|| usage("url has no host".to_string()))?;
    let host_raw = authority.host();
    // The http crate keeps IPv6 literal brackets in `host()`; strip
    // them for the resolver (std's tuple parser takes the bare form).
    let is_v6_literal = host_raw.starts_with('[') && host_raw.ends_with(']');
    let host = if is_v6_literal {
        &host_raw[1..host_raw.len() - 1]
    } else {
        host_raw
    };
    let port = authority
        .port_u16()
        .unwrap_or_else(|| match uri.scheme_str() {
            // Scheme-defaulted ports (explicit ports win).
            Some("https") => 443,
            _ => 80,
        });
    // Hosts are IP addresses for the driver; resolve names via std.
    let mut addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| CliError::Runtime(format!("cannot resolve `{host}`: {e}")))?;
    let addr = if let Ok(literal) = host.parse::<std::net::IpAddr>() {
        // An IP literal picks its own family out of the resolver list
        // (names may resolve to both).
        addrs
            .find(|a| a.ip() == literal)
            .ok_or_else(|| CliError::Runtime(format!("no address for `{host}`")))?
    } else {
        addrs
            .next()
            .ok_or_else(|| CliError::Runtime(format!("no address for `{host}`")))?
    };
    Ok(addr)
}

/// Local bind for the TCP connection: -i's address when given (multi-
/// homed determinism), with --source-port honored. Tranche 10a: the
/// bind picks the iface address of `family` (the peer's family — a
/// cross-family bind is a kernel EINVAL).
fn tcp_bind(
    common: &Common,
    source_port: Option<u16>,
    family: std::net::IpAddr,
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
    let ip = match family {
        std::net::IpAddr::V4(_) => entry
            .ipv4s
            .first()
            .copied()
            .map(std::net::IpAddr::V4)
            .ok_or_else(|| {
                CliError::Runtime(format!("iface `{iface}` has no IPv4 source address"))
            })?,
        std::net::IpAddr::V6(_) => entry
            .ipv6s
            .first()
            .copied()
            .map(std::net::IpAddr::V6)
            .ok_or_else(|| {
                CliError::Runtime(format!("iface `{iface}` has no IPv6 source address"))
            })?,
    };
    Ok(Some(std::net::SocketAddr::new(
        ip,
        source_port.unwrap_or(0),
    )))
}

/// Render one response as a JSON value (the `--format json` shape).
fn http_response_json(resp: &wrex_http::HttpResponse) -> serde_json::Value {
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
    serde_json::json!({
        "status": resp.status.as_u16(),
        "reason": resp.reason,
        "version": match resp.version {
            http2 if http2 == wrex_http::http::Version::HTTP_2 => "HTTP/2",
            http10 if http10 == wrex_http::http::Version::HTTP_10 => "HTTP/1.0",
            _ => "HTTP/1.1",
        },
        "headers": headers,
        "body_hex": hex::encode(&resp.body),
    })
}

/// Render the completed exchanges, in queue order. A keep-alive queue
/// prints every response (text/raw stream them; json wraps a queue in
/// an array, a lone response stays the T4 object). `--fail` is handled
/// by the caller (responses stay data: they print first).
fn render_http_responses(
    responses: &[wrex_http::HttpResponse],
    format: Format,
) -> Result<(), CliError> {
    for resp in responses {
        let status = resp.status.as_u16();
        match format {
            Format::Raw => write_stdout(&resp.body)?,
            Format::Text => {
                let mut out = format!(
                    "HTTP/{} {} {}\r\n",
                    match resp.version {
                        wrex_http::http::Version::HTTP_10 => "1.0".to_string(),
                        wrex_http::http::Version::HTTP_2 => "2".to_string(),
                        _ => "1.1".to_string(),
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
                // One JSON document for the whole run: a lone response
                // keeps the T4 object shape; a queue is an array.
                let json = if responses.len() == 1 {
                    http_response_json(resp)
                } else {
                    serde_json::Value::Array(responses.iter().map(http_response_json).collect())
                };
                let mut out = serde_json::to_string_pretty(&json)
                    .map_err(|e| CliError::Runtime(format!("json: {e}")))?;
                out.push('\n');
                write_stdout(out.as_bytes())?;
                return Ok(());
            }
            Format::Jsonl | Format::Hex => unreachable!("rejected above"),
        }
    }
    Ok(())
}

// --- query --------------------------------------------------------------------

/// `wrex query`: one seeded DNS question over a raw UDP datagram, the
/// reply dissected to stdout. A reply is exit 0 whatever the rcode says
/// (NXDOMAIN/SERVFAIL are data); silence after all attempts is exit 1.
fn query(registry: &Registry, args: &crate::cli::QueryArgs) -> Result<(), CliError> {
    use wrex_dns::QueryConfig;

    let common = &args.common;
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
    // Tranche 10a: either family. The raw UDP path roots the query at
    // ipv4/ipv6 per the server family; --tcp/--tls ride the (now)
    // dual-family kernel driver.
    let server: std::net::IpAddr = server_raw.parse().map_err(|_| {
        usage(format!(
            "bad server `{server_raw}` (expected an IP address)"
        ))
    })?;
    let timeout = duration_arg(args.timeout.as_deref())?.unwrap_or(SCAN_DEFAULT_TIMEOUT);
    let retries = args.retries.unwrap_or(1);
    let seed = args.seed.unwrap_or_else(time_seed);
    let cfg = QueryConfig {
        server,
        // --tls (DNS-over-TLS) defaults to the RFC 7858 port.
        port: args.port.unwrap_or(if args.tls { 853 } else { 53 }),
        name: args.name.trim().trim_end_matches('.').to_string(),
        qtype: args.qtype.clone().unwrap_or_else(|| "A".to_string()),
        qclass: args.qclass.clone().unwrap_or_else(|| "IN".to_string()),
        rd: !common.no_autofill,
        retries,
        timeout,
        seed,
    };

    // Grammar/name errors surface as usage (exit 2) BEFORE any socket
    // is opened (the sessions validate in `new`).
    //
    // Perf-pass 3b: EVERY transport rides a kernel socket — no -i, no
    // capabilities (`-i`, when given, pins the source address for
    // multihomed determinism). Arbitrary L3/L4 crafting stays in the
    // craft/send verbs; the raw-UDP + AF_PACKET tap path this replaced
    // measured ~15-19ms of fixed cost per invocation (the perf-diff
    // dns/udp row).
    if args.tcp || args.tls {
        let src = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        return query_tcp(registry, cfg, args, format, src);
    }
    query_udp(registry, cfg, args, format)
}

/// `wrex query` default mode: one seeded DNS question over a kernel
/// UDP socket ([`wrex_io::UdpDriver`] — the dig-style transport). The
/// session retransmits the SAME bytes after each attempt timeout (DNS
/// keeps the id); the kernel's `connect(2)` demux replaces the raw
/// path's 4-tuple reply matching. The reply dissects from the `dns`
/// root — the same output shape as `--tcp`/`--tls`, whose kernels own
/// L3/L4 likewise.
fn query_udp(
    registry: &Registry,
    cfg: wrex_dns::QueryConfig,
    args: &crate::cli::QueryArgs,
    format: Format,
) -> Result<(), CliError> {
    use wrex_dns::{DnsReply, DnsUdpSession};

    // Seeded identity comes from the same rng draws as --tcp (sport,
    // then id): the same --seed identifies the same exchange on either
    // transport; the wire bytes are the BARE dns message (the kernel
    // owns L3/L4 here).
    let mut rng = wrex_io::Rng::new(cfg.seed);
    let sport = rng.range_u16(32768, 60999);
    let id = (rng.next_u64() & 0xffff) as u16;
    let query = wrex_dns::build_tcp_query(registry, &cfg, 0, id)
        .map_err(|e| usage(format!("query: {e}")))?;

    // Optional source pin: the `-i` iface's address for the server's
    // family (without -i the kernel routes and picks). The seeded
    // sport binds when free; a taken port falls back to the kernel's
    // ephemeral pick inside the driver (never a failure, and the dns
    // message bytes stay seed-identical either way).
    let bind = match args.common.iface.as_deref() {
        None => None,
        Some(iface) => {
            let table = IfTable::from_system()
                .map_err(|e| CliError::Runtime(format!("reading interfaces: {e}")))?;
            let entry = table.get(iface).ok_or_else(|| {
                CliError::Runtime(format!(
                    "unknown iface `{iface}` (available: {})",
                    table.names().join(", ")
                ))
            })?;
            let src = match cfg.server {
                std::net::IpAddr::V4(_) => entry
                    .ipv4s
                    .first()
                    .copied()
                    .map(std::net::IpAddr::V4)
                    .ok_or_else(|| {
                    CliError::Runtime(format!("iface `{iface}` has no IPv4 source address"))
                })?,
                std::net::IpAddr::V6(_) => entry
                    .ipv6s
                    .first()
                    .copied()
                    .map(std::net::IpAddr::V6)
                    .ok_or_else(|| {
                    CliError::Runtime(format!("iface `{iface}` has no IPv6 source address"))
                })?,
            };
            Some(std::net::SocketAddr::new(src, sport))
        }
    };

    let server = cfg.server;
    let timeout = cfg.timeout;
    let peer = std::net::SocketAddr::new(server, cfg.port);
    let mut driver = wrex_io::UdpDriver::connect(peer, bind)
        .map_err(|e| CliError::Runtime(format!("query: {e}")))?;
    let mut session = DnsUdpSession::new(registry, cfg, query, id, Instant::now())
        .map_err(|e| usage(format!("query: {e}")))?;
    let outcomes = wrex_session::run(&mut session, &mut driver, &wrex_io::SystemClock)
        .map_err(|e| CliError::Runtime(format!("query: {e}")))?;

    match outcomes.into_iter().next() {
        Some(DnsReply::Reply(pkt)) => write_dns_reply(&pkt, format),
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

/// Render a matched DNS reply (a dns-rooted `DissectedPacket`) in the
/// requested format — shared by both kernel transports.
fn write_dns_reply(
    pkt: &wrex_core::dissect::DissectedPacket,
    format: Format,
) -> Result<(), CliError> {
    let out = match format {
        Format::Text => {
            let mut s = dissect_to_text(pkt);
            s.push('\n');
            s
        }
        Format::Json => {
            let mut s = serde_json::to_string_pretty(pkt)
                .map_err(|e| CliError::Runtime(format!("json: {e}")))?;
            s.push('\n');
            s
        }
        Format::Jsonl => {
            let mut s = dissect_to_jsonl(pkt);
            s.push('\n');
            s
        }
        Format::Raw | Format::Hex => unreachable!("rejected in query()"),
    };
    write_stdout(out.as_bytes())
}

/// `query --tcp`: RFC 7766 length-prefixed DNS over a fresh kernel TCP
/// connection per attempt (the UDP session retries internally; TCP
/// reconnects, per the frozen plan). `--tls` wraps the same exchange
/// in TLS (RFC 7858 DNS-over-TLS): same length-prefixed wire bytes,
/// fresh TLS connection per attempt, server name = `--server`.
#[allow(clippy::too_many_arguments)]
fn query_tcp(
    registry: &Registry,
    cfg: wrex_dns::QueryConfig,
    args: &crate::cli::QueryArgs,
    format: Format,
    src: std::net::IpAddr,
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
        // Tranche 10a: the peer speaks either family (the driver is
        // dual-family; rustls's socket is the only difference for --tls).
        let peer = std::net::SocketAddr::new(server, cfg.port);
        let bind = None;
        // --tls picks the TLS driver (same stream conventions); the
        // session and wire bytes are identical either way.
        let tls_cfg = if args.tls {
            let ca_der = match &args.tls_ca {
                Some(path) => {
                    Some(wrex_tls::load_ca_file(path).map_err(|e| usage(format!("query: {e}")))?)
                }
                None => None,
            };
            Some(wrex_tls::TlsConfig {
                // Server name = the --server host (an IP literal here:
                // matched against the cert's IP SAN).
                server_name: server.to_string(),
                insecure: args.tls_insecure,
                ca_der,
                alpn_protocols: vec![],
            })
        } else {
            None
        };
        let mut driver: Box<dyn wrex_io::Driver> = match &tls_cfg {
            Some(tcfg) => Box::new(
                wrex_tls::TlsDriver::connect(peer, bind, timeout, tcfg)
                    .map_err(|e| CliError::Runtime(format!("query --tls: {e}")))?,
            ),
            None => Box::new(
                wrex_io::TcpDriver::connect(peer, bind, timeout)
                    .map_err(|e| CliError::Runtime(format!("query --tcp: {e}")))?,
            ),
        };
        let mut session =
            DnsTcpSession::new(registry, cfg.clone(), query.clone(), id, Instant::now())
                .map_err(|e| usage(format!("query: {e}")))?;
        let outcomes = wrex_session::run(&mut session, driver.as_mut(), &wrex_io::SystemClock)
            .map_err(|e| CliError::Runtime(format!("query --tcp: {e}")))?;
        match outcomes.into_iter().next() {
            Some(DnsTcpReply::Reply(pkt)) => {
                return write_dns_reply(&pkt, format);
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
    use std::io::Write;
    use std::net::Ipv4Addr;

    /// A failing writer (EPIPE-class) maps to CliError::Runtime, and a
    /// succeeding one round-trips (pass-2 fault injection).
    #[test]
    fn write_all_flush_maps_writer_faults_to_runtime() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "pump closed",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        match write_all_flush(&mut Broken, b"data") {
            Err(CliError::Runtime(msg)) => {
                assert!(msg.starts_with("stdout: "), "{msg}");
            }
            other => panic!("broken writer must be a Runtime error: {other:?}"),
        }
        // A partial writer (writes half, then EPIPE): same mapping.
        struct Half;
        impl Write for Half {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                Ok(b.len() / 2)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "closed",
                ))
            }
        }
        assert!(matches!(
            write_all_flush(&mut Half, b"abcd"),
            Err(CliError::Runtime(_))
        ));
        // Healthy path: bytes land, flush called.
        let mut sink = Vec::new();
        write_all_flush(&mut sink, b"ok").unwrap();
        assert_eq!(sink, b"ok");
    }

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

    fn common(format: Option<&str>, strict: bool, no_autofill: bool) -> Common {
        Common {
            iface: None,
            format: format.map(str::to_string),
            verbose: 0,
            no_autofill,
            strict,
        }
    }

    #[test]
    fn format_parse_table() {
        // Default when absent; each spelling; unknown → usage error.
        assert_eq!(
            Format::parse(&common(None, false, false), Format::Raw).unwrap(),
            Format::Raw
        );
        assert_eq!(
            Format::parse(&common(None, false, false), Format::Jsonl).unwrap(),
            Format::Jsonl
        );
        for (spelling, want) in [
            ("raw", Format::Raw),
            ("hex", Format::Hex),
            ("text", Format::Text),
            ("json", Format::Json),
            ("jsonl", Format::Jsonl),
        ] {
            assert_eq!(
                Format::parse(&common(Some(spelling), false, false), Format::Raw).unwrap(),
                want
            );
        }
        assert!(Format::parse(&common(Some("yaml"), false, false), Format::Raw).is_err());
        // parse_opt: absent → None (the capture tee stays quiet);
        // present → Some (jsonl default) / the usage error propagates.
        assert_eq!(
            Format::parse_opt(&common(None, false, false)).unwrap(),
            None
        );
        assert_eq!(
            Format::parse_opt(&common(Some("raw"), false, false)).unwrap(),
            Some(Format::Raw)
        );
        assert!(Format::parse_opt(&common(Some("yaml"), false, false)).is_err());
    }

    #[test]
    fn hum_duration_boundaries() {
        assert_eq!(hum_duration(Duration::from_millis(500)), "500ms");
        assert_eq!(hum_duration(Duration::from_millis(999)), "999ms");
        // >= 1000ms flips to seconds with one decimal.
        assert_eq!(hum_duration(Duration::from_millis(1000)), "1.0s");
        assert_eq!(hum_duration(Duration::from_millis(1500)), "1.5s");
        assert_eq!(hum_duration(Duration::from_secs(2)), "2.0s");
    }

    #[test]
    fn jittered_step_zero_jitter_is_the_base_step() {
        let mut rng = wrex_io::Rng::new(1);
        // No jitter: the base step rides through unchanged.
        assert_eq!(
            jittered_step(Duration::from_millis(200), Duration::ZERO, &mut rng),
            Duration::from_millis(200)
        );
        // Seeded: a pinned seed gives a deterministic (replayable) step.
        let a = {
            let mut rng = wrex_io::Rng::new(0x5eed);
            jittered_step(Duration::from_secs(1), Duration::from_millis(100), &mut rng)
        };
        let b = {
            let mut rng = wrex_io::Rng::new(0x5eed);
            jittered_step(Duration::from_secs(1), Duration::from_millis(100), &mut rng)
        };
        assert_eq!(a, b);
        // The jitter magnitude bounds the delta.
        assert!(
            a >= Duration::from_millis(900) && a <= Duration::from_millis(1100),
            "jittered step out of bounds: {a:?}"
        );
    }

    #[test]
    fn render_spec_text_shapes() {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("src".into(), Value::Mac([1, 2, 3, 4, 5, 6]));
        fields.insert("type".into(), Value::Int(2048));
        let spec = PacketSpec::new(
            vec![wrex_core::LayerSpec::with_fields("eth", fields)],
            Some(Value::Bytes(bytes::Bytes::from_static(&[0xde, 0xad]))),
        );
        let mut out = String::new();
        render_spec_text(&spec, &mut out);
        assert_eq!(
            out,
            "eth\n  src: 01:02:03:04:05:06\n  type: 2048\npayload: dead\n"
        );
        // No layers/payload: empty render.
        let mut out = String::new();
        render_spec_text(&PacketSpec::default(), &mut out);
        assert_eq!(out, "");
    }

    #[test]
    fn http_body_grammar() {
        assert_eq!(http_body("hello").unwrap().as_ref(), b"hello".as_slice());
        assert_eq!(
            http_body("hex:deadbeef").unwrap().as_ref(),
            [0xde, 0xad, 0xbe, 0xef].as_ref()
        );
        // Plain text keeps bytes verbatim (not hex-decoded).
        assert_eq!(http_body("zz").unwrap().as_ref(), b"zz".as_slice());
        assert!(http_body("hex:zz").is_err());
        // `@<path>` reads a file.
        let dir = std::env::temp_dir().join("wrex-verbs-body-test");
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("body.bin");
        std::fs::write(&f, [0xaa, 0xbb]).unwrap();
        assert_eq!(
            http_body(&format!("@{}", f.display())).unwrap().as_ref(),
            [0xaa, 0xbb].as_ref()
        );
        assert!(http_body("@/no/such/wrex/path").is_err());
    }

    #[test]
    fn tcp_peer_resolves_ip_literals_and_scheme_ports() {
        let uri: wrex_http::http::Uri = "http://127.0.0.1:8080/x".parse().unwrap();
        assert_eq!(
            tcp_peer(&uri).unwrap(),
            std::net::SocketAddr::from(([127, 0, 0, 1], 8080))
        );
        // Scheme defaults: https → 443, http → 80 (no explicit port).
        let uri: wrex_http::http::Uri = "https://127.0.0.1/".parse().unwrap();
        assert_eq!(
            tcp_peer(&uri).unwrap(),
            std::net::SocketAddr::from(([127, 0, 0, 1], 443))
        );
        let uri: wrex_http::http::Uri = "http://127.0.0.1/".parse().unwrap();
        assert_eq!(
            tcp_peer(&uri).unwrap(),
            std::net::SocketAddr::from(([127, 0, 0, 1], 80))
        );
        // IPv6 literal (bracket-stripped) resolves on its own family.
        let uri: wrex_http::http::Uri = "http://[::1]:9/".parse().unwrap();
        assert_eq!(
            tcp_peer(&uri).unwrap(),
            std::net::SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 9))
        );
        // No host → usage error.
        let uri: wrex_http::http::Uri = "not-a-url".parse().unwrap();
        assert!(tcp_peer(&uri).is_err());
    }

    fn http_resp() -> wrex_http::HttpResponse {
        let mut headers = wrex_http::http::HeaderMap::new();
        headers.append(
            "X-Wrex",
            wrex_http::http::HeaderValue::from_str("1").unwrap(),
        );
        headers.append(
            "X-Wrex",
            wrex_http::http::HeaderValue::from_str("2").unwrap(),
        );
        wrex_http::HttpResponse {
            status: wrex_http::http::StatusCode::NOT_FOUND,
            reason: "Not Found".to_string(),
            version: wrex_http::http::Version::HTTP_11,
            headers,
            body: "no".into(),
        }
    }

    #[test]
    fn http_response_json_shape() {
        let v = http_response_json(&http_resp());
        assert_eq!(v["status"], 404);
        assert_eq!(v["reason"], "Not Found");
        assert_eq!(v["version"], "HTTP/1.1");
        assert_eq!(v["body_hex"], "6e6f");
        // Duplicate headers merge into one array (order kept).
        assert_eq!(v["headers"]["x-wrex"], serde_json::json!(["1", "2"]));
    }

    #[test]
    fn render_findings_formats() {
        let finding = wrex_fuzz::Finding {
            target: wrex_scan::ScanAddr::V4(Ipv4Addr::LOCALHOST),
            port: Some(22),
            proto: "tcp",
            round: None,
            strategy: "baseline",
            outcome: wrex_fuzz::Outcome::Silence,
            attempts: 1,
            rtt_ms: None,
            probe_hex: "aa".to_string(),
            reply_hex: None,
        };
        // json: one pretty array + trailing newline.
        let json = render_findings(std::slice::from_ref(&finding), Format::Json).unwrap();
        assert!(json.starts_with('[') && json.ends_with("]\n"));
        assert!(json.contains(r#""outcome": "silence""#), "{json}");
        // jsonl: one compact line per finding.
        let jsonl = render_findings(std::slice::from_ref(&finding), Format::Jsonl).unwrap();
        assert_eq!(jsonl.lines().count(), 1);
        assert!(jsonl.contains(r#""outcome":"silence""#), "{jsonl}");
        // text: the text_line() shape.
        let text = render_findings(&[finding], Format::Text).unwrap();
        assert!(
            text.contains("silence") && text.contains("22/tcp"),
            "{text}"
        );
    }

    #[test]
    fn patch_error_mappings() {
        // Grammar problems are usage (exit 2); frame-ordinal runtime
        // problems carry their position.
        match patch_usage(crate::edit::EditError::Usage("boom".to_string())) {
            CliError::Usage(lines) => assert!(lines[0].starts_with("patch: "), "{lines:?}"),
            other => panic!("usage mapping: {other:?}"),
        }
        match patch_runtime(3, crate::edit::EditError::Runtime("boom".to_string())) {
            CliError::Runtime(msg) => assert!(msg.starts_with("frame 3: "), "{msg}"),
            other => panic!("runtime mapping: {other:?}"),
        }
    }

    #[test]
    fn encode_opts_and_strict_gate() {
        let o = encode_opts(&common(None, false, false));
        assert!((o.autofill, o.strict) == (true, false));
        let o = encode_opts(&common(None, false, true));
        assert!((o.autofill, o.strict) == (false, false));
        let o = encode_opts(&common(None, true, false));
        assert!((o.autofill, o.strict) == (true, true));
        // check_strict: violations only fail under --strict, with one
        // `path: message` line each plus the trailer.
        let encoded = wrex_core::encode::Encoded {
            bytes: bytes::Bytes::new(),
            violations: vec![wrex_core::encode::Violation {
                path: "ipv4.ttl".into(),
                message: "is zero".into(),
            }],
        };
        assert!(check_strict(&common(None, false, false), &encoded).is_ok());
        match check_strict(&common(None, true, false), &encoded) {
            Err(CliError::Usage(lines)) => {
                assert_eq!(
                    lines,
                    vec![
                        "ipv4.ttl: is zero".to_string(),
                        "craft/send --strict: packet failed validation".to_string(),
                    ]
                );
            }
            other => panic!("strict gate: {other:?}"),
        }
    }

    #[test]
    fn iface_autofill_fills_only_missing_sources() {
        let entry = wrex_io::IfEntry {
            name: "lo".into(),
            mac: [0xaa, 1, 2, 3, 4, 5],
            mtu: 65536,
            up: true,
            ipv4s: vec![Ipv4Addr::LOCALHOST],
            ipv6s: vec!["::1".parse().unwrap()],
            ifindex: 1,
        };
        let mut spec = PacketSpec::new(
            vec![
                wrex_core::LayerSpec::with_fields(
                    "eth",
                    [("dst".into(), Value::Mac([9; 6]))].into_iter().collect(),
                ),
                wrex_core::LayerSpec::with_fields("ipv4", std::collections::BTreeMap::new()),
            ],
            None,
        );
        apply_iface_autofill(&mut spec, &entry, true);
        assert_eq!(
            spec.layers[0].fields.get("src"),
            Some(&Value::Mac(entry.mac))
        );
        assert_eq!(
            spec.layers[1].fields.get("src"),
            Some(&Value::Ipv4(Ipv4Addr::LOCALHOST))
        );
        // autofill=false: nothing changes.
        let mut spec2 = PacketSpec::new(vec![wrex_core::LayerSpec::new("eth")], None);
        apply_iface_autofill(&mut spec2, &entry, false);
        assert!(!spec2.layers[0].fields.contains_key("src"));
        // Existing src values are never overwritten.
        let mut spec3 = PacketSpec::new(
            vec![wrex_core::LayerSpec::with_fields(
                "eth",
                [("src".into(), Value::Mac([7; 6]))].into_iter().collect(),
            )],
            None,
        );
        apply_iface_autofill(&mut spec3, &entry, true);
        assert_eq!(spec3.layers[0].fields.get("src"), Some(&Value::Mac([7; 6])));
        // No IPv4s on the entry → ipv4.src stays absent.
        let mut no4 = entry.clone();
        no4.ipv4s.clear();
        let mut spec4 = PacketSpec::new(vec![wrex_core::LayerSpec::new("ipv4")], None);
        apply_iface_autofill(&mut spec4, &no4, true);
        assert!(!spec4.layers[0].fields.contains_key("src"));
    }
}
