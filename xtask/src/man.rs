//! Man page generation (systemd-style split: one page per concern).
//!
//! - `wrex(1)` renders from the clap definition, so the page mirrors
//!   `--help` exactly (one source of truth for the CLI surface).
//! - `wrex-<kind>(7)` renders per-protocol pages from the live registry
//!   schemas: `LayerSchema::doc` + `FieldSchema::{name,kind,default,
//!   required,bit_names,doc}` — the same in-code documentation the
//!   rustdoc and `wrex fields` output carry.
//!
//! Deterministic output (no timestamps): regeneration is diffable, and
//! CI checks `git diff --exit-code -- man/` after running it.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use clap::CommandFactory as _;
use wrex_core::schema::LayerSchema;

/// Frozen manual date (man pages conventionally carry a release date;
/// pinned so regeneration stays byte-identical between runs).
const MAN_DATE: &str = "2026-10-18";

/// Generate every page into `<root>/man/`; returns the output directory.
pub fn generate(root: &Path) -> PathBuf {
    let dir = root.join("man");
    std::fs::create_dir_all(&dir).expect("mkdir man/");
    let cmd = wrex::cli::Cli::command();
    let version = cmd.get_version().unwrap_or("0.1.0").to_string();

    // wrex(1): straight from the clap definition (== --help).
    let mut buf = Vec::new();
    clap_mangen::Man::new(cmd.clone())
        .render(&mut buf)
        .expect("render wrex(1)");
    write(&dir.join("wrex.1"), &buf);

    // wrex-<verb>(1): one page per subcommand so the cross-references
    // clap_mangen emits in wrex(1) resolve to real pages.
    for sub in cmd.get_subcommands() {
        let name = sub.get_name();
        if name == "help" {
            continue; // clap's auto-generated helper, not a real page
        }
        let mut b = Vec::new();
        clap_mangen::Man::new(sub.clone())
            .render(&mut b)
            .expect("render subcommand");
        write(&dir.join(format!("wrex-{name}.1")), &b);
    }

    // wrex-<kind>(7): one page per registered protocol.
    let registry = wrex::standard();
    let kinds: Vec<&'static str> = registry.kinds().to_vec();
    for &kind in &kinds {
        let schema = registry.schema(kind).expect("registered kind");
        let page = proto_page(schema, &kinds, &version);
        write(&dir.join(format!("wrex-{kind}.7")), page.as_bytes());
    }
    dir
}

/// Per-protocol roff page.
fn proto_page(schema: &LayerSchema, all_kinds: &[&str], version: &str) -> String {
    let kind = schema.kind;
    let mut s = String::new();
    let _ = writeln!(
        s,
        ".TH WREX-{} 7 \"{}\" \"wrex {}\" \"wrex Manual\"",
        kind.to_uppercase(),
        MAN_DATE,
        version
    );

    let _ = writeln!(s, ".SH NAME");
    let _ = writeln!(s, "wrex-{kind} \\- {kind} layer for \\fBwrex\\fR(1)");
    let _ = writeln!(s);

    let _ = writeln!(s, ".SH SYNOPSIS");
    let _ = writeln!(
        s,
        "\\fBwrex\\fR \\fIcraft\\fR|\\fIsend\\fR [options] \\fB--layer\\fR \\fI{kind}\\fR \\fB--{kind}\\-<field>\\fR=\\fIVALUE\\fR ..."
    );
    let _ = writeln!(s, "\\fBwrex\\fR \\fIfields\\fR \\fI{kind}\\fR");
    let _ = writeln!(s);

    let _ = writeln!(s, ".SH DESCRIPTION");
    for line in schema.doc.lines() {
        let _ = writeln!(s, "{}", esc(line));
    }
    let _ = writeln!(s, ".");
    let _ = writeln!(s);

    let _ = writeln!(s, ".SH ENCAPSULATION");
    if schema.parents.is_empty() {
        let _ = writeln!(s, "Rank {} (valid stack start: no parents).", schema.rank);
    } else {
        let _ = writeln!(
            s,
            "Rank {}; stacks on {} (parents).",
            schema.rank,
            schema.parents.join(", ")
        );
    }
    let _ = writeln!(s);

    let _ = writeln!(s, ".SH \"FIELD FLAGS\"");
    let _ = writeln!(
        s,
        "Dots in field paths become dashes in flags ({}).",
        example_flags(kind, schema)
    );
    let _ = writeln!(s, "Explicit values always win over autofill and are kept");
    let _ = writeln!(
        s,
        "unvalidated; \\fB\\-\\-strict\\fR re-validates (violations exit 2)."
    );
    for f in schema.fields {
        let mut title = flag_name(kind, f.name);
        let placeholder = match f.kind {
            wrex_core::FieldKind::Bytes | wrex_core::FieldKind::ByteList => "BYTES",
            wrex_core::FieldKind::Mac => "MAC",
            wrex_core::FieldKind::Ipv4 => "IP",
            _ => "INT",
        };
        if !matches!(
            f.kind,
            wrex_core::FieldKind::Bytes
                | wrex_core::FieldKind::ByteList
                | wrex_core::FieldKind::FlagSet
        ) {
            title.push_str(format!("=\\fI{placeholder}\\fR").as_str());
        }
        let _ = writeln!(s, ".TP");
        let _ = writeln!(s, "\\fB{title}\\fR");
        let mut line = String::new();
        if !f.doc.is_empty() {
            let _ = write!(line, "{} ", esc(f.doc));
        }
        let _ = write!(
            line,
            "Type {}. Default: {}.",
            f.kind.type_name(),
            esc(&wrex::spec::render_value_flat(&f.default))
        );
        if f.required {
            let _ = write!(line, " Required.");
        }
        let _ = writeln!(s, "{line}");
        if !f.bit_names.is_empty() {
            let _ = writeln!(
                s,
                "Bit names (MSB first): {}. Aggregate \\fB{}\\fR sets the whole unit; per-bit {} sets one bit.",
                f.bit_names.join(", "),
                flag_name(kind, f.name),
                flag_name(kind, &format!("{}.{}", f.name, f.bit_names[0]))
            );
        }
    }
    let _ = writeln!(s);

    let _ = writeln!(s, ".SH EXAMPLES");
    for line in examples(kind) {
        let _ = writeln!(s, "{}", esc(&line));
    }
    let _ = writeln!(s);

    let _ = writeln!(s, ".SH \"SEE ALSO\"");
    let mut see: Vec<String> = vec!["\\fBwrex\\fR(1)".to_string()];
    for k in all_kinds {
        if *k != kind {
            see.push(format!("\\fBwrex\\-{k}\\fR(7)"));
        }
    }
    let _ = writeln!(s, "{}", see.join(", "));
    s
}

/// CLI flag for a field path: `--<kind>-<path>` with dots as dashes.
fn flag_name(kind: &str, path: &str) -> String {
    format!("\\-\\-{}\\-{}", kind, path.replace('.', "\\-"))
}

/// One inline example of this kind's flag spelling.
fn example_flags(kind: &str, schema: &LayerSchema) -> String {
    let first = schema
        .fields
        .first()
        .map(|f| format!("--{kind}-{}", f.name.replace('.', "-")))
        .unwrap_or_else(|| format!("--{kind}-<field>"));
    format!("ipv4.ttl -> --ipv4-ttl, {first}")
}

/// Kind-specific example commands (mirrors the README quickstart).
fn examples(kind: &str) -> Vec<String> {
    match kind {
        "eth" => vec![
            "wrex craft --format hex --layer eth \\\\".into(),
            "  --eth-dst=ff:ff:ff:ff:ff:ff --eth-type=0x0800".into(),
            "wrex fields eth".into(),
        ],
        "arp" => vec![
            "wrex craft --format hex --layer eth --layer arp \\\\".into(),
            "  --arp-oper=1 --arp-tpa=10.0.0.1".into(),
            "# arp.tpa is required: omitting it is an Unfillable error".into(),
        ],
        "ipv4" => vec![
            "wrex craft --format hex --layer eth --layer ipv4 \\\\".into(),
            "  --ipv4-src=127.0.0.1 --ipv4-dst=127.0.0.1 --ipv4-ttl=63".into(),
            "# CLI alias: --ip-ttl=63 == --ipv4-ttl=63".into(),
        ],
        "icmp" => vec![
            "wrex craft --format hex --layer eth --layer ipv4 --layer icmp \\\\".into(),
            "  --ipv4-src=127.0.0.1 --ipv4-dst=127.0.0.1 --icmp-type=8 \\\\".into(),
            "  --icmp-echo-id=1 --icmp-echo-seq=1 --payload=hex:deadbeef".into(),
        ],
        "udp" => vec![
            "wrex craft --format hex --layer eth --layer ipv4 --layer udp \\\\".into(),
            "  --eth-dst=ff:ff:ff:ff:ff:ff --ipv4-src=127.0.0.1 \\\\".into(),
            "  --ipv4-dst=127.0.0.1 --udp-sport=4444 --udp-dport=5555 \\\\".into(),
            "  --payload=hex:deadbeef".into(),
        ],
        "tcp" => vec![
            "wrex craft --format hex --layer eth --layer ipv4 --layer tcp \\\\".into(),
            "  --ipv4-src=127.0.0.1 --ipv4-dst=127.0.0.1 \\\\".into(),
            "  --tcp-sport=1234 --tcp-dport=80 --tcp-flags=syn,ack".into(),
        ],
        _ => vec![format!("wrex fields {kind}")],
    }
}

/// roff text escaping: backslash then hyphen (macro lines escape themselves).
fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('-', "\\-")
}

fn write(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}
