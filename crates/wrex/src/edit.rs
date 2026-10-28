//! `wrex patch` edit grammar (tranche 14): `--set path=value`,
//! `--insert AT:HEX`, `--delete AT:LEN` → engine
//! [`wrex_core::patch::Edit`]s, plus the `--scope`/`--index` parsers.
//!
//! Two phases, two error classes:
//!
//! - [`parse_edits`] validates the whole grammar against the registry
//!   schema **upfront** — unknown layers/fields, bad value spelling,
//!   scope conflicts: [`EditError::Usage`] (exit 2) before any frame is
//!   read. The set lands complete or errors, the engine's
//!   never-partial rule hoisted to parse time.
//! - [`EditSet::materialize`] resolves each `--set` against one
//!   dissected frame — span lookup + typed-value serialization at the
//!   span's width — and missing-in-THIS-frame paths surface as
//!   [`EditError::Runtime`] (exit 1, the verb names the frame). Width
//!   mismatches, bounds and re-encode rejections stay the engine's own
//!   pointed errors.
//!
//! Values parse through the pinned field grammar
//! ([`wrex_core::value::parse_value`]) and serialize through
//! [`wrex_core::encode::serialize_field_value`] at the span's width —
//! the same serialization the mut field strategy rides. Over-wide
//! bit-window values mask (the craft rule). The `wire:HEX` escape
//! hands a region raw bytes when the typed grammar cannot speak the
//! encoding: string-typed fields over RAW spans are refused pointedly
//! (dns type/class are names behind u16s, dns names are label-encoded
//! — the T13a mut-exclusion rule, so nothing writes presentation bytes
//! silently), while string-typed `ReEncode` regions stay typed (the
//! codec hook owns the encoding: dhcp `sname`/`file` NUL-pad
//! presentation bytes, dhcp `msg_type`'s 1-byte TLV wants `wire:`).

use std::collections::BTreeSet;
use std::ops::Range;

use bytes::Bytes;
use wrex_core::dissect::{DissectedPacket, FieldSpan};
use wrex_core::encode::serialize_field_value;
use wrex_core::patch::{Edit, Scope};
use wrex_core::schema::ResolvedField;
use wrex_core::value::{parse_bool, parse_hex_bytes, parse_value};
use wrex_core::{FieldKind, Registry, Value};

/// Edit-grammar failure: usage (malformed request → exit 2) vs
/// runtime (a property of the frame under the knife → exit 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EditError {
    Usage(String),
    Runtime(String),
}

impl std::fmt::Display for EditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EditError::Usage(m) => write!(f, "{m}"),
            EditError::Runtime(m) => write!(f, "{m}"),
        }
    }
}

fn usage(msg: impl Into<String>) -> EditError {
    EditError::Usage(msg.into())
}

fn runtime(msg: impl Into<String>) -> EditError {
    EditError::Runtime(msg.into())
}

/// One `--set` after static validation: everything derivable from the
/// schema alone. Frame-dependent bits (the span, the wire width)
/// resolve at [`EditSet::materialize`] time.
#[derive(Debug)]
struct ParsedSet {
    /// Full path as written (`tcp.flags.syn`).
    path: String,
    /// Layer kind (`tcp`).
    kind: &'static str,
    /// Path within the layer (`flags.syn`).
    field_path: String,
    /// Wire kind of the field (the flag parent for bit subpaths).
    wire_kind: FieldKind,
    bit_names: &'static [&'static str],
    /// The typed value (`None` for the `wire:` raw escape).
    value: Option<Value>,
    /// Raw region bytes for the `wire:` escape (`None` otherwise).
    raw: Option<Bytes>,
}

/// The parsed edit grammar, validated against the registry: the whole
/// set is static before the first frame is read.
#[derive(Debug)]
pub struct EditSet {
    sets: Vec<ParsedSet>,
    inserts: Vec<(usize, Bytes)>,
    deletes: Vec<Range<usize>>,
}

impl EditSet {
    pub fn is_empty(&self) -> bool {
        self.sets.is_empty() && self.inserts.is_empty() && self.deletes.is_empty()
    }

    /// Resolve the set against one dissected frame: span lookup +
    /// typed-value serialization at the span's width. Everything that
    /// depends on THIS frame (path present? span geometry? wire
    /// width?) fails here, pointedly.
    pub fn materialize(&self, packet: &DissectedPacket) -> Result<Vec<Edit>, EditError> {
        let mut edits =
            Vec::with_capacity(self.sets.len() + self.inserts.len() + self.deletes.len());
        for s in &self.sets {
            let span = packet
                .layers
                .iter()
                .find(|l| l.kind == s.kind)
                .and_then(|l| l.field_spans.get(s.field_path.as_str()))
                .ok_or_else(|| runtime(format!("no dissected field at path `{}`", s.path)))?;
            let bytes = if let Some(raw) = &s.raw {
                // wire:HEX — raw region bytes; the engine width-checks
                // Bytes/Bits spans and the re-encode hook validates
                // its own regions.
                raw.clone()
            } else {
                let value = s.value.as_ref().expect("typed value or raw bytes");
                // A typed Str over a RAW span cannot speak the wire
                // encoding generically (dns type/class are name-vs-
                // u16, names are label-encoded, dhcp option text is
                // raw) — the T13a mut-exclusion rule, held here too:
                // pointed refusal instead of silent presentation
                // bytes. ReEncode regions stay typed (the codec hook
                // validates and encodes); wire: covers the rest.
                if s.wire_kind == FieldKind::Str
                    && matches!(span, FieldSpan::Bytes(_) | FieldSpan::Bits { .. })
                {
                    return Err(runtime(format!(
                        "field `{}` is string-typed over a raw span — the presentation is not the wire encoding (use wire:HEX)",
                        s.path
                    )));
                }
                match span {
                    FieldSpan::Bytes(r) => {
                        let bytes =
                            serialize_field_value(s.wire_kind, s.bit_names, r.len() * 8, value)
                                .ok_or_else(|| {
                                    runtime(format!(
                                        "value for `{}` does not serialize at its {}-byte span",
                                        s.path,
                                        r.len()
                                    ))
                                })?;
                        Bytes::from(bytes)
                    }
                    FieldSpan::Bits { width, .. } => {
                        let bytes = serialize_field_value(
                            s.wire_kind,
                            s.bit_names,
                            *width as usize,
                            value,
                        )
                        .ok_or_else(|| {
                            runtime(format!(
                                "value for `{}` does not serialize at its {width}-bit window",
                                s.path
                            ))
                        })?;
                        Bytes::from(bytes)
                    }
                    // The codec owns the region's encoding: hand it
                    // the typed value's own bytes (dhcp sname/file
                    // NUL-pad presentation bytes); the hook validates,
                    // pads and width-checks. wire: is the escape for
                    // encodings the typed grammar cannot speak.
                    FieldSpan::ReEncode(_) => {
                        let bytes = reencode_value_bytes(s.wire_kind, value).ok_or_else(|| {
                            runtime(format!(
                                "value for `{}` does not serialize for its re-encode region (use wire:HEX)",
                                s.path
                            ))
                        })?;
                        Bytes::from(bytes)
                    }
                    FieldSpan::None => {
                        return Err(runtime(format!(
                            "field `{}` has no patchable span (unsupported under span-patch)",
                            s.path
                        )));
                    }
                }
            };
            edits.push(Edit::SetField {
                path: s.path.clone(),
                bytes,
            });
        }
        for (at, bytes) in &self.inserts {
            edits.push(Edit::Insert {
                at: *at,
                bytes: bytes.clone(),
            });
        }
        for at in &self.deletes {
            edits.push(Edit::Delete { at: at.clone() });
        }
        Ok(edits)
    }
}

/// Validate the whole edit grammar against the registry (usage errors
/// before any frame is read): `--set` paths resolve against the
/// schema, values parse through the pinned field grammar, shape edits
/// parse their `AT:HEX` / `AT:LEN` forms, and an edit on a
/// scope-selected derived field is the pointed static conflict the
/// engine would raise later.
pub fn parse_edits(
    registry: &Registry,
    scope: &Scope,
    set: &[String],
    insert: &[String],
    delete: &[String],
) -> Result<EditSet, EditError> {
    let mut sets = Vec::with_capacity(set.len());
    for raw in set {
        let (path, value_raw) = raw.split_once('=').ok_or_else(|| {
            usage(format!(
                "bad --set `{raw}` (expected path=value, e.g. --set ipv4.ttl=64)"
            ))
        })?;
        let (path, value_raw) = (path.trim(), value_raw.trim());
        if path.is_empty() {
            return Err(usage(format!("empty path in --set `{raw}`")));
        }
        if value_raw.is_empty() {
            return Err(usage(format!("empty value in --set `{raw}`")));
        }
        let (kind, field_path) = path
            .split_once('.')
            .ok_or_else(|| usage(format!("bad --set path `{path}` (expected <kind>.<field>)")))?;
        let codec = registry
            .get(kind)
            .ok_or_else(|| usage(format!("unknown layer `{kind}` in --set `{raw}`")))?;
        let schema = codec.schema();
        let resolved = schema
            .resolve(field_path)
            .ok_or_else(|| usage(format!("unknown field `{path}` (see: wrex fields {kind})")))?;
        let (wire_kind, bit_names, flag_bit) = match resolved {
            ResolvedField::Field(f) => (f.kind, f.bit_names, false),
            ResolvedField::RecordField { field, .. } => (field.kind, field.bit_names, false),
            ResolvedField::FlagBit { parent, .. } => (parent.kind, parent.bit_names, true),
        };
        // Edits decide bytes, scope decides recomputation — the
        // conflict is fully static (schema + scope), so it fires here:
        // exit 2 before any frame is read, never a mid-stream surprise.
        // Sub-bit paths and record fields are never derived targets
        // (the engine's own comparison rule).
        if !flag_bit
            && codec.derived().iter().any(|d| d.field() == field_path)
            && scope.selects_path(path)
        {
            return Err(usage(format!(
                "--set {path} conflicts with the scope (an edit on a field the scope recomputes): \
                 narrow the scope, drop the edit, or --no-recompute"
            )));
        }
        let (value, raw_bytes) = if let Some(hexpart) = value_raw.strip_prefix("wire:") {
            // The raw-bytes escape for codec-owned encodings.
            (
                None,
                Some(Bytes::from(
                    parse_hex_bytes(hexpart)
                        .map_err(|e| usage(format!("bad --set `{raw}`: {e}")))?,
                )),
            )
        } else {
            let value = match resolved {
                ResolvedField::FlagBit { .. } => {
                    let set = parse_bool(value_raw)
                        .map_err(|e| usage(format!("bad --set `{raw}`: {e}")))?;
                    Value::Int(u128::from(set))
                }
                ResolvedField::Field(f) => parse_value(f, value_raw)
                    .map_err(|e| usage(format!("bad --set `{raw}`: {e}")))?,
                ResolvedField::RecordField { field, .. } => parse_value(field, value_raw)
                    .map_err(|e| usage(format!("bad --set `{raw}`: {e}")))?,
            };
            (Some(value), None)
        };
        sets.push(ParsedSet {
            path: path.to_string(),
            kind: schema.kind,
            field_path: field_path.to_string(),
            wire_kind,
            bit_names,
            value,
            raw: raw_bytes,
        });
    }

    let mut inserts = Vec::with_capacity(insert.len());
    for raw in insert {
        let (at_raw, hexpart) = raw
            .split_once(':')
            .ok_or_else(|| usage(format!("bad --insert `{raw}` (expected AT:HEX)")))?;
        let at: usize = at_raw.trim().parse().map_err(|_| {
            usage(format!(
                "bad --insert `{raw}` (offset must be a decimal byte offset)"
            ))
        })?;
        let bytes = parse_hex_bytes(hexpart.trim())
            .map_err(|e| usage(format!("bad --insert `{raw}`: {e}")))?;
        if bytes.is_empty() {
            return Err(usage(format!("empty --insert `{raw}`")));
        }
        inserts.push((at, Bytes::from(bytes)));
    }

    let mut deletes = Vec::with_capacity(delete.len());
    for raw in delete {
        let (at_raw, len_raw) = raw
            .split_once(':')
            .ok_or_else(|| usage(format!("bad --delete `{raw}` (expected AT:LEN)")))?;
        let at: usize = at_raw.trim().parse().map_err(|_| {
            usage(format!(
                "bad --delete `{raw}` (offset must be a decimal byte offset)"
            ))
        })?;
        let len: usize = len_raw.trim().parse().map_err(|_| {
            usage(format!(
                "bad --delete `{raw}` (length must be a decimal byte count)"
            ))
        })?;
        if len == 0 {
            return Err(usage(format!("zero-length --delete `{raw}`")));
        }
        deletes.push(at..at + len);
    }

    Ok(EditSet {
        sets,
        inserts,
        deletes,
    })
}

/// The typed value's own bytes for a codec-owned re-encode region:
/// Str presentation bytes (the dhcp sname/file NUL-pad rule), raw
/// bytes, ints as minimal big-endian. The hook validates against the
/// region (over-length, embedded NUL, wire-name shape are its pointed
/// rejections).
fn reencode_value_bytes(kind: FieldKind, v: &Value) -> Option<Vec<u8>> {
    match (kind, v) {
        (FieldKind::Str, Value::Str(s)) => Some(s.as_bytes().to_vec()),
        (FieldKind::Bytes | FieldKind::ByteList, Value::Bytes(b)) => Some(b.to_vec()),
        (
            FieldKind::U8
            | FieldKind::U16
            | FieldKind::U32
            | FieldKind::U64
            | FieldKind::U128
            | FieldKind::FlagSet,
            Value::Int(x),
        ) => {
            let be = x.to_be_bytes();
            let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
            Some(be[first..].to_vec())
        }
        (FieldKind::Ipv4, Value::Ipv4(a)) => Some(a.octets().to_vec()),
        (FieldKind::Ipv6, Value::Ipv6(a)) => Some(a.octets().to_vec()),
        (FieldKind::Mac, Value::Mac(m)) => Some(m.to_vec()),
        _ => None,
    }
}

/// Parse the consistency-scope flags: default [`Scope::all`],
/// `--no-recompute` = [`Scope::none`] (preserve semantics),
/// `--scope SEL[,…]` = selective (`KIND.*` layer shorthand or
/// `kind.field` picks, the engine's own selector). Both flags together
/// are a pointed usage error.
pub fn parse_scope(scope: Option<&str>, no_recompute: bool) -> Result<Scope, EditError> {
    match (scope, no_recompute) {
        (Some(_), true) => Err(usage(
            "--no-recompute and --scope are mutually exclusive (one consistency scope per run)",
        )),
        (Some(raw), false) => {
            let sels: Vec<&str> = raw.split(',').map(str::trim).collect();
            Scope::select(&sels).map_err(|e| usage(e.to_string()))
        }
        (None, true) => Ok(Scope::none()),
        (None, false) => Ok(Scope::all()),
    }
}

/// Parse `--index N[-M][,…]`: 1-based ordinals in stream order (the
/// scan port-list grammar shape). Zero and reversed ranges are usage
/// errors.
pub fn parse_indices(raw: &str) -> Result<BTreeSet<usize>, EditError> {
    let mut set = BTreeSet::new();
    for tok in raw.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            return Err(usage(format!(
                "empty --index token in `{raw}` (expected N[-M][,…])"
            )));
        }
        let single = tok.split_once('-');
        let (a_raw, b_raw) = match single {
            None => (tok, None),
            Some((a, b)) => (a, Some(b)),
        };
        let parse = |s: &str| -> Result<usize, EditError> {
            s.trim().parse().map_err(|_| {
                usage(format!(
                    "bad --index token `{tok}` (expected a decimal ordinal)"
                ))
            })
        };
        let a = parse(a_raw)?;
        match b_raw {
            None => {
                if a == 0 {
                    return Err(usage("--index ordinals are 1-based (frame 1 is the first)"));
                }
                set.insert(a);
            }
            Some(b_raw) => {
                let b = parse(b_raw)?;
                if a == 0 || b == 0 {
                    return Err(usage("--index ordinals are 1-based (frame 1 is the first)"));
                }
                if a > b {
                    return Err(usage(format!(
                        "reversed --index range `{tok}` (expected N-M with N <= M)"
                    )));
                }
                // Keep the set bounded: a stray huge range must not
                // allocate it (a pcap cannot hold that many records).
                if b - a > 1_000_000 {
                    return Err(usage(format!("--index range `{tok}` too wide")));
                }
                set.extend(a..=b);
            }
        }
    }
    if set.is_empty() {
        return Err(usage(format!("empty --index `{raw}`")));
    }
    Ok(set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use wrex_core::encode::{EncodeOpts, encode};
    use wrex_core::spec::{LayerSpec, PacketSpec};
    use wrex_core::{Scope, dissect};

    fn registry() -> Registry {
        crate::standard()
    }

    fn layer(kind: &'static str, fields: &[(&'static str, Value)]) -> LayerSpec {
        let mut map = std::collections::BTreeMap::new();
        for (k, v) in fields {
            map.insert(Cow::Owned(k.to_string()), v.clone());
        }
        LayerSpec::with_fields(kind, map)
    }

    /// eth + ipv4 + tcp (SYN), autofilled — the verb's test fixture.
    fn tcp_frame(reg: &Registry) -> bytes::Bytes {
        let spec = PacketSpec::new(
            vec![
                layer("eth", &[("dst", Value::Mac([0xff; 6]))]),
                layer(
                    "ipv4",
                    &[
                        ("src", Value::Ipv4("127.0.0.1".parse().unwrap())),
                        ("dst", Value::Ipv4("127.0.0.1".parse().unwrap())),
                        ("proto", Value::Int(6)),
                    ],
                ),
                layer(
                    "tcp",
                    &[
                        ("sport", Value::Int(40000)),
                        ("dport", Value::Int(80)),
                        ("flags", Value::Int(0x02)),
                    ],
                ),
            ],
            None,
        );
        encode(
            reg,
            &spec,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .expect("encode")
        .bytes
    }

    fn one_set(reg: &Registry, frame: &[u8], raw: &str) -> Result<Vec<Edit>, EditError> {
        let scope = Scope::none();
        let es = parse_edits(reg, &scope, &[raw.to_string()], &[], &[])?;
        let p = dissect(reg, frame, "eth");
        es.materialize(&p)
    }

    #[test]
    fn set_grammar_static_errors() {
        let reg = registry();
        let scope = Scope::all();
        // no '=' / empty path / empty value / no dot / unknown kind /
        // unknown field / bad value / out-of-range int
        for raw in [
            "ipv4.ttl",
            "=7",
            "ipv4.=7",
            "ipv4=7",
            "nope.ttl=7",
            "ipv4.bogus=7",
            "ipv4.ttl=abc",
            "ipv4.ttl=999",
            "ipv4.ttl=hex:07",
        ] {
            assert!(
                parse_edits(&reg, &scope, &[raw.to_string()], &[], &[]).is_err(),
                "`{raw}` must be a usage error"
            );
        }
        // the scope conflict is static: --set tcp.checksum under the
        // default scope errors BEFORE any frame exists.
        let err =
            parse_edits(&reg, &scope, &["tcp.checksum=0001".to_string()], &[], &[]).unwrap_err();
        assert!(
            matches!(err, EditError::Usage(ref m) if m.contains("conflicts with the scope")),
            "{err}"
        );
        // ...and does not under a scope that leaves tcp alone.
        let outer = Scope::select(&["ipv4.*"]).unwrap();
        parse_edits(&reg, &outer, &["tcp.checksum=0001".to_string()], &[], &[])
            .expect("outer-only scope: no conflict");
        // flag subpaths never conflict (sub-bit paths are not derived
        // targets) and take the boolean grammar.
        parse_edits(&reg, &scope, &["tcp.flags.syn=1".to_string()], &[], &[])
            .expect("flag subpath parses");
        let err =
            parse_edits(&reg, &scope, &["tcp.flags.syn=yes".to_string()], &[], &[]).unwrap_err();
        assert!(matches!(err, EditError::Usage(_)), "{err}");
    }

    #[test]
    fn insert_delete_grammar() {
        let reg = registry();
        let scope = Scope::none();
        let es = parse_edits(
            &reg,
            &scope,
            &[],
            &["14:aabb".to_string(), "0:01".to_string()],
            &["14:2".to_string()],
        )
        .unwrap();
        assert!(!es.is_empty());
        for raw in [
            "14",     // no :
            "x:aabb", // bad offset
            "14:zz",  // bad hex
            "14:",    // empty bytes
            "0x1:aa", // hex offset (decimal only)
        ] {
            assert!(
                parse_edits(&reg, &scope, &[], &[raw.to_string()], &[]).is_err(),
                "--insert `{raw}` must be a usage error"
            );
        }
        for raw in ["14", "x:2", "14:0", "14:-2"] {
            assert!(
                parse_edits(&reg, &scope, &[], &[], &[raw.to_string()]).is_err(),
                "--delete `{raw}` must be a usage error"
            );
        }
    }

    #[test]
    fn materialize_typed_widths() {
        let reg = registry();
        let frame = tcp_frame(&reg);
        // Bytes span: 4-byte ipv4 address.
        let edits = one_set(&reg, &frame, "ipv4.dst=10.0.0.5").unwrap();
        let Edit::SetField { bytes, .. } = &edits[0] else {
            panic!("set edit");
        };
        assert_eq!(bytes, &Bytes::from_static(&[10, 0, 0, 5]));
        // Bit subpath: 1 byte for a 1-bit window; masked into the
        // container by the engine, not here.
        let edits = one_set(&reg, &frame, "ipv4.flags.df=1").unwrap();
        let Edit::SetField { bytes, .. } = &edits[0] else {
            panic!("set edit");
        };
        assert_eq!(bytes, &Bytes::from_static(&[1]));
        // FlagSet aggregate: bit names pack through the MSB-first
        // convention at the 8-bit window.
        let edits = one_set(&reg, &frame, "tcp.flags=syn,ack").unwrap();
        let Edit::SetField { bytes, .. } = &edits[0] else {
            panic!("set edit");
        };
        assert_eq!(bytes, &Bytes::from_static(&[0x12]));
        // wire: escape: raw region bytes, byte-for-byte.
        let edits = one_set(&reg, &frame, "tcp.seq=wire:0102030405060708").unwrap();
        let Edit::SetField { bytes, .. } = &edits[0] else {
            panic!("set edit");
        };
        assert_eq!(bytes, &Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]));
        // A path missing from THIS frame is a runtime error (the engine
        // wording): the fixture has no udp layer.
        let err = one_set(&reg, &frame, "udp.dport=53").unwrap_err();
        assert!(
            matches!(err, EditError::Runtime(ref m) if m.contains("no dissected field")),
            "{err}"
        );
        // A dynamic-region path on this frame: unsupported, runtime.
        let err = one_set(&reg, &frame, "tcp.options=hex:00").unwrap_err();
        assert!(matches!(err, EditError::Runtime(_)), "{err}");
    }

    #[test]
    fn reencode_typed_value_bytes() {
        assert_eq!(
            reencode_value_bytes(FieldKind::Str, &Value::Str("myserver".into())).unwrap(),
            b"myserver".to_vec()
        );
        assert_eq!(
            reencode_value_bytes(FieldKind::U8, &Value::Int(8)).unwrap(),
            vec![8]
        );
        assert_eq!(
            reencode_value_bytes(FieldKind::U32, &Value::Int(0x63825363)).unwrap(),
            vec![0x63, 0x82, 0x53, 0x63]
        );
        assert_eq!(
            reencode_value_bytes(
                FieldKind::Bytes,
                &Value::Bytes(bytes::Bytes::from_static(&[1, 2]))
            )
            .unwrap(),
            vec![1, 2]
        );
        assert!(reencode_value_bytes(FieldKind::Str, &Value::Int(1)).is_none());
    }

    #[test]
    fn scope_and_index_parsers() {
        assert!(matches!(parse_scope(None, false).unwrap(), s if s == Scope::all()));
        assert!(matches!(parse_scope(None, true).unwrap(), s if s == Scope::none()));
        assert!(parse_scope(Some("udp.*"), false).is_ok());
        assert!(parse_scope(Some("udp.checksum,ipv4.*"), false).is_ok());
        assert!(parse_scope(Some("udp.*"), true).is_err());
        assert!(parse_scope(Some("bogus"), false).is_err()); // no dot
        assert!(parse_scope(Some("udp.*, "), false).is_err()); // empty token

        let idx = parse_indices("2,5-7").unwrap();
        assert_eq!(idx, [2, 5, 6, 7].into_iter().collect());
        for bad in ["", "0", "5-3", "x", "1,", "1-", "1-2,y", "1-3000000"] {
            assert!(parse_indices(bad).is_err(), "--index `{bad}` must error");
        }
    }
}
