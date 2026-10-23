//! Field-flag → [`wrex_core::PacketSpec`] assembly from parsed matches.
//!
//! The flags themselves are clap args built from the registry schemas
//! ([`crate::cli::field_args`]); this module reads their values back,
//! applies the value grammar, and determines the layer stack (explicit
//! `--layer` order, or implied from the flags present, ranked, with
//! sibling-conflict and parents validation).

use std::collections::BTreeMap;

use clap::ArgMatches;
use wrex_core::value::parse_value;
use wrex_core::{FieldSchema, PacketSpec, Registry, SpecError, Value};

/// CLI-only kind alias table (pinned): `ip` → `ipv4`, `ip6`/`v6` → `ipv6`.
fn resolve_kind(registry: &Registry, wanted: &str) -> Result<&'static str, SpecError> {
    let canonical = match wanted {
        "ip" => "ipv4",
        "ip6" | "v6" => "ipv6",
        other => other,
    };
    match registry.get(canonical) {
        Some(c) => Ok(c.schema().kind),
        None => Err(SpecError::UnknownLayer {
            wanted: wanted.to_string(),
            known: registry.kinds().join(", "),
        }),
    }
}

/// A `--payload` value schema (Bytes grammar).
fn payload_field() -> FieldSchema {
    FieldSchema {
        name: "payload",
        kind: wrex_core::FieldKind::Bytes,
        bit_names: &[],
        default: Value::Bytes(bytes::Bytes::new()),
        required: false,
        doc: "terminal payload bytes",
    }
}

/// Flat single-line rendering of a [`Value`] (text/fields output).
///
/// ```
/// use wrex_core::value::Value;
///
/// assert_eq!(wrex::spec::render_value_flat(&Value::Int(42)), "42");
/// assert_eq!(
///     wrex::spec::render_value_flat(&Value::Mac([0x11, 0x22, 0, 0, 0, 0])),
///     "11:22:00:00:00:00",
/// );
/// assert_eq!(
///     wrex::spec::render_value_flat(&Value::Bytes("ab".into())),
///     "6162",
/// );
/// ```
pub fn render_value_flat(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::Int(n) => n.to_string(),
        Value::Bytes(b) => hex::encode(b),
        Value::Str(s) => s.clone(),
        Value::Ipv4(a) => a.to_string(),
        Value::Ipv6(a) => a.to_string(),
        Value::Mac(m) => wrex_core::mac_string(*m),
        Value::List(items) => items
            .iter()
            .map(render_value_flat)
            .collect::<Vec<_>>()
            .join(","),
    }
}

/// Long-flag spelling of a field path (mirrors [`crate::cli::field_args`]).
fn flag_long(kind: &str, path: &str) -> String {
    format!("{kind}-{}", path.replace('.', "-"))
}

/// Assemble a [`PacketSpec`] from the parsed craft/send matches.
///
/// Explicit `--layer` order validates the parents chain and requires
/// every field flag to belong to a declared layer; implied mode sorts
/// referenced kinds by rank and rejects sibling conflicts.
pub fn packet_spec_from_matches(
    registry: &Registry,
    matches: &ArgMatches,
) -> Result<PacketSpec, SpecError> {
    let declared: Vec<&'static str> = matches
        .get_many::<String>("layer")
        .map(|vals| {
            vals.map(|raw| resolve_kind(registry, raw))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    let payload = matches
        .get_one::<String>("payload")
        .map(|raw| parse_value(&payload_field(), raw))
        .transpose()?;

    let mut kind_fields: BTreeMap<&'static str, BTreeMap<String, Value>> = BTreeMap::new();
    for &kind in registry.kinds() {
        let schema = registry.schema(kind).expect("registered kind");
        let mut fields: BTreeMap<String, Value> = BTreeMap::new();
        for field in schema.fields {
            // Whole-field arg: value through the pinned value grammar.
            if let Some(raw) = matches.get_one::<String>(&flag_long(kind, field.name)) {
                fields.insert(field.name.to_string(), parse_value(field, raw)?);
            }
            // Per-bit subpaths: boolean flags.
            if field.kind == wrex_core::FieldKind::FlagSet {
                for &bit in field.bit_names {
                    let path = format!("{}.{}", field.name, bit);
                    if matches.get_flag(&flag_long(kind, &path)) {
                        fields.insert(path, Value::Bool(true));
                    }
                }
            }
        }
        // Record-section shorthands (settable, max 1): the arg id is the
        // full dashed path (`dns-qd-0-name` → spec key `qd.0.name`).
        for record in schema.records {
            if !(record.settable && record.max == Some(1)) {
                continue;
            }
            for field in record.fields {
                let arg_id = flag_long(kind, &format!("{}.0.{}", record.name, field.name));
                if let Some(raw) = matches.get_one::<String>(&arg_id) {
                    fields.insert(
                        format!("{}.0.{}", record.name, field.name),
                        parse_value(field, raw)?,
                    );
                }
            }
        }
        if !fields.is_empty() {
            kind_fields.insert(kind, fields);
        }
    }

    finalize(registry, declared, kind_fields, payload)
}

/// Stack determination + validation, shared by explicit and implied modes.
fn finalize(
    registry: &Registry,
    declared: Vec<&'static str>,
    kind_fields: BTreeMap<&'static str, BTreeMap<String, Value>>,
    payload: Option<Value>,
) -> Result<PacketSpec, SpecError> {
    // Determine the layer stack.
    let layer_kinds: Vec<&'static str> = if !declared.is_empty() {
        // Explicit mode: every field flag must belong to a declared layer.
        for kind in kind_fields.keys() {
            if !declared.contains(kind) {
                return Err(SpecError::InvalidStack {
                    detail: format!(
                        "field flags for `{kind}` require `--layer {kind}` (declared: {})",
                        declared.join(", ")
                    ),
                });
            }
        }
        declared
    } else if kind_fields.is_empty() {
        return Err(SpecError::InvalidStack {
            detail: "no layers specified; use --layer or a layer field flag".into(),
        });
    } else {
        // Implied mode: referenced kinds sorted by rank; sibling ranks
        // (two rank-30 kinds, or arp+ipv4) are ambiguous → suggest --layer.
        let mut ranked: Vec<(u16, &'static str)> = kind_fields
            .keys()
            .map(|&k| (registry.get(k).unwrap().schema().rank, k))
            .collect();
        ranked.sort();
        let kinds: Vec<&'static str> = ranked.iter().map(|(_, k)| *k).collect();
        let mut prev_rank: Option<u16> = None;
        for &(rank, k) in &ranked {
            if prev_rank == Some(rank) {
                return Err(SpecError::InvalidStack {
                    detail: format!(
                        "sibling conflict: `{k}` shares rank {rank} with another layer; pass explicit `--layer` order"
                    ),
                });
            }
            prev_rank = Some(rank);
        }
        kinds
    };

    // Parents validation (explicit or implied): layer[i] must list
    // layer[i-1] in its parents (the first layer may start anywhere).
    for w in 1..layer_kinds.len() {
        let (prev, cur) = (layer_kinds[w - 1], layer_kinds[w]);
        let parents = registry.get(cur).unwrap().schema().parents;
        if !parents.contains(&prev) {
            return Err(SpecError::InvalidStack {
                detail: format!(
                    "{cur} requires parent {} (got `{prev}`); use --layer to order the stack",
                    parents.join(" or ")
                ),
            });
        }
    }

    let layers = layer_kinds
        .into_iter()
        .map(|k| {
            let fields = kind_fields.get(&k).cloned().unwrap_or_default();
            wrex_core::LayerSpec::with_fields(k, fields)
        })
        .collect();
    Ok(PacketSpec::new(layers, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::build_cli;

    fn reg() -> Registry {
        crate::standard()
    }

    /// Parse a full `wrex craft …` argv through the real command.
    fn spec_of(args: &[&str]) -> Result<PacketSpec, SpecError> {
        let mut argv = vec!["wrex", "craft"];
        argv.extend_from_slice(args);
        let cmd = build_cli();
        let matches = cmd
            .try_get_matches_from(argv)
            .expect("argv parses (usage errors assert separately)");
        packet_spec_from_matches(&reg(), matches.subcommand_matches("craft").unwrap())
    }

    #[test]
    fn explicit_golden_spec() {
        let spec = spec_of(&[
            "--layer",
            "eth",
            "--layer",
            "ipv4",
            "--layer",
            "udp",
            "--eth-dst=ff:ff:ff:ff:ff:ff",
            "--ipv4-src=127.0.0.1",
            "--ipv4-dst=127.0.0.1",
            "--udp-sport=4444",
            "--udp-dport=5555",
            "--payload=hex:deadbeef",
        ])
        .unwrap();
        assert_eq!(
            spec.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec!["eth", "ipv4", "udp"]
        );
        assert!(matches!(spec.payload, Some(Value::Bytes(_))));
    }

    #[test]
    fn implied_mode_sorts_by_rank() {
        let spec = spec_of(&[
            "--udp-sport=4444",
            "--eth-dst=ff:ff:ff:ff:ff:ff",
            "--ipv4-src=127.0.0.1",
            "--ipv4-dst=127.0.0.1",
            "--udp-dport=5555",
            "--payload=hex:deadbeef",
        ])
        .unwrap();
        assert_eq!(
            spec.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec!["eth", "ipv4", "udp"]
        );
    }

    #[test]
    fn alias_ip_is_ipv4() {
        let spec = spec_of(&["--ip-ttl=63"]).unwrap();
        assert_eq!(spec.layers[0].kind, "ipv4");
        assert_eq!(spec.layers[0].fields.get("ttl"), Some(&Value::Int(63)));
    }

    #[test]
    fn flagbit_subpaths() {
        let spec = spec_of(&["--tcp-flags-syn"]).unwrap();
        assert_eq!(
            spec.layers[0].fields.get("flags.syn"),
            Some(&Value::Bool(true))
        );
    }

    #[test]
    fn errors() {
        // zero layers (payload only)
        let e = spec_of(&["--payload=hex:00"]).unwrap_err();
        assert!(e.to_string().contains("no layers"), "{e}");
        // sibling conflict: arp+ipv4
        let e = spec_of(&["--arp-tpa=10.0.0.1", "--ipv4-src=1.2.3.4"]).unwrap_err();
        assert!(e.to_string().contains("sibling conflict"), "{e}");
        // tcp alone implied: valid stack start
        let spec = spec_of(&["--tcp-sport=1"]).unwrap();
        assert_eq!(spec.layers.len(), 1);
        // explicit bad chain
        let e = spec_of(&["--layer", "eth", "--layer", "tcp", "--tcp-sport=1"]).unwrap_err();
        assert!(e.to_string().contains("tcp requires parent ipv4"), "{e}");
        // field for undeclared layer
        let e = spec_of(&["--layer", "eth", "--tcp-sport=1"]).unwrap_err();
        assert!(e.to_string().contains("require `--layer"), "{e}");
        // unknown layer kind for --layer
        let e = spec_of(&["--layer", "nope"]).unwrap_err();
        assert!(e.to_string().contains("unknown layer"), "{e}");
    }

    #[test]
    fn unknown_and_missing_values_are_usage_errors() {
        // unknown flag → clap usage error (exit 2), not a SpecError
        let mut cmd = build_cli();
        let res = cmd.try_get_matches_from_mut(["wrex", "craft", "--ipx-src=1.2.3.4"]);
        assert!(res.is_err(), "unknown kind prefix must fail at parse");
        // unknown field of a known kind → clap usage error too
        let mut cmd = build_cli();
        let res = cmd.try_get_matches_from_mut(["wrex", "craft", "--ipv4-bogus=1"]);
        assert!(res.is_err());
        // missing value → clap usage error
        let mut cmd = build_cli();
        let res = cmd.try_get_matches_from_mut(["wrex", "craft", "--ipv4-ttl"]);
        assert!(res.is_err());
        // standard options interleave freely with field flags
        let spec = spec_of(&["--ipv4-ttl=63", "--format", "hex", "--layer", "ipv4"]).unwrap();
        assert_eq!(spec.layers[0].fields.get("ttl"), Some(&Value::Int(63)));
    }
}
