//! CLI spec parser: `--layer`, `--payload`, and `--<kind>-<path>=<value>`
//! field flags → [`wrex_core::PacketSpec`].

use std::collections::BTreeMap;

use wrex_core::value::{parse_bool, parse_value};
use wrex_core::{FieldSchema, PacketSpec, Registry, ResolvedField, SpecError, Value};

/// CLI-only kind alias table (pinned): `ip` → `ipv4`.
fn resolve_kind(registry: &Registry, wanted: &str) -> Result<&'static str, SpecError> {
    let canonical = match wanted {
        "ip" => "ipv4",
        other => other,
    };
    match registry.get(canonical) {
        Some(codec) => Ok(codec.schema().kind),
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
pub fn render_value_flat(v: &Value) -> String {
    match v {
        Value::Bool(b) => b.to_string(),
        Value::Int(n) => n.to_string(),
        Value::Bytes(b) => hex::encode(b),
        Value::Str(s) => s.clone(),
        Value::Ipv4(a) => a.to_string(),
        Value::Mac(m) => wrex_core::mac_string(*m),
        Value::List(items) => {
            let parts: Vec<String> = items.iter().map(render_value_flat).collect();
            parts.join(",")
        }
    }
}

/// Parse trailing field-flag tokens into a [`PacketSpec`].
///
/// Grammar: `--layer <KIND>` (repeatable), `--payload <VALUE>` (Bytes
/// grammar), `--<kind>-<path with dots as dashes>[=<VALUE>| <VALUE>]`.
/// Explicit `--layer` mode validates the parents chain; implied mode sorts
/// referenced kinds by rank and rejects sibling conflicts.
pub fn parse_packet_spec(registry: &Registry, tokens: &[String]) -> Result<PacketSpec, SpecError> {
    let mut declared: Vec<&'static str> = Vec::new();
    let mut kind_fields: BTreeMap<&'static str, BTreeMap<String, Value>> = BTreeMap::new();
    let mut payload: Option<Value> = None;

    let mut i = 0usize;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        if tok == "--layer" {
            let Some(kind_raw) = tokens.get(i + 1) else {
                return Err(SpecError::InvalidStack {
                    detail: "--layer requires a kind argument".into(),
                });
            };
            let kind = resolve_kind(registry, kind_raw)?;
            declared.push(kind);
            i += 2;
        } else if tok == "--payload" || tok.starts_with("--payload=") {
            let val_raw = if tok == "--payload" {
                let Some(v) = tokens.get(i + 1) else {
                    return Err(SpecError::InvalidStack {
                        detail: "--payload requires a value".into(),
                    });
                };
                i += 2;
                v.clone()
            } else {
                i += 1;
                tok.strip_prefix("--payload=").unwrap().to_string()
            };
            let field = payload_field();
            payload = Some(parse_value(&field, &val_raw)?);
        } else if let Some(body) = tok.strip_prefix("--") {
            let (flag, inline_val) = match body.split_once('=') {
                Some((f, v)) => (f, Some(v.to_string())),
                None => (body, None),
            };
            let Some((kind_raw, path_dashed)) = flag.split_once('-') else {
                return Err(SpecError::UnknownField {
                    layer: "<none>",
                    path: format!("--{flag}"),
                });
            };
            let kind = resolve_kind(registry, kind_raw)?;
            // dashes → dots (`tcp-flags-syn` → `flags.syn`)
            let path = path_dashed.replace('-', ".");
            let schema = registry.get(kind).unwrap().schema();
            let resolved = schema
                .resolve(&path)
                .ok_or_else(|| SpecError::UnknownField {
                    layer: kind,
                    path: path.clone(),
                })?;
            let (val_raw, consumed) = match inline_val {
                Some(v) => (v, 0usize),
                None => {
                    let Some(v) = tokens.get(i + 1) else {
                        return Err(SpecError::BadValue {
                            path: format!("{kind}.{path}"),
                            raw: "<missing>".into(),
                            reason: "field flag requires a value".into(),
                        });
                    };
                    (v.clone(), 1usize)
                }
            };
            let value = match resolved {
                ResolvedField::Field(field) => parse_value(field, &val_raw)?,
                ResolvedField::FlagBit { .. } => {
                    Value::Bool(parse_bool(&val_raw).map_err(|reason| SpecError::BadValue {
                        path: format!("{kind}.{path}"),
                        raw: val_raw.clone(),
                        reason,
                    })?)
                }
            };
            kind_fields.entry(kind).or_default().insert(path, value);
            i += 1 + consumed;
        } else {
            return Err(SpecError::InvalidStack {
                detail: format!("unexpected argument `{tok}`"),
            });
        }
    }

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
            let fields = kind_fields.remove(&k).unwrap_or_default();
            wrex_core::LayerSpec::with_fields(k, fields)
        })
        .collect();
    Ok(PacketSpec::new(layers, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> Registry {
        crate::standard()
    }

    fn toks(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn explicit_golden_spec() {
        let spec = parse_packet_spec(
            &reg(),
            &toks(&[
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
            ]),
        )
        .unwrap();
        assert_eq!(
            spec.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec!["eth", "ipv4", "udp"]
        );
        assert!(matches!(spec.payload, Some(Value::Bytes(_))));
    }

    #[test]
    fn implied_mode_sorts_by_rank() {
        let spec = parse_packet_spec(
            &reg(),
            &toks(&[
                "--udp-sport=4444",
                "--eth-dst=ff:ff:ff:ff:ff:ff",
                "--ipv4-src=127.0.0.1",
                "--ipv4-dst=127.0.0.1",
                "--udp-dport=5555",
                "--payload=hex:deadbeef",
            ]),
        )
        .unwrap();
        assert_eq!(
            spec.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec!["eth", "ipv4", "udp"]
        );
    }

    #[test]
    fn alias_ip_is_ipv4() {
        let spec = parse_packet_spec(&reg(), &toks(&["--ip-ttl=63"])).unwrap();
        assert_eq!(spec.layers[0].kind, "ipv4");
        assert_eq!(spec.layers[0].fields.get("ttl"), Some(&Value::Int(63)));
    }

    #[test]
    fn flagbit_subpaths() {
        let spec = parse_packet_spec(&reg(), &toks(&["--tcp-flags-syn=true"])).unwrap();
        assert_eq!(
            spec.layers[0].fields.get("flags.syn"),
            Some(&Value::Bool(true))
        );
    }

    #[test]
    fn errors() {
        // unknown kind
        let e = parse_packet_spec(&reg(), &toks(&["--ipx-src=1.2.3.4"])).unwrap_err();
        assert!(e.to_string().contains("unknown layer"), "{e}");
        // unknown field
        let e = parse_packet_spec(&reg(), &toks(&["--ipv4-bogus=1"])).unwrap_err();
        assert!(e.to_string().contains("unknown field"), "{e}");
        // zero layers (payload only)
        let e = parse_packet_spec(&reg(), &toks(&["--payload=hex:00"])).unwrap_err();
        assert!(e.to_string().contains("no layers"), "{e}");
        // sibling conflict: arp+ipv4
        let e = parse_packet_spec(&reg(), &toks(&["--arp-tpa=10.0.0.1", "--ipv4-src=1.2.3.4"]))
            .unwrap_err();
        assert!(e.to_string().contains("sibling conflict"), "{e}");
        // tcp requires parent ipv4 (implied: tcp alone starts a stack OK)
        let spec = parse_packet_spec(&reg(), &toks(&["--tcp-sport=1"])).unwrap();
        assert_eq!(spec.layers.len(), 1);
        // explicit bad chain
        let e = parse_packet_spec(
            &reg(),
            &toks(&["--layer", "eth", "--layer", "tcp", "--tcp-sport=1"]),
        )
        .unwrap_err();
        assert!(e.to_string().contains("tcp requires parent ipv4"), "{e}");
        // field for undeclared layer
        let e = parse_packet_spec(&reg(), &toks(&["--layer", "eth", "--tcp-sport=1"])).unwrap_err();
        assert!(e.to_string().contains("require `--layer"), "{e}");
        // unknown layer kind for --layer
        let e = parse_packet_spec(&reg(), &toks(&["--layer", "nope"])).unwrap_err();
        assert!(e.to_string().contains("unknown layer"), "{e}");
    }
}
