#![forbid(unsafe_code)]
//! wrex IPv6 extension header codecs (tranche 17a; RFC 8200 §4, AH per
//! RFC 4302, ESP per RFC 4303): hop-by-hop options (`hopopts`,
//! next-header 0), routing (`routing`, 43), fragment (`frag`, 44),
//! ESP (`esp`, 50), authentication header (`ah`, 51), no-next-header
//! (`nonext`, 59) and destination options (`dstopts`, 60). One crate,
//! seven kinds — the first multi-kind crate, deliberately (chain-shaped
//! tests are inherently cross-kind: sibling dev-deps cycle, stubbing
//! six siblings to test the seventh inverts the udp stand-in
//! economics, and a test shell above would recreate the family crate
//! worse; the five non-terminal kinds also share one private
//! next_header→kind table).
//!
//! Semantics (tranche 17a planning decisions):
//! - `next_header` autofills from the next layer (the `eth.type` rule);
//!   with nothing following it derives 59 (`nonext` — the honest
//!   terminal; explicit wins).
//! - The options-style headers (`hopopts`/`dstopts`/`routing`) zero-pad
//!   their raw region to the 8-octet grid on craft (the dhcp
//!   sname-padding precedent); `len` (hdr_ext_len) autofills exactly
//!   `(octets/8) − 1`, explicit wins and is kept verbatim. Dissection
//!   consumes `(len+1)*8` bytes and renders the region verbatim
//!   (padding included — the wire truth).
//! - `frag` chains into its `next_header` **only at offset 0** — a
//!   non-initial fragment carries no upper-layer header, so
//!   `offset > 0` is terminal with the fragment bytes as payload
//!   (reassembly stays a deferral). `offset`/`m` are `Bits` windows
//!   over the packed u16 (the ipv4 flags/frag_off pattern).
//! - `ah` never verifies integrity and `esp` never decrypts — wrex
//!   carves headers, never touches crypto (the standing TLS rule
//!   transposed). AH's `len` autofills `(octets/4) − 2`; the `icv`
//!   region is verbatim (no padding — it is the actual ICV, not a
//!   padded field).
//! - `nonext` is a zero-extent terminal marker layer so filters can
//!   speak its presence; craftable as a stack terminator.
//! - No ext header carries a checksum; the upper-layer checksums cover
//!   them via `Facts::upper_start` (RFC 8200 §8.1, handled by the
//!   net/L4 codecs).

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::LazyLock;

use bytes::BufMut;
use wrex_core::dissect::{DecodeCtx, FieldSpan, LayerView};
use wrex_core::encode::{EncodeCtx, bytes_or_empty, int_or_default};
use wrex_core::error::DecodeError;
use wrex_core::schema::{
    Derived, FieldKind, FieldSchema, LayerSchema, Layout, LengthBase, LengthUnits,
};
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;
use wrex_core::{Anomaly, Codec, EncodeError, Next, ReadOutcome};

/// The kind strings this crate implements (ADR 3): the net/L4 crates
/// reference these consts in their `parents` and craft stacks — the
/// registry vocabulary is compile-checked.
pub const KIND_HOPOPTS: &str = "hopopts";
pub const KIND_ROUTING: &str = "routing";
pub const KIND_FRAG: &str = "frag";
pub const KIND_AH: &str = "ah";
pub const KIND_ESP: &str = "esp";
pub const KIND_NONEXT: &str = "nonext";
pub const KIND_DSTOPTS: &str = "dstopts";

/// next-header number → next layer kind: the ipv6 lineage table
/// extended with the ext family (tranche 17a). Shared privately by the
/// five non-terminal kinds; `wrex-proto-ip6` carries the same rows in
/// its own copy (dispatch is registry strings — the ADR-3
/// child-side integration test pins the two tables against each other).
fn next_header_to_kind(n: u8) -> &'static str {
    match n {
        0 => KIND_HOPOPTS,
        6 => "tcp",
        17 => "udp",
        43 => KIND_ROUTING,
        44 => KIND_FRAG,
        50 => KIND_ESP,
        51 => KIND_AH,
        58 => "icmpv6",
        59 => KIND_NONEXT,
        60 => KIND_DSTOPTS,
        _ => "unknown",
    }
}

/// next layer kind → next-header number (for `write` autofill). With
/// nothing following (or an unknown kind) 59 — `nonext`, the honest
/// terminal.
fn kind_to_next_header(kind: Option<&'static str>) -> u8 {
    match kind {
        Some("icmpv6") => 58,
        Some("tcp") => 6,
        Some("udp") => 17,
        Some(KIND_HOPOPTS) => 0,
        Some(KIND_ROUTING) => 43,
        Some(KIND_FRAG) => 44,
        Some(KIND_ESP) => 50,
        Some(KIND_AH) => 51,
        Some(KIND_DSTOPTS) => 60,
        _ => 59,
    }
}

/// Zero-pad a raw region length up to its octet grid (8 for the
/// options-style headers): craft emits well-formed multiples even
/// from arbitrary regions (the dhcp sname-padding precedent).
fn pad_to_grid(len: usize, unit: usize) -> usize {
    len.div_ceil(unit) * unit
}

fn ext_field(
    name: &'static str,
    kind: FieldKind,
    doc: &'static str,
    default: Value,
) -> FieldSchema {
    FieldSchema {
        name,
        kind,
        bit_names: &[],
        default,
        required: false,
        doc,
    }
}

/// Schemas for the three options-style headers share this field list.
fn opts_fields() -> &'static [FieldSchema] {
    static FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
        vec![
            ext_field(
                "next_header",
                FieldKind::U8,
                "next header protocol (autofill: derived from the next layer; 59 = no next header)",
                Value::Int(59),
            ),
            ext_field(
                "len",
                FieldKind::U8,
                "hdr_ext_len: header length in 8-octet units minus 1 (autofill: exact over the padded region)",
                Value::Int(0),
            ),
            ext_field(
                "options",
                FieldKind::Bytes,
                "raw TLV region after the 2-byte prefix, zero-padded to the 8-octet grid on craft (hex on the CLI)",
                Value::Bytes(bytes::Bytes::new()),
            ),
        ]
    });
    FIELDS.as_slice()
}

static HOPOPTS_SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: KIND_HOPOPTS,
    rank: 25,
    parents: &[
        wrex_proto_ip6::KIND,
        KIND_HOPOPTS,
        KIND_ROUTING,
        KIND_FRAG,
        KIND_DSTOPTS,
        KIND_AH,
    ],
    doc: "IPv6 hop-by-hop options header (RFC 8200 §4.3, next-header 0): next_header + hdr_ext_len + the raw options TLV region (zero-padded to the 8-octet grid on craft, verbatim on dissection). Options must be examined by every node on the path; the wrex codec dissects and re-emits the region verbatim — TLV typing (Router Alert, Jumbo Payload, PadN) is a tranche-17a deferral, the raw region covers. len autofills (octets/8)-1; explicit wins and is kept.",
    fields: opts_fields(),
    records: &[],
});

static DSTOPTS_SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: KIND_DSTOPTS,
    rank: 25,
    parents: &[
        wrex_proto_ip6::KIND,
        KIND_HOPOPTS,
        KIND_ROUTING,
        KIND_FRAG,
        KIND_DSTOPTS,
        KIND_AH,
    ],
    doc: "IPv6 destination options header (RFC 8200 §4.6, next-header 60): the hop-by-hop shape examined only by the destination — next_header + hdr_ext_len + the raw options TLV region (zero-padded to the 8-octet grid on craft, verbatim on dissection; TLV typing is a deferral). May appear twice in one chain (before routing and before the upper layer) — dstopts-on-dstopts is legal per RFC 8200 §4.2 ordering. len autofills (octets/8)-1; explicit wins and is kept.",
    fields: opts_fields(),
    records: &[],
});

static ROUTING_SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: KIND_ROUTING,
    rank: 25,
    parents: &[
        wrex_proto_ip6::KIND,
        KIND_HOPOPTS,
        KIND_ROUTING,
        KIND_FRAG,
        KIND_DSTOPTS,
        KIND_AH,
    ],
    doc: "IPv6 routing header (RFC 8200 §4.4, next-header 43): next_header + hdr_ext_len + routing type + segments left + the raw type-specific region (zero-padded to the 8-octet grid on craft; the caller embeds the per-type reserved prefix + 16-byte addresses — e.g. RH0's 4 reserved bytes — verbatim on the wire). Dissection renders type/segs_left and the region raw; segs_left is NOT validated against the segment count (deliberate invalid packets are a feature). Typed per-type decoding (type-2 home address) is a deferral. len autofills (octets/8)-1; explicit wins and is kept.",
    fields: {
        static FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
            vec![
                ext_field(
                    "next_header",
                    FieldKind::U8,
                    "next header protocol (autofill: derived from the next layer; 59 = no next header)",
                    Value::Int(59),
                ),
                ext_field(
                    "len",
                    FieldKind::U8,
                    "hdr_ext_len: header length in 8-octet units minus 1 (autofill: exact over the padded region)",
                    Value::Int(0),
                ),
                ext_field(
                    "type",
                    FieldKind::U8,
                    "routing type (0 = the deprecated RH0, 2 = home address)",
                    Value::Int(0),
                ),
                ext_field(
                    "segs_left",
                    FieldKind::U8,
                    "segments left (not validated against the segment count)",
                    Value::Int(0),
                ),
                ext_field(
                    "segments",
                    FieldKind::Bytes,
                    "raw type-specific region after the 4-byte prefix (reserved bytes + 16-byte addresses, hand-built; hex on the CLI)",
                    Value::Bytes(bytes::Bytes::new()),
                ),
            ]
        });
        FIELDS.as_slice()
    },
    records: &[],
});

static FRAG_SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: KIND_FRAG,
    rank: 25,
    parents: &[
        wrex_proto_ip6::KIND,
        KIND_HOPOPTS,
        KIND_ROUTING,
        KIND_FRAG,
        KIND_DSTOPTS,
        KIND_AH,
    ],
    doc: "IPv6 fragment header (RFC 8200 §4.5, next-header 44): fixed 8 bytes — next_header, reserved, the packed u16 (13-bit offset | 2 reserved bits | M flag) and the 32-bit ident. offset and m are bit windows over the packed u16 (the ipv4 flags/frag_off pattern; over-wide offset values mask to 13 bits). The header chains into next_header ONLY at offset 0 — a non-initial fragment carries no upper-layer header, so offset > 0 is terminal with the fragment bytes as payload. Dissect-only view: reassembly is a deferral (analyzer work).",
    fields: {
        static FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
            vec![
                ext_field(
                    "next_header",
                    FieldKind::U8,
                    "next header protocol of the fragmentable part (autofill: derived from the next layer)",
                    Value::Int(59),
                ),
                ext_field(
                    "offset",
                    FieldKind::U16,
                    "fragment offset in 8-octet units (13 bits; over-wide values mask)",
                    Value::Int(0),
                ),
                ext_field(
                    "m",
                    FieldKind::U8,
                    "more-fragments flag (1 bit: 0 = last fragment)",
                    Value::Int(0),
                ),
                ext_field(
                    "ident",
                    FieldKind::U32,
                    "fragment identification (matches fragments of one packet)",
                    Value::Int(0),
                ),
            ]
        });
        FIELDS.as_slice()
    },
    records: &[],
});

static AH_SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: KIND_AH,
    rank: 25,
    parents: &[
        wrex_proto_ip6::KIND,
        KIND_HOPOPTS,
        KIND_ROUTING,
        KIND_FRAG,
        KIND_DSTOPTS,
        KIND_AH,
    ],
    doc: "IP authentication header (RFC 4302 §2.2, next-header 51): next_header + payload_len (AH length in 4-octet units minus 2 — autofills (octets/4)-2, explicit wins) + reserved (2 bytes) + spi + seq + the raw ICV region (verbatim, never padded — it is the actual integrity check value; len autofill truncates over non-multiple regions, kept). NO integrity verification: wrex carves headers, never touches crypto (the standing TLS rule transposed).",
    fields: {
        static FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
            vec![
                ext_field(
                    "next_header",
                    FieldKind::U8,
                    "next header protocol (autofill: derived from the next layer; 59 = no next header)",
                    Value::Int(59),
                ),
                ext_field(
                    "len",
                    FieldKind::U8,
                    "payload_len: AH length in 4-octet units minus 2 (autofill: (octets/4)-2, truncating — kept)",
                    Value::Int(1),
                ),
                ext_field(
                    "spi",
                    FieldKind::U32,
                    "security parameters index",
                    Value::Int(0),
                ),
                ext_field("seq", FieldKind::U32, "sequence number", Value::Int(0)),
                ext_field(
                    "icv",
                    FieldKind::Bytes,
                    "integrity check value (raw, verbatim — never verified; hex on the CLI)",
                    Value::Bytes(bytes::Bytes::new()),
                ),
            ]
        });
        FIELDS.as_slice()
    },
    records: &[],
});

static ESP_SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: KIND_ESP,
    rank: 25,
    parents: &[wrex_proto_ip6::KIND],
    doc: "IP encapsulating security payload (RFC 4303, next-header 50): the 8-byte fixed header — spi + seq — then everything after is opaque ciphertext (IV, payload, padding, pad length, next header). Craftable as the header + caller-supplied payload; TERMINAL both ways: the encrypted payload stays payload, and nothing stacks on esp (the payload's next-header byte is inside the ciphertext). NO decryption or integrity check — the standing crypto rule.",
    fields: {
        static FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
            vec![
                ext_field(
                    "spi",
                    FieldKind::U32,
                    "security parameters index",
                    Value::Int(0),
                ),
                ext_field("seq", FieldKind::U32, "sequence number", Value::Int(0)),
            ]
        });
        FIELDS.as_slice()
    },
    records: &[],
});

static NONEXT_SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: KIND_NONEXT,
    rank: 25,
    parents: &[wrex_proto_ip6::KIND],
    doc: "IPv6 no-next-header sentinel (RFC 8200 §4.6, next-header 59): a zero-extent terminal marker layer — it consumes no bytes and carries no fields, but materializes as a real layer so filters can speak `nonext` presence and craft can terminate a stack (`--layer ipv6 --layer nonext`; the ipv6 next_header autofills 59). Zero-length spans are safe through the reassemble/coverage invariants (verified by the tranche-17a units).",
    fields: &[],
    records: &[],
});

/// hop-by-hop / destination options codec unit (one struct, two
/// statics — the schema picks on `kind`; a `&LazyLock` cannot live in
/// a static initializer).
pub struct OptsCodec {
    kind: &'static str,
}

pub static HOPOPTS_CODEC: OptsCodec = OptsCodec { kind: KIND_HOPOPTS };
pub static DSTOPTS_CODEC: OptsCodec = OptsCodec { kind: KIND_DSTOPTS };

/// routing codec unit.
pub struct RoutingCodec;
pub static ROUTING_CODEC: RoutingCodec = RoutingCodec;

/// fragment codec unit.
pub struct FragCodec;
pub static FRAG_CODEC: FragCodec = FragCodec;

/// authentication header codec unit.
pub struct AhCodec;
pub static AH_CODEC: AhCodec = AhCodec;

/// ESP codec unit.
pub struct EspCodec;
pub static ESP_CODEC: EspCodec = EspCodec;

/// no-next-header codec unit.
pub struct NonextCodec;
pub static NONEXT_CODEC: NonextCodec = NonextCodec;

/// ADR 3 registration closure: the seven kinds self-first in the fixed
/// family order (hopopts, dstopts, routing, frag, ah, esp, nonext —
/// the enumeration order `wrex fields` and the man pages render), each
/// dedup-guarded via [`wrex_core::Registry::get`], then the parent
/// crate's closure (ipv6 → eth, vlan). Self-first keeps
/// `wrex::standard()`'s fixed registration order byte-identical —
/// presence, not order, is the guarantee.
pub fn register(r: &mut wrex_core::Registry) {
    for codec in [
        &HOPOPTS_CODEC as &'static dyn Codec,
        &DSTOPTS_CODEC,
        &ROUTING_CODEC,
        &FRAG_CODEC,
        &AH_CODEC,
        &ESP_CODEC,
        &NONEXT_CODEC,
    ] {
        if r.get(codec.schema().kind).is_none() {
            r.register(codec);
        }
    }
    wrex_proto_ip6::register(r);
}

/// Read the 2-byte options-style prefix + the declared region.
/// Returns `(next_header, total)`.
fn read_opts_prefix(
    bytes: &[u8],
    ctx: &mut DecodeCtx<'_>,
    kind: &'static str,
) -> Option<(u8, usize)> {
    if bytes.len() < 2 {
        ctx.anomalies.push(Anomaly::new(
            format!("{kind}.len"),
            format!("truncated (need 2, found {})", bytes.len()),
        ));
        return None;
    }
    let next_header = bytes[0];
    let len = bytes[1] as usize;
    let total = (len + 1) * 8;
    Some((next_header, total))
}

impl Codec for OptsCodec {
    fn schema(&self) -> &'static LayerSchema {
        match self.kind {
            KIND_HOPOPTS => &HOPOPTS_SCHEMA,
            _ => &DSTOPTS_SCHEMA,
        }
    }

    fn header_len(&self, spec: &LayerSpec) -> Result<usize, EncodeError> {
        let options = bytes_or_empty(spec, "options");
        if let Some(Value::Int(v)) = spec.fields.get("len") {
            return Ok(((*v as u8 as usize) + 1) * 8);
        }
        Ok(2 + pad_to_grid(options.len() + 2, 8) - 2)
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let next_header = match spec.fields.get("next_header") {
            Some(Value::Int(v)) => *v as u8,
            _ if af => kind_to_next_header(ctx.next),
            _ => 59,
        };
        ctx.buf.put_u8(next_header);
        // Zero-pad the region to the 8-octet grid (the dhcp
        // sname-padding precedent): len autofills exactly; explicit
        // len wins and is kept verbatim (deliberate invalid packets
        // are a feature).
        let options = bytes_or_empty(spec, "options");
        let region = if let Some(Value::Int(v)) = spec.fields.get("len") {
            let _ = v; // explicit len: the region stays verbatim
            options.to_vec()
        } else {
            let padded_total = pad_to_grid(options.len() + 2, 8);
            let mut region = options.to_vec();
            region.resize(padded_total - 2, 0);
            region
        };
        let len = match spec.fields.get("len") {
            Some(Value::Int(v)) => *v as u8,
            _ if af => ((2 + region.len()) / 8).saturating_sub(1) as u8,
            _ => 0,
        };
        ctx.buf.put_u8(len);
        ctx.buf.extend_from_slice(&region);
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        let kind = self.kind;
        let Some((next_header, total)) = read_opts_prefix(bytes, ctx, kind) else {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind,
                    need: 2,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        };
        if bytes.len() < total {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind,
                    need: total,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let region = total - 2;
        let mut fields = BTreeMap::new();
        fields.insert("next_header".into(), Value::Int(next_header as u128));
        fields.insert("len".into(), Value::Int(bytes[1] as u128));
        fields.insert(
            "options".into(),
            Value::Bytes(bytes::Bytes::copy_from_slice(&bytes[2..total])),
        );
        let mut spans = BTreeMap::new();
        spans.insert(
            "next_header".to_string(),
            FieldSpan::Bytes(ctx.offset..ctx.offset + 1),
        );
        spans.insert(
            "len".to_string(),
            FieldSpan::Bytes(ctx.offset + 1..ctx.offset + 2),
        );
        spans.insert(
            "options".to_string(),
            FieldSpan::Bytes(ctx.offset + 2..ctx.offset + total),
        );

        // Thread the terminal upper-layer protocol through the chain:
        // RFC 8200 §8.1's pseudo-header carries the FINAL upper-layer
        // protocol, and the patch-engine checksum walk reads it from
        // the net facts (the L4 dissect verifies hardcode their own
        // proto; the walk's FromFacts path needs the threaded value —
        // without this, [ipv6, hopopts, icmpv6] would pseudo-fold with
        // proto 0 instead of 58).
        if let Some(wrex_core::dissect::NetFacts::V6 { src, dst, .. }) = ctx.facts.net {
            ctx.facts.net = Some(wrex_core::dissect::NetFacts::V6 {
                src,
                dst,
                next_header,
            });
        }
        let _ = region;
        let view = LayerView {
            kind,
            span: ctx.offset..ctx.offset + total,
            field_spans: spans,
            fields,
        };
        ReadOutcome::Layer(view, Some(Next::Kind(next_header_to_kind(next_header))))
    }

    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        static LAYOUTS: &[(&str, Layout)] = &[
            ("next_header", Layout::Bytes { at: 0, len: 1 }),
            ("len", Layout::Bytes { at: 1, len: 1 }),
        ];
        LAYOUTS
    }

    fn derived(&self) -> &'static [Derived] {
        // The region span is codec-side (parse-time); `len` derives
        // over the whole header in 8-octet units minus 1.
        static DERIVED: &[Derived] = &[Derived::Length {
            field: "len",
            at: 1,
            base: LengthBase::Span,
            units: LengthUnits::Octlets8,
        }];
        DERIVED
    }
}

impl Codec for RoutingCodec {
    fn schema(&self) -> &'static LayerSchema {
        &ROUTING_SCHEMA
    }

    fn header_len(&self, spec: &LayerSpec) -> Result<usize, EncodeError> {
        if let Some(Value::Int(v)) = spec.fields.get("len") {
            return Ok(((*v as u8 as usize) + 1) * 8);
        }
        let segments = bytes_or_empty(spec, "segments");
        Ok(pad_to_grid(segments.len() + 4, 8))
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let next_header = match spec.fields.get("next_header") {
            Some(Value::Int(v)) => *v as u8,
            _ if af => kind_to_next_header(ctx.next),
            _ => 59,
        };
        ctx.buf.put_u8(next_header);
        let segments = bytes_or_empty(spec, "segments");
        let region = if let Some(Value::Int(v)) = spec.fields.get("len") {
            let _ = v; // explicit len: the region stays verbatim
            segments.to_vec()
        } else {
            let padded_total = pad_to_grid(segments.len() + 4, 8);
            let mut region = segments.to_vec();
            region.resize(padded_total - 4, 0);
            region
        };
        let len = match spec.fields.get("len") {
            Some(Value::Int(v)) => *v as u8,
            _ if af => ((4 + region.len()) / 8).saturating_sub(1) as u8,
            _ => 0,
        };
        ctx.buf.put_u8(len);
        ctx.buf
            .put_u8(int_or_default(spec, &routing_f()[2], af) as u8); // type
        ctx.buf
            .put_u8(int_or_default(spec, &routing_f()[3], af) as u8); // segs_left
        ctx.buf.extend_from_slice(&region);
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.len() < 4 {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: KIND_ROUTING,
                    need: 4,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let next_header = bytes[0];
        let len = bytes[1] as usize;
        let total = (len + 1) * 8;
        if bytes.len() < total {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: KIND_ROUTING,
                    need: total,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let mut fields = BTreeMap::new();
        fields.insert("next_header".into(), Value::Int(next_header as u128));
        fields.insert("len".into(), Value::Int(bytes[1] as u128));
        fields.insert("type".into(), Value::Int(bytes[2] as u128));
        fields.insert("segs_left".into(), Value::Int(bytes[3] as u128));
        fields.insert(
            "segments".into(),
            Value::Bytes(bytes::Bytes::copy_from_slice(&bytes[4..total])),
        );
        let mut spans = BTreeMap::new();
        spans.insert(
            "next_header".to_string(),
            FieldSpan::Bytes(ctx.offset..ctx.offset + 1),
        );
        spans.insert(
            "len".to_string(),
            FieldSpan::Bytes(ctx.offset + 1..ctx.offset + 2),
        );
        spans.insert(
            "type".to_string(),
            FieldSpan::Bytes(ctx.offset + 2..ctx.offset + 3),
        );
        spans.insert(
            "segs_left".to_string(),
            FieldSpan::Bytes(ctx.offset + 3..ctx.offset + 4),
        );
        spans.insert(
            "segments".to_string(),
            FieldSpan::Bytes(ctx.offset + 4..ctx.offset + total),
        );

        // Thread the terminal upper-layer protocol through the chain:
        // RFC 8200 §8.1's pseudo-header carries the FINAL upper-layer
        // protocol, and the patch-engine checksum walk reads it from
        // the net facts (the L4 dissect verifies hardcode their own
        // proto; the walk's FromFacts path needs the threaded value —
        // without this, [ipv6, hopopts, icmpv6] would pseudo-fold with
        // proto 0 instead of 58).
        if let Some(wrex_core::dissect::NetFacts::V6 { src, dst, .. }) = ctx.facts.net {
            ctx.facts.net = Some(wrex_core::dissect::NetFacts::V6 {
                src,
                dst,
                next_header,
            });
        }

        let view = LayerView {
            kind: KIND_ROUTING,
            span: ctx.offset..ctx.offset + total,
            field_spans: spans,
            fields,
        };
        ReadOutcome::Layer(view, Some(Next::Kind(next_header_to_kind(next_header))))
    }

    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        static LAYOUTS: &[(&str, Layout)] = &[
            ("next_header", Layout::Bytes { at: 0, len: 1 }),
            ("len", Layout::Bytes { at: 1, len: 1 }),
            ("type", Layout::Bytes { at: 2, len: 1 }),
            ("segs_left", Layout::Bytes { at: 3, len: 1 }),
        ];
        LAYOUTS
    }

    fn derived(&self) -> &'static [Derived] {
        static DERIVED: &[Derived] = &[Derived::Length {
            field: "len",
            at: 1,
            base: LengthBase::Span,
            units: LengthUnits::Octlets8,
        }];
        DERIVED
    }
}

fn routing_f() -> &'static [FieldSchema] {
    ROUTING_SCHEMA.fields
}

impl Codec for FragCodec {
    fn schema(&self) -> &'static LayerSchema {
        &FRAG_SCHEMA
    }

    fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
        Ok(8)
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let next_header = match spec.fields.get("next_header") {
            Some(Value::Int(v)) => *v as u8,
            _ if af => kind_to_next_header(ctx.next),
            _ => 59,
        };
        ctx.buf.put_u8(next_header);
        ctx.buf.put_u8(0); // reserved
        let offset = int_or_default(spec, &frag_f()[1], af) as u16 & 0x1fff; // 13 bits
        let m = int_or_default(spec, &frag_f()[2], af) as u8 & 1;
        ctx.buf.put_u16((offset << 3) | (m as u16));
        ctx.buf
            .put_u32(int_or_default(spec, &frag_f()[3], af) as u32);
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.len() < 8 {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: KIND_FRAG,
                    need: 8,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let next_header = bytes[0];
        let word = u16::from_be_bytes([bytes[2], bytes[3]]);
        let offset = word >> 3;
        let m = word & 1;
        let ident = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let mut fields = BTreeMap::new();
        fields.insert("next_header".into(), Value::Int(next_header as u128));
        fields.insert("offset".into(), Value::Int(offset as u128));
        fields.insert("m".into(), Value::Int(m as u128));
        fields.insert("ident".into(), Value::Int(ident as u128));
        let mut spans = BTreeMap::new();
        spans.insert(
            "next_header".to_string(),
            FieldSpan::Bytes(ctx.offset..ctx.offset + 1),
        );
        let container: Range<usize> = ctx.offset + 2..ctx.offset + 4;
        spans.insert(
            "offset".to_string(),
            FieldSpan::Bits {
                container: container.clone(),
                shift: 0,
                width: 13,
            },
        );
        spans.insert(
            "m".to_string(),
            FieldSpan::Bits {
                container,
                shift: 13,
                width: 1,
            },
        );
        spans.insert(
            "ident".to_string(),
            FieldSpan::Bytes(ctx.offset + 4..ctx.offset + 8),
        );
        let view = LayerView {
            kind: KIND_FRAG,
            span: ctx.offset..ctx.offset + 8,
            field_spans: spans,
            fields,
        };
        // A non-initial fragment (offset > 0) carries no upper-layer
        // header: terminal, the fragment bytes stay payload
        // (reassembly is a deferral). At offset 0 the upper header IS
        // present — chain regardless of M.
        if offset == 0 {
            // Thread the terminal upper-layer protocol through the chain:
            // RFC 8200 §8.1's pseudo-header carries the FINAL upper-layer
            // protocol, and the patch-engine checksum walk reads it from
            // the net facts (the L4 dissect verifies hardcode their own
            // proto; the walk's FromFacts path needs the threaded value —
            // without this, [ipv6, hopopts, icmpv6] would pseudo-fold with
            // proto 0 instead of 58).
            if let Some(wrex_core::dissect::NetFacts::V6 { src, dst, .. }) = ctx.facts.net {
                ctx.facts.net = Some(wrex_core::dissect::NetFacts::V6 {
                    src,
                    dst,
                    next_header,
                });
            }
            ReadOutcome::Layer(view, Some(Next::Kind(next_header_to_kind(next_header))))
        } else {
            ReadOutcome::Layer(view, Some(Next::Payload))
        }
    }

    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        static LAYOUTS: &[(&str, Layout)] = &[
            ("next_header", Layout::Bytes { at: 0, len: 1 }),
            (
                "offset",
                Layout::Bits {
                    at: 2,
                    shift: 0,
                    width: 13,
                },
            ),
            (
                "m",
                Layout::Bits {
                    at: 2,
                    shift: 13,
                    width: 1,
                },
            ),
            ("ident", Layout::Bytes { at: 4, len: 4 }),
        ];
        LAYOUTS
    }
}

fn frag_f() -> &'static [FieldSchema] {
    FRAG_SCHEMA.fields
}

impl Codec for AhCodec {
    fn schema(&self) -> &'static LayerSchema {
        &AH_SCHEMA
    }

    fn header_len(&self, spec: &LayerSpec) -> Result<usize, EncodeError> {
        if let Some(Value::Int(v)) = spec.fields.get("len") {
            return Ok(((*v as u8 as usize) + 2) * 4);
        }
        let icv = bytes_or_empty(spec, "icv");
        Ok(12 + pad_to_grid(icv.len(), 4))
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let next_header = match spec.fields.get("next_header") {
            Some(Value::Int(v)) => *v as u8,
            _ if af => kind_to_next_header(ctx.next),
            _ => 59,
        };
        ctx.buf.put_u8(next_header);
        let icv = bytes_or_empty(spec, "icv");
        // The ICV is verbatim — never padded (it is the actual
        // integrity check value, not a padded field); a non-multiple
        // region truncates the len autofill (kept, --strict territory
        // is not enforced here — deliberate invalid packets are a
        // feature).
        let len = match spec.fields.get("len") {
            Some(Value::Int(v)) => *v as u8,
            _ if af => ((12 + icv.len()) / 4).saturating_sub(2) as u8,
            _ => 1,
        };
        ctx.buf.put_u8(len);
        ctx.buf.put_u16(0); // reserved
        ctx.buf.put_u32(int_or_default(spec, &ah_f()[2], af) as u32); // spi
        ctx.buf.put_u32(int_or_default(spec, &ah_f()[3], af) as u32); // seq
        ctx.buf.extend_from_slice(&icv);
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.len() < 12 {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: KIND_AH,
                    need: 12,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let next_header = bytes[0];
        let declared = (bytes[1] as usize + 2) * 4;
        if declared < 12 {
            // Never fatal: the value is kept and rendered; the layer
            // consumes at least the fixed part.
            ctx.anomalies.push(Anomaly::new(
                "ah.len",
                format!(
                    "below minimum (declared {declared} octets < the 12-byte fixed part; kept)"
                ),
            ));
        }
        let total = declared.max(12);
        if bytes.len() < total {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: KIND_AH,
                    need: total,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let spi = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let seq = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let mut fields = BTreeMap::new();
        fields.insert("next_header".into(), Value::Int(next_header as u128));
        fields.insert("len".into(), Value::Int(bytes[1] as u128));
        fields.insert("spi".into(), Value::Int(spi as u128));
        fields.insert("seq".into(), Value::Int(seq as u128));
        fields.insert(
            "icv".into(),
            Value::Bytes(bytes::Bytes::copy_from_slice(&bytes[12..total])),
        );
        let mut spans = BTreeMap::new();
        spans.insert(
            "next_header".to_string(),
            FieldSpan::Bytes(ctx.offset..ctx.offset + 1),
        );
        spans.insert(
            "len".to_string(),
            FieldSpan::Bytes(ctx.offset + 1..ctx.offset + 2),
        );
        spans.insert(
            "spi".to_string(),
            FieldSpan::Bytes(ctx.offset + 4..ctx.offset + 8),
        );
        spans.insert(
            "seq".to_string(),
            FieldSpan::Bytes(ctx.offset + 8..ctx.offset + 12),
        );
        spans.insert(
            "icv".to_string(),
            FieldSpan::Bytes(ctx.offset + 12..ctx.offset + total),
        );

        // Thread the terminal upper-layer protocol through the chain:
        // RFC 8200 §8.1's pseudo-header carries the FINAL upper-layer
        // protocol, and the patch-engine checksum walk reads it from
        // the net facts (the L4 dissect verifies hardcode their own
        // proto; the walk's FromFacts path needs the threaded value —
        // without this, [ipv6, hopopts, icmpv6] would pseudo-fold with
        // proto 0 instead of 58).
        if let Some(wrex_core::dissect::NetFacts::V6 { src, dst, .. }) = ctx.facts.net {
            ctx.facts.net = Some(wrex_core::dissect::NetFacts::V6 {
                src,
                dst,
                next_header,
            });
        }

        let view = LayerView {
            kind: KIND_AH,
            span: ctx.offset..ctx.offset + total,
            field_spans: spans,
            fields,
        };
        ReadOutcome::Layer(view, Some(Next::Kind(next_header_to_kind(next_header))))
    }

    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        static LAYOUTS: &[(&str, Layout)] = &[
            ("next_header", Layout::Bytes { at: 0, len: 1 }),
            ("len", Layout::Bytes { at: 1, len: 1 }),
            ("spi", Layout::Bytes { at: 4, len: 4 }),
            ("seq", Layout::Bytes { at: 8, len: 4 }),
        ];
        LAYOUTS
    }

    fn derived(&self) -> &'static [Derived] {
        static DERIVED: &[Derived] = &[Derived::Length {
            field: "len",
            at: 1,
            base: LengthBase::Span,
            units: LengthUnits::Octlets4,
        }];
        DERIVED
    }
}

fn ah_f() -> &'static [FieldSchema] {
    AH_SCHEMA.fields
}

impl Codec for EspCodec {
    fn schema(&self) -> &'static LayerSchema {
        &ESP_SCHEMA
    }

    fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
        Ok(8)
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        ctx.buf
            .put_u32(int_or_default(spec, &esp_f()[0], af) as u32); // spi
        ctx.buf
            .put_u32(int_or_default(spec, &esp_f()[1], af) as u32); // seq
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.len() < 8 {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: KIND_ESP,
                    need: 8,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let spi = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let seq = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let mut fields = BTreeMap::new();
        fields.insert("spi".into(), Value::Int(spi as u128));
        fields.insert("seq".into(), Value::Int(seq as u128));
        let mut spans = BTreeMap::new();
        spans.insert(
            "spi".to_string(),
            FieldSpan::Bytes(ctx.offset..ctx.offset + 4),
        );
        spans.insert(
            "seq".to_string(),
            FieldSpan::Bytes(ctx.offset + 4..ctx.offset + 8),
        );
        let view = LayerView {
            kind: KIND_ESP,
            span: ctx.offset..ctx.offset + 8,
            field_spans: spans,
            fields,
        };
        // TERMINAL: everything after the 8-byte header is opaque
        // ciphertext — it stays payload.
        ReadOutcome::Layer(view, Some(Next::Payload))
    }

    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        static LAYOUTS: &[(&str, Layout)] = &[
            ("spi", Layout::Bytes { at: 0, len: 4 }),
            ("seq", Layout::Bytes { at: 4, len: 4 }),
        ];
        LAYOUTS
    }
}

fn esp_f() -> &'static [FieldSchema] {
    ESP_SCHEMA.fields
}

impl Codec for NonextCodec {
    fn schema(&self) -> &'static LayerSchema {
        &NONEXT_SCHEMA
    }

    fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
        Ok(0)
    }

    fn write(&self, _spec: &LayerSpec, _ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        Ok(())
    }

    fn read<'a>(&self, _bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        // Zero-extent terminal marker: always a Layer (never Empty —
        // the layer must materialize so filters speak `nonext`
        // presence), consuming no bytes. The reassemble/coverage
        // invariants accept start == end spans (pinned by the units).
        ReadOutcome::Layer(
            LayerView {
                kind: KIND_NONEXT,
                span: ctx.offset..ctx.offset,
                field_spans: BTreeMap::new(),
                fields: BTreeMap::new(),
            },
            Some(Next::Payload),
        )
    }
}

/// Proptest strategies (the `test-util` feature; the wrex-test
/// differential picks these up per kind).
#[cfg(feature = "test-util")]
pub mod strategy {
    use super::*;
    use proptest::prelude::*;
    use wrex_core::spec::LayerSpec;

    fn any_u8() -> impl Strategy<Value = u128> {
        any::<u8>().prop_map(|v| v as u128)
    }

    /// hopopts/dstopts: options regions are multiples of 8 minus the
    /// 2-byte prefix (0..=3 grid cells), so craft stays well-formed
    /// without padding luck.
    fn opts_strategy(kind: &'static str) -> impl Strategy<Value = LayerSpec> {
        proptest::collection::vec(any::<u8>(), 0..=24)
            .prop_map(move |mut options| {
                options.resize(options.len().div_ceil(8) * 8, 0);
                let mut fields = BTreeMap::new();
                fields.insert("options".to_string(), Value::Bytes(options.into()));
                LayerSpec::with_fields(kind, fields)
            })
            .boxed()
    }

    pub fn hopopts() -> BoxedStrategy<LayerSpec> {
        opts_strategy(super::KIND_HOPOPTS).boxed()
    }

    pub fn dstopts() -> BoxedStrategy<LayerSpec> {
        opts_strategy(super::KIND_DSTOPTS).boxed()
    }

    /// routing: the type-specific region is 4 reserved + 16k address
    /// bytes (the RH0 layout), type/segs_left random.
    pub fn routing() -> BoxedStrategy<LayerSpec> {
        (
            proptest::collection::vec(any::<u8>(), 0..=32),
            any_u8(),
            any_u8(),
        )
            .prop_map(|(mut addresses, rtype, segs_left)| {
                addresses.resize(addresses.len().div_ceil(16) * 16, 0);
                let mut region = vec![0u8; 4];
                region.extend_from_slice(&addresses);
                let mut fields = BTreeMap::new();
                fields.insert("type".to_string(), Value::Int(rtype));
                fields.insert("segs_left".to_string(), Value::Int(segs_left));
                fields.insert("segments".to_string(), Value::Bytes(region.into()));
                LayerSpec::with_fields(super::KIND_ROUTING, fields)
            })
            .boxed()
    }

    /// frag: offset 0 pinned? No — random offsets exercise the
    /// terminal branch; the differential stack wrapper pins offset 0
    /// so the chain holds.
    pub fn frag() -> BoxedStrategy<LayerSpec> {
        (any::<u16>(), any::<bool>(), any::<u32>())
            .prop_map(|(offset, m, ident)| {
                let mut fields = BTreeMap::new();
                fields.insert("offset".to_string(), Value::Int((offset & 0x1fff) as u128));
                fields.insert("m".to_string(), Value::Int(m as u128));
                fields.insert("ident".to_string(), Value::Int(ident as u128));
                LayerSpec::with_fields(super::KIND_FRAG, fields)
            })
            .boxed()
    }

    /// ah: ICV of 4k bytes (never padded — kept verbatim), spi/seq
    /// random.
    pub fn ah() -> BoxedStrategy<LayerSpec> {
        (
            proptest::collection::vec(any::<u8>(), 0..=16),
            any::<u32>(),
            any::<u32>(),
        )
            .prop_map(|(mut icv, spi, seq)| {
                icv.resize(icv.len().div_ceil(4) * 4, 0);
                let mut fields = BTreeMap::new();
                fields.insert("spi".to_string(), Value::Int(spi as u128));
                fields.insert("seq".to_string(), Value::Int(seq as u128));
                fields.insert("icv".to_string(), Value::Bytes(icv.into()));
                LayerSpec::with_fields(super::KIND_AH, fields)
            })
            .boxed()
    }

    pub fn esp() -> BoxedStrategy<LayerSpec> {
        (any::<u32>(), any::<u32>())
            .prop_map(|(spi, seq)| {
                let mut fields = BTreeMap::new();
                fields.insert("spi".to_string(), Value::Int(spi as u128));
                fields.insert("seq".to_string(), Value::Int(seq as u128));
                LayerSpec::with_fields(super::KIND_ESP, fields)
            })
            .boxed()
    }

    pub fn nonext() -> BoxedStrategy<LayerSpec> {
        Just(LayerSpec::new(super::KIND_NONEXT)).boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wrex_core::Registry;
    use wrex_core::encode::encode;
    use wrex_core::spec::PacketSpec;

    fn af_opts() -> wrex_core::encode::EncodeOpts {
        wrex_core::encode::EncodeOpts {
            autofill: true,
            ..Default::default()
        }
    }

    fn spec(kind: &'static str, fields: &[(&str, &str)]) -> LayerSpec {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            let value = match *k {
                "options" | "segments" | "icv" => {
                    Value::Bytes(bytes::Bytes::from(hex::decode(v).unwrap()))
                }
                _ => Value::Int(v.parse::<u128>().unwrap()),
            };
            map.insert(k.to_string(), value);
        }
        LayerSpec::with_fields(kind, map)
    }

    fn kinds(p: &wrex_core::DissectedPacket) -> Vec<&'static str> {
        p.layers.iter().map(|l| l.kind).collect()
    }

    /// ADR 3: ipv6 is a real parent dep — the dispatch-in test runs
    /// against the actual ipv6 codec through the register closure
    /// (no stand-in), full chain: eth → ipv6 → hopopts → dstopts →
    /// routing → frag → tcp.
    #[test]
    fn ipv6_dispatches_ext_chains_with_real_codecs() {
        let mut r = Registry::empty();
        register(&mut r);
        let s = wrex_core::spec::PacketSpec::new(
            vec![
                wrex_core::spec::LayerSpec::new("eth"),
                wrex_core::spec::LayerSpec::new(wrex_proto_ip6::KIND),
                spec(KIND_HOPOPTS, &[("options", "010400000000")]),
                LayerSpec::new(KIND_DSTOPTS),
                spec(
                    KIND_ROUTING,
                    &[("segments", "00000000112233445566778899aabbcc")],
                ),
                spec(KIND_FRAG, &[("offset", "0"), ("m", "1")]),
                // tcp/udp are children (they dep on this crate — ADR 3
                // cycles); the in-crate chain ends at the real nonext
                // marker. The L4 side of the chain is covered by the
                // udp/tcp/icmpv6 crates' ext-chain tests.
                LayerSpec::new(KIND_NONEXT),
            ],
            None,
        );
        let enc = encode(&r, &s, &af_opts()).unwrap();
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, "eth");
        assert_eq!(
            kinds(&p),
            vec![
                "eth", "ipv6", "hopopts", "dstopts", "routing", "frag", "nonext"
            ],
            "the full RFC 8200 chain must dissect through the real codecs"
        );
        // No anomalies: lengths/checksums consistent under autofill.
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        // T11a byte-fidelity: the dissection reassembles verbatim.
        assert_eq!(&p.reassemble()[..], &enc.bytes[..]);
    }

    #[test]
    fn hopopts_golden() {
        let mut r = Registry::empty();
        register(&mut r);
        // options region 6 bytes → padded total 8, len 0; next nonext (59).
        let s = PacketSpec::new(
            vec![
                spec(KIND_HOPOPTS, &[("options", "010400000000")]),
                LayerSpec::new(KIND_NONEXT),
            ],
            Some(Value::Bytes(bytes::Bytes::from_static(&[0xde]))),
        );
        let enc = encode(&r, &s, &af_opts()).unwrap();
        assert_eq!(
            &enc.bytes[..],
            &[0x3b, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0xde][..]
        );
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, KIND_HOPOPTS);
        assert_eq!(kinds(&p), vec![KIND_HOPOPTS, KIND_NONEXT]);
        assert_eq!(
            p.layers[0].fields.get("options"),
            Some(&Value::Bytes(bytes::Bytes::from_static(&[
                0x01, 0x04, 0x00, 0x00, 0x00, 0x00
            ])))
        );
    }

    #[test]
    fn routing_len_autofill_and_explicit_kept() {
        let mut r = Registry::empty();
        register(&mut r);
        // 4 reserved + 16 bytes = 20 → total 24 → len 2.
        let s = PacketSpec::new(
            vec![spec(
                KIND_ROUTING,
                &[("segments", "00000000112233445566778899aabbcc")],
            )],
            None,
        );
        let enc = encode(&r, &s, &af_opts()).unwrap();
        assert_eq!(enc.bytes[1], 2);
        assert_eq!(enc.bytes.len(), 24);
        // explicit len wins (kept, invalid on purpose)
        let s = PacketSpec::new(
            vec![spec(
                KIND_ROUTING,
                &[("len", "9"), ("segments", "01020304")],
            )],
            None,
        );
        let enc = encode(&r, &s, &af_opts()).unwrap();
        assert_eq!(enc.bytes[1], 9);
    }

    #[test]
    fn frag_offset_zero_chains_nonzero_terminal() {
        let mut r = Registry::empty();
        register(&mut r);
        let chain = PacketSpec::new(
            vec![
                spec(KIND_FRAG, &[("offset", "0"), ("m", "1")]),
                LayerSpec::new(KIND_NONEXT),
            ],
            None,
        );
        let enc = encode(&r, &chain, &af_opts()).unwrap();
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, KIND_FRAG);
        assert_eq!(kinds(&p), vec![KIND_FRAG, KIND_NONEXT]);

        let mid = PacketSpec::new(
            vec![spec(KIND_FRAG, &[("offset", "5"), ("m", "1")])],
            Some(Value::Bytes(bytes::Bytes::from_static(&[1, 2, 3]))),
        );
        let enc = encode(&r, &mid, &af_opts()).unwrap();
        assert_eq!(
            &enc.bytes[..],
            &[
                0x3b,
                0x00,
                (5u16 << 3 | 1).to_be_bytes()[0],
                (5u16 << 3 | 1).to_be_bytes()[1],
                0,
                0,
                0,
                0,
                1,
                2,
                3
            ][..]
        );
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, KIND_FRAG);
        assert_eq!(kinds(&p), vec![KIND_FRAG]);
        assert_eq!(&p.payload[..], &[1, 2, 3][..]);
    }

    #[test]
    fn ah_len_bias_and_short_declared() {
        let mut r = Registry::empty();
        register(&mut r);
        // ICV 4 bytes → total 16 → len (16/4)-2 = 2.
        let s = PacketSpec::new(vec![spec(KIND_AH, &[("icv", "a1b2c3d4")])], None);
        let enc = encode(&r, &s, &af_opts()).unwrap();
        assert_eq!(enc.bytes[1], 2);
        assert_eq!(enc.bytes.len(), 16);
        // len 0 → declared 8 < fixed 12: never-fatal anomaly, consumes
        // the fixed part. Next 59 → the real nonext marker.
        let frame = [59u8, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        let p = wrex_core::dissect::dissect(&r, &frame, KIND_AH);
        assert_eq!(kinds(&p), vec![KIND_AH, KIND_NONEXT]);
        assert!(
            p.anomalies.iter().any(|a| a.path == "ah.len"),
            "{:?}",
            p.anomalies
        );
    }

    #[test]
    fn esp_terminal_craftable() {
        let mut r = Registry::empty();
        register(&mut r);
        let s = PacketSpec::new(
            vec![spec(KIND_ESP, &[("spi", "287454020"), ("seq", "7")])],
            Some(Value::Bytes(bytes::Bytes::from_static(&[0xaa, 0xbb]))),
        );
        let enc = encode(&r, &s, &af_opts()).unwrap();
        assert_eq!(
            &enc.bytes[..],
            &[0x11, 0x22, 0x33, 0x44, 0, 0, 0, 7, 0xaa, 0xbb][..]
        );
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, KIND_ESP);
        assert_eq!(kinds(&p), vec![KIND_ESP]);
        assert_eq!(&p.payload[..], &[0xaa, 0xbb][..]);
        assert_eq!(p.layers[0].fields.get("spi"), Some(&Value::Int(0x11223344)));
    }

    #[test]
    fn nonext_zero_extent_reassembles() {
        let mut r = Registry::empty();
        register(&mut r);
        let s = PacketSpec::new(
            vec![LayerSpec::new(KIND_NONEXT)],
            Some(Value::Bytes(bytes::Bytes::from_static(&[9]))),
        );
        let enc = encode(&r, &s, &af_opts()).unwrap();
        assert_eq!(&enc.bytes[..], &[9][..]);
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, KIND_NONEXT);
        assert_eq!(kinds(&p), vec![KIND_NONEXT]);
        assert_eq!(p.layers[0].span, 0..0);
        // T11a: byte-identity through the zero-extent layer.
        assert_eq!(&p.reassemble()[..], &enc.bytes[..]);
    }

    #[test]
    fn quantized_length_patch() {
        use wrex_core::patch::{Edit, Scope, patch};
        let mut r = Registry::empty();
        register(&mut r);
        let s = PacketSpec::new(
            vec![spec(
                KIND_HOPOPTS,
                &[("next_header", "6"), ("options", "010400000000")],
            )],
            None,
        );
        let enc = encode(&r, &s, &af_opts()).unwrap();
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, KIND_HOPOPTS);
        // Normalize (Scope::all): byte-identical (already consistent).
        let out = patch(&r, &p, &[], &Scope::all()).unwrap();
        assert_eq!(&out[..], &enc.bytes[..]);
        // Insert 8 bytes into the options region: the ext `len` is
        // self-referential under dissection (the dissector trusts it,
        // so the re-dissected span cannot grow past the stale len) —
        // the honest workflow sets len explicitly alongside the
        // insert, under preserve (the add-a-record precedent:
        // count-style fields are caller-decided), then a second
        // normalize pass heals everything (len already consistent →
        // a no-op; the udp/tcp checksums fold over the grown region).
        let p2 = wrex_core::dissect::dissect(&r, &out, KIND_HOPOPTS);
        let edits = vec![
            Edit::Insert {
                at: 2 + 3, // inside the options region
                bytes: bytes::Bytes::from_static(&[0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            },
            Edit::SetField {
                path: "hopopts.len".to_string(),
                bytes: bytes::Bytes::from_static(&[1]),
            },
        ];
        let out2 = patch(&r, &p2, &edits, &Scope::none()).unwrap();
        assert_eq!(out2[1], 1); // 16 octets, declared
        let re = wrex_core::dissect::dissect(&r, &out2, KIND_HOPOPTS);
        assert_eq!(re.layers[0].span, 0..16, "the grown region dissects");
        assert!(re.anomalies.is_empty(), "{:?}", re.anomalies);
        // Normalize afterwards: idempotent (len already consistent).
        let p3 = wrex_core::dissect::dissect(&r, &out2, KIND_HOPOPTS);
        let out3 = patch(&r, &p3, &[], &Scope::all()).unwrap();
        assert_eq!(&out3[..], &out2[..]);
        // A quantized recompute over a non-grid span is a pointed
        // error (LengthNotQuantized) — unreachable through THIS
        // family's dissectors (the span is grid-aligned by
        // construction); the guard is pinned by the wrex-core mock
        // suite over a synthetic non-multiple span.
    }
}
