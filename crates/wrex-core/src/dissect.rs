//! Dissection output model and chain-walk engine.

use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;

use bytes::Bytes;

use crate::codec::{Next, ReadOutcome, Registry};
use crate::error::DecodeError;
use crate::value::Value;

/// Facts propagated along the dissection chain (recorded by network-layer
/// codecs, consumed by L4/ICMPv6 checksum verification). Generalized over
/// the IP version at tranche 7b — additive: every pre-7b consumer matched
/// the `V4` variant only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetFacts {
    V4 {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        proto: u8,
    },
    V6 {
        src: Ipv6Addr,
        dst: Ipv6Addr,
        next_header: u8,
    },
}

impl NetFacts {
    /// The upper-layer protocol number (v4 `proto` / v6 `next_header`).
    pub fn proto(&self) -> u8 {
        match *self {
            NetFacts::V4 { proto, .. } => proto,
            NetFacts::V6 { next_header, .. } => next_header,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Facts {
    pub net: Option<NetFacts>,
    /// Interface MAC (send `-i`): eth.src autofill source.
    pub link_src: Option<[u8; 6]>,
    /// Interface MAC for dst autofill (reserved; unused in tranche 1).
    pub link_dst: Option<[u8; 6]>,
}

/// One dissected layer: kind, byte span in the input, local fields, and
/// per-field wire geometry (tranche 11b).
///
/// `field_spans` is a **parallel map** to `fields` — same name keys,
/// geometry only — kept separate because semantics (scalar/aggregate/
/// record) resolve through the schema, single-sourced. The
/// **total-presence invariant** holds: every key of `fields` has a
/// `field_spans` entry (a real span, or `None` where patching is
/// deliberately unsupported); absence of a key is always a bug.
/// Sub-bit paths (`flags.syn`) appear as extra keys derived from
/// `FieldKind::FlagSet` bit names.
#[derive(Clone, Debug)]
pub struct LayerView {
    pub kind: &'static str,
    pub span: Range<usize>,
    pub fields: BTreeMap<String, Value>,
    /// Per-field wire geometry (tranche 11b), populated by the engine
    /// from [`crate::codec::Codec::layouts`] after `read` returns.
    pub field_spans: BTreeMap<String, FieldSpan>,
}

/// Wire geometry of one dissected field path (tranche 11b): where the
/// bytes (or bits) live, in **absolute frame offsets**, and how a patch
/// applies. The closed enum carries geometry only — the schema keeps
/// semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldSpan {
    /// `len` contiguous bytes at an absolute frame range: scalars,
    /// hoisted sources, derived wire-homes. A patch overwrites them.
    Bytes(Range<usize>),
    /// A bit window (MSB-first `shift`/`width`) inside a container range:
    /// bit-sliced subfields (`ipv4.ver`, `vlan.vid`), aggregates
    /// (`ipv4.flags` = its own window), per-bit FlagSet subpaths
    /// (`tcp.flags.syn`). A patch masked-writes the container.
    Bits {
        container: Range<usize>,
        shift: u8,
        width: u8,
    },
    /// The value re-encodes at this range (NUL-padded, re-derived
    /// padding: dhcp sname/file). Reserved for the tranche-11b codec
    /// slices; patching one is a pointed deferral error until then.
    ReEncode(Range<usize>),
    /// No span recorded: pointer-resolved (dns compressed names) or
    /// dynamic regions (options, record sections until their slice).
    /// Patching is a **pointed error**, never a silent wrong-target
    /// write.
    None,
}

impl FieldSpan {
    /// The container range a patch writes into (`Bytes`' own range for
    /// whole-field patches, the `Bits` container otherwise).
    pub fn container(&self) -> Option<Range<usize>> {
        match self {
            FieldSpan::Bytes(r) | FieldSpan::ReEncode(r) => Some(r.start..r.end),
            FieldSpan::Bits { container, .. } => Some(container.start..container.end),
            FieldSpan::None => None,
        }
    }
}

/// A non-fatal dissection anomaly (`! path: message` in text output).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anomaly {
    pub path: String,
    pub message: String,
}

impl Anomaly {
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Anomaly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "! {}: {}", self.path, self.message)
    }
}

/// A fully dissected packet. Never fatal: structural failures become
/// [`Anomaly`]s plus a synthetic `unknown` layer holding the remaining bytes.
///
/// Tranche 11a (the byte-fidelity contract): the original input is
/// **retained** in `frame`; every layer's `span` (and the payload tail)
/// resolves against it, and [`DissectedPacket::reassemble`] stitches those
/// spans back verbatim — zero edits ⇒ byte-identical by construction,
/// malformed included (nothing is re-derived).
#[derive(Clone, Debug)]
pub struct DissectedPacket {
    pub start: &'static str,
    pub layers: Vec<LayerView>,
    pub payload: Bytes,
    pub anomalies: Vec<Anomaly>,
    /// The original dissected input, retained verbatim (tranche 11a).
    pub frame: Bytes,
    /// Facts recorded by the chain walk (tranche 11b: net-layer
    /// addresses/protocol for pseudo-header recomputation).
    pub facts: Facts,
}

impl DissectedPacket {
    /// Verbatim reassembly (tranche 11a): splice each layer's span bytes
    /// out of the retained `frame`, then the payload.
    ///
    /// With no edits applied this is byte-identical to `frame` **by
    /// construction** for any input dissection accepts — wrong checksums,
    /// compressed names, trailing bytes all survive, because no field is
    /// ever re-derived. The future span-patch engine composes on this same
    /// stitch: edits at spans, then a caller-selected derived-field
    /// recompute pass (the deferred tranche-11b scope).
    ///
    /// Coverage invariant (holds for every packet produced by
    /// [`dissect`], and debug-asserted here): layer spans are ordered,
    /// non-overlapping, inside the frame, and together with the payload
    /// exhaust it.
    pub fn reassemble(&self) -> Bytes {
        let len = self.frame.len();
        let mut out = bytes::BytesMut::with_capacity(len);
        let mut cursor = 0usize;
        for l in &self.layers {
            debug_assert!(
                l.span.start >= cursor && l.span.end <= len && l.span.start <= l.span.end,
                "layer {} span {:?} breaks coverage invariant (cursor {cursor}, frame {len})",
                l.kind,
                l.span
            );
            let s = l.span.start.min(len);
            let e = l.span.end.max(s).min(len);
            out.extend_from_slice(&self.frame[s..e]);
            cursor = e;
        }
        out.extend_from_slice(&self.payload);
        out.freeze()
    }
}

/// Per-chain-walk decode context handed to [`crate::codec::Codec::read`].
pub struct DecodeCtx<'a> {
    /// Absolute offset of `bytes` within the full input.
    pub offset: usize,
    /// Facts recorded by earlier layers in this chain.
    pub facts: Facts,
    /// Non-fatal anomalies pushed by codecs (checksum mismatches etc.).
    pub anomalies: Vec<Anomaly>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> DecodeCtx<'a> {
    pub fn new(offset: usize) -> Self {
        Self {
            offset,
            facts: Facts::default(),
            anomalies: Vec::new(),
            _lifetime: PhantomData,
        }
    }
}

/// Auto-start heuristic for `dissect --start auto`:
/// `bytes[0] >> 4 == 4` → ipv4; `== 6` → ipv6 (tranche 7b); else
/// len ≥ 14 → eth; else unknown.
pub fn auto_start(bytes: &[u8]) -> &'static str {
    match bytes.first() {
        None => "unknown",
        Some(&b) if b >> 4 == 4 => "ipv4",
        Some(&b) if b >> 4 == 6 => "ipv6",
        Some(_) if bytes.len() >= 14 => "eth",
        _ => "unknown",
    }
}

/// Synthesize the terminal `unknown` layer holding `bytes` as one `hex` field.
fn unknown_layer(bytes: &[u8], offset: usize) -> LayerView {
    let mut fields = BTreeMap::new();
    fields.insert(
        "hex".to_string(),
        Value::Bytes(Bytes::copy_from_slice(bytes)),
    );
    let mut spans = BTreeMap::new();
    spans.insert(
        "hex".to_string(),
        FieldSpan::Bytes(offset..offset + bytes.len()),
    );
    LayerView {
        kind: "unknown",
        span: offset..offset + bytes.len(),
        field_spans: spans,
        fields,
    }
}

/// Dissect `bytes` starting at `start` (a registry kind or `"auto"`).
///
/// `start` is resolved through the registry so [`DissectedPacket::start`] is
/// always a registered `&'static str` (or the literal `"unknown"`).
pub fn dissect(registry: &Registry, bytes: &[u8], start: &str) -> DissectedPacket {
    let start: &'static str = if start == "auto" {
        auto_start(bytes)
    } else {
        match registry.get(start) {
            Some(codec) => codec.schema().kind,
            None => "unknown",
        }
    };
    let mut layers: Vec<LayerView> = Vec::new();
    let mut anomalies: Vec<Anomaly> = Vec::new();
    let mut facts = Facts::default();
    let mut offset = 0usize;
    let mut chain = Some(Next::Kind(start));
    let mut payload_start = None;

    while let Some(next) = chain {
        match next {
            Next::Payload => {
                payload_start = Some(offset);
                chain = None;
            }
            Next::Kind(kind) => {
                let rest = &bytes[offset.min(bytes.len())..];
                match registry.get(kind) {
                    Some(codec) => {
                        let mut ctx = DecodeCtx::new(offset);
                        ctx.facts = facts;
                        match codec.read(rest, &mut ctx) {
                            ReadOutcome::Layer(mut view, next) => {
                                offset += view.span.len();
                                facts = ctx.facts;
                                anomalies.append(&mut ctx.anomalies);
                                populate_field_spans(&mut view, codec.schema(), codec.layouts());
                                layers.push(view);
                                chain = Some(next.unwrap_or(Next::Payload));
                            }
                            ReadOutcome::Anomaly(err, _next) => {
                                facts = ctx.facts;
                                anomalies.append(&mut ctx.anomalies);
                                anomalies.push(anomaly_for(&err));
                                // Structural failure: keep the remaining bytes
                                // as partial data in a synthetic layer.
                                layers.push(unknown_layer(rest, offset));
                                offset = bytes.len();
                                payload_start = Some(bytes.len());
                                chain = None;
                            }
                            ReadOutcome::Empty => {
                                facts = ctx.facts;
                                anomalies.append(&mut ctx.anomalies);
                                payload_start = Some(offset);
                                chain = None;
                            }
                        }
                    }
                    None => {
                        // Unknown/unregistered kind (unknown ethertype, ipv6,
                        // `--start unknown`): synthetic hex layer, terminal.
                        layers.push(unknown_layer(rest, offset));
                        offset = bytes.len();
                        payload_start = Some(bytes.len());
                        chain = None;
                    }
                }
            }
        }
    }

    let payload_at = payload_start.unwrap_or(bytes.len()).min(bytes.len());
    DissectedPacket {
        start,
        layers,
        payload: Bytes::copy_from_slice(&bytes[payload_at..]),
        anomalies,
        frame: Bytes::copy_from_slice(bytes),
        facts,
    }
}

/// Populate [`LayerView::field_spans`] — a **merge** (tranche 11b):
///
/// 1. **Codec-provided entries win** (dynamic geometry recorded at
///    parse time: record sections, hoisted sources, scattered flag
///    bits). The codec's map is the seed.
/// 2. The static [`crate::codec::Codec::layouts`] table fills every
///    still-missing field key (fixed header geometry, `base + at`).
/// 3. Sub-bit paths derive for `FieldKind::FlagSet` aggregates that
///    got a **layout-derived** span (contiguous windows only —
///    scattered aggregates like dns `flags` are codec-side) and whose
///    subbits the codec did not already provide.
/// 4. `None`-fallback for the remainder — **total presence**: every
///    key of `fields` resolves; the variant carries the policy.
fn populate_field_spans(
    view: &mut LayerView,
    schema: &crate::schema::LayerSchema,
    layouts: &[(&'static str, crate::schema::Layout)],
) {
    use crate::schema::Layout;
    let base = view.span.start;
    let lookup = |name: &str| layouts.iter().find(|(n, _)| *n == name).map(|(_, l)| *l);
    let mut spans: BTreeMap<String, FieldSpan> = std::mem::take(&mut view.field_spans);
    // Names the static table spanned (sub-bit derivation eligibility).
    let mut layout_derived: Vec<String> = Vec::new();
    for name in view.fields.keys() {
        if spans.contains_key(name) {
            continue;
        }
        match lookup(name) {
            Some(Layout::Bytes { at, len }) => {
                spans.insert(name.clone(), FieldSpan::Bytes(base + at..base + at + len));
                layout_derived.push(name.clone());
            }
            Some(Layout::ReEncode { at, len }) => {
                spans.insert(
                    name.clone(),
                    FieldSpan::ReEncode(base + at..base + at + len),
                );
                layout_derived.push(name.clone());
            }
            Some(Layout::Bits { at, shift, width }) => {
                spans.insert(
                    name.clone(),
                    FieldSpan::Bits {
                        container: base + at
                            ..base + at + Layout::container_len(&Layout::Bits { at, shift, width }),
                        shift,
                        width,
                    },
                );
                layout_derived.push(name.clone());
            }
            None => {
                spans.insert(name.clone(), FieldSpan::None);
            }
        }
    }
    // Sub-bit paths of layout-derived FlagSet aggregates: extra keys,
    // one bit each, MSB-first inside the aggregate's own window.
    for f in schema.fields {
        if f.kind != crate::schema::FieldKind::FlagSet {
            continue;
        }
        // Only aggregates the static table spanned into THIS view
        // (conditional fields stay out; codec-side subbits win).
        if !layout_derived.iter().any(|n| n == f.name) {
            continue;
        }
        let Some(l) = lookup(f.name) else {
            continue;
        };
        let (window_shift, window_width) = match l {
            Layout::Bytes { len, .. } => (0u8, (len * 8) as u8),
            Layout::Bits { shift, width, .. } => (shift, width),
            Layout::ReEncode { .. } => continue,
        };
        for bit in f.bit_names {
            let Some(pos) = f.bit_pos(bit) else {
                continue;
            };
            let shift = window_shift + window_width.saturating_sub(1) - pos;
            spans.insert(
                format!("{}.{bit}", f.name),
                FieldSpan::Bits {
                    container: FieldSpan::container(&spans[f.name]).expect("aggregate span"),
                    shift,
                    width: 1,
                },
            );
        }
    }
    view.field_spans = spans;
}

fn anomaly_for(err: &DecodeError) -> Anomaly {
    match err {
        DecodeError::Truncated { kind, need, have } => {
            Anomaly::new(*kind, format!("truncated: need {need} bytes, have {have}"))
        }
        DecodeError::BadField { path, reason } => Anomaly::new(path.clone(), reason.clone()),
        DecodeError::Unsupported { kind } => Anomaly::new(*kind, "unsupported".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heuristic_table() {
        assert_eq!(auto_start(&[]), "unknown");
        assert_eq!(auto_start(&[0x45, 0x00]), "ipv4");
        assert_eq!(auto_start(&[0x60, 0x00, 0x00, 0x00]), "ipv6"); // ipv6 (tranche 7b)
        assert_eq!(auto_start(&[0xff; 14]), "eth");
        assert_eq!(auto_start(&[0xff; 13]), "unknown");
        assert_eq!(auto_start(&[0x00, 0x11, 0x22]), "unknown");
    }

    #[test]
    fn empty_input_is_never_fatal() {
        let r = Registry::empty();
        let p = dissect(&r, &[], "auto");
        assert_eq!(p.start, "unknown");
        assert_eq!(p.layers.len(), 1);
        assert_eq!(p.layers[0].kind, "unknown");
        assert_eq!((p.layers[0].span.start, p.layers[0].span.end), (0, 0));
        assert!(p.payload.is_empty());
    }

    #[test]
    fn unknown_start_kind_synthesizes() {
        let r = Registry::empty();
        let p = dissect(&r, &[0xaa, 0xbb], "eth");
        // no eth codec registered: unknown layer holding the bytes
        assert_eq!(p.layers.len(), 1);
        assert_eq!(p.layers[0].kind, "unknown");
        assert_eq!(p.layers[0].span, 0..2);
        match p.layers[0].fields.get("hex") {
            Some(Value::Bytes(b)) => assert_eq!(&b[..], &[0xaa, 0xbb]),
            other => panic!("no hex field: {other:?}"),
        }
    }

    /// Tranche 11a: the frame is retained and reassembles verbatim —
    /// including on the never-fatal structural-failure paths.
    #[test]
    fn reassemble_is_verbatim_by_construction() {
        let r = Registry::empty();
        for (bytes, start) in [
            (&[][..], "auto"),
            (&[0xaa, 0xbb][..], "eth"),
            (&[0xff; 14][..], "auto"),
            (&[0xff; 13][..], "auto"),
        ] {
            let p = dissect(&r, bytes, start);
            assert_eq!(&p.frame[..], bytes, "frame retained verbatim");
            assert_eq!(&p.reassemble()[..], bytes, "reassemble == frame ({start})");
        }
    }
}
