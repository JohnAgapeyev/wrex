//! Dissection output model and chain-walk engine.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;

use bytes::{Bytes, BytesMut};

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
    pub const fn proto(&self) -> u8 {
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
    /// Absolute offset where the *upper-layer packet* begins — recorded
    /// by the net-layer codecs (ipv4: after its header incl. options;
    /// ipv6: after the 40-byte header, i.e. at the first extension
    /// header) at both write and read. RFC 8200 §8.1 makes the L4
    /// checksum cover everything from here (tranche 17a): the L4
    /// encode-side checksum defers and the patch-engine
    /// `ChecksumStart::UpperPacket` walk accumulate from it, and the
    /// dissect-side verify reads the range through [`DecodeCtx::frame`].
    /// `None` = no net-layer parent recorded it (bare-layer craft, the
    /// pre-17a direct-parent value falls out as the layer's own start).
    pub upper_start: Option<usize>,
    /// The L4 arrived via a FRAGMENT header (v4 `mf`/frag_off, or a
    /// v6 frag header anywhere in the chain): its checksum was folded
    /// over the ORIGINAL unfragmented upper-layer packet, so a single
    /// fragment carrier can never verify — the fold over the visible
    /// bytes is a *different* sum by construction. The kernel and
    /// tshark verify after reassembly; so does `wrex replay
    /// --reassemble` (the reassembled datagram re-dissects with no
    /// frag header in the chain and the original checksum verifies).
    /// The L4 dissect-side verifies skip when set — the foreign-capture
    /// scenarios (HP3-b, the kernel-carved fragment corpus) drove the
    /// fix: every frag0 dissected with a pointed false
    /// `icmp/udp/tcp/icmpv6.checksum` anomaly before it.
    pub fragmented: bool,
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
    pub fields: BTreeMap<Cow<'static, str>, Value>,
    /// Per-field wire geometry (tranche 11b), populated by the engine
    /// from [`crate::codec::Codec::layouts`] after `read` returns.
    pub field_spans: BTreeMap<Cow<'static, str>, FieldSpan>,
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
    /// The value re-encodes at this range (tranche 13a): the codec's
    /// [`crate::codec::Codec::reencode`] hook serializes the edit
    /// value into the region replacement (NUL-padded `Str` regions:
    /// dhcp sname/file; pointer-resolved dns names: the range is the
    /// *pointer target*, so a patch rewrites the shared target).
    /// A codec without a hook for the field → a pointed deferral
    /// error ([`crate::patch::PatchError::UnsupportedPath`]).
    ReEncode(Range<usize>),
    /// No span recorded: dynamic regions (ipv4/tcp `options`, …).
    /// Patching is a **pointed error**, never a silent wrong-target
    /// write.
    None,
}

impl FieldSpan {
    /// The container range a patch writes into (`Bytes`' own range for
    /// whole-field patches, the `Bits` container otherwise).
    pub const fn container(&self) -> Option<Range<usize>> {
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
    /// The **full input frame** (tranche 17a): codecs receive
    /// `read(bytes = frame[offset..])` as their slice, and this field
    /// gives the lookback — the dissect-side L4 checksum verify under
    /// v6 extension chains accumulates
    /// `frame[facts.upper_start..]` (the RFC 8200 §8.1 upper-layer
    /// packet), which its forward slice cannot see. Empty under
    /// `new()` (in-crate codec unit tests call `read` directly); the
    /// dissect engine always sets it via [`DecodeCtx::with_frame`].
    pub frame: &'a [u8],
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
            frame: &[],
            facts: Facts::default(),
            anomalies: Vec::new(),
            _lifetime: PhantomData,
        }
    }

    /// Engine constructor: `frame` is the complete input, `offset` the
    /// layer's position within it (`bytes == frame[offset..]`).
    pub fn with_frame(frame: &'a [u8], offset: usize) -> Self {
        Self {
            offset,
            frame,
            facts: Facts::default(),
            anomalies: Vec::new(),
            _lifetime: PhantomData,
        }
    }
}

/// Auto-start heuristic for `dissect --start auto`:
/// `bytes[0] >> 4 == 4` → ipv4; `== 6` → ipv6 (tranche 7b); else
/// len ≥ 14 → eth; else unknown. (const: `first` is not const-stable,
/// index guarded.)
pub const fn auto_start(bytes: &[u8]) -> &'static str {
    let first = if bytes.is_empty() {
        256
    } else {
        bytes[0] as usize
    };
    match first {
        b if b >> 4 == 4 => "ipv4",
        b if b >> 4 == 6 => "ipv6",
        _ if bytes.len() >= 14 => "eth",
        _ => "unknown",
    }
}

/// Synthesize the terminal `unknown` layer holding the frame bytes from
/// `offset` on as one `hex` field (zero-copy: refcount slice).
fn unknown_layer(frame: &Bytes, offset: usize) -> LayerView {
    let len = frame.len();
    let mut fields = BTreeMap::new();
    fields.insert("hex".into(), Value::Bytes(frame.slice(offset..)));
    let mut spans = BTreeMap::new();
    spans.insert(
        "hex".into(),
        FieldSpan::Bytes(offset..offset + (len - offset)),
    );
    LayerView {
        kind: "unknown",
        span: offset..len,
        field_spans: spans,
        fields,
    }
}

/// Frame ownership transfer into [`dissect`]: the hot paths hold a
/// [`Bytes`] (the io drivers) and hand it over **zero-copy** —
/// refcount clone, retention is refcount slices of the same backing;
/// borrowed forms copy once up front (as they always did at retention).
pub trait IntoFrame {
    fn into_frame(self) -> Bytes;
}

impl IntoFrame for Bytes {
    fn into_frame(self) -> Bytes {
        self
    }
}

impl IntoFrame for Vec<u8> {
    fn into_frame(self) -> Bytes {
        Bytes::from(self)
    }
}

impl IntoFrame for Box<[u8]> {
    fn into_frame(self) -> Bytes {
        Bytes::from(self)
    }
}

impl IntoFrame for &Bytes {
    fn into_frame(self) -> Bytes {
        self.clone()
    }
}

impl IntoFrame for &[u8] {
    fn into_frame(self) -> Bytes {
        Bytes::copy_from_slice(self)
    }
}

impl<const N: usize> IntoFrame for &[u8; N] {
    fn into_frame(self) -> Bytes {
        Bytes::copy_from_slice(&self[..])
    }
}

impl IntoFrame for &Vec<u8> {
    fn into_frame(self) -> Bytes {
        Bytes::copy_from_slice(self)
    }
}

impl IntoFrame for &mut [u8] {
    fn into_frame(self) -> Bytes {
        Bytes::copy_from_slice(self)
    }
}

impl IntoFrame for &BytesMut {
    fn into_frame(self) -> Bytes {
        Bytes::copy_from_slice(&self[..])
    }
}

/// Dissect `bytes` starting at `start` (a registry kind or `"auto"`).
///
/// `start` is resolved through the registry so [`DissectedPacket::start`] is
/// always a registered `&'static str` (or the literal `"unknown"`).
///
/// `bytes` takes anything [`IntoFrame`]: a caller holding a `Bytes`
/// (the io drivers already do) retains **zero-copy** — `frame` and
/// `payload` are refcount slices of the same backing; borrowed forms
/// copy once up front (as they always did at retention).
pub fn dissect(registry: &Registry, bytes: impl IntoFrame, start: &str) -> DissectedPacket {
    let bytes = bytes.into_frame();
    let start: &'static str = if start == "auto" {
        auto_start(&bytes)
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
                        let mut ctx = DecodeCtx::with_frame(&bytes, offset);
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
                                layers.push(unknown_layer(&bytes, offset));
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
                        layers.push(unknown_layer(&bytes, offset));
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
        // Zero-copy retention: refcount slices of the caller's backing.
        payload: bytes.slice(payload_at..),
        anomalies,
        frame: bytes,
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
    let mut spans: BTreeMap<Cow<'static, str>, FieldSpan> = std::mem::take(&mut view.field_spans);
    // Names the static table spanned (sub-bit derivation eligibility).
    let mut layout_derived: Vec<Cow<'static, str>> = Vec::new();
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
        if !layout_derived.iter().any(|n| n.as_ref() == f.name) {
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
                Cow::Owned(crate::schema::dotted_path(f.name, bit)),
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
    use crate::codec::{Codec, Next, ReadOutcome, Registry};
    use crate::error::EncodeError;
    use crate::schema::{FieldKind, FieldSchema, LayerSchema, Layout};
    use crate::spec::LayerSpec;

    // A 2-byte fixed-header codec for engine-geometry tests (the payload
    // handoff and the span table merge).
    static MINI_FIELDS: &[FieldSchema] = &[FieldSchema {
        name: "x",
        kind: FieldKind::U8,
        bit_names: &[],
        default: Value::Int(0),
        required: false,
        doc: "x",
    }];
    static MINI_SCHEMA: LayerSchema = LayerSchema {
        kind: "mocki",
        rank: 5,
        parents: &[],
        doc: "dissect-test mock",
        fields: MINI_FIELDS,
        records: &[],
    };
    struct MockMini;
    impl Codec for MockMini {
        fn schema(&self) -> &'static LayerSchema {
            &MINI_SCHEMA
        }
        fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
            Ok(2)
        }
        fn write(
            &self,
            _spec: &LayerSpec,
            _ctx: &mut crate::encode::EncodeCtx,
        ) -> Result<(), EncodeError> {
            Ok(())
        }
        fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
            if bytes.len() < 2 {
                return ReadOutcome::Anomaly(
                    crate::error::DecodeError::Truncated {
                        kind: "mocki",
                        need: 2,
                        have: bytes.len(),
                    },
                    Next::Payload,
                );
            }
            let mut fields = BTreeMap::new();
            fields.insert("x".into(), Value::Int(bytes[0] as u128));
            let view = LayerView {
                kind: "mocki",
                span: ctx.offset..ctx.offset + 2,
                field_spans: Default::default(),
                fields,
            };
            ReadOutcome::Layer(view, Some(Next::Payload))
        }
    }

    // A codec with flag aggregates + bit-window layouts (the span
    // table merge and sub-bit derivation fixture).
    static LAY_FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "f",
            kind: FieldKind::U16,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "f",
        },
        FieldSchema {
            name: "g",
            kind: FieldKind::FlagSet,
            bit_names: &["a", "b"],
            default: Value::Int(0),
            required: false,
            doc: "g (Bytes-layout flagset)",
        },
        FieldSchema {
            name: "flags",
            kind: FieldKind::FlagSet,
            bit_names: &["syn", "fin"],
            default: Value::Int(0),
            required: false,
            doc: "flags (Bits-layout flagset)",
        },
    ];
    static LAY_SCHEMA: LayerSchema = LayerSchema {
        kind: "mocklay",
        rank: 5,
        parents: &[],
        doc: "span-merge mock",
        fields: LAY_FIELDS,
        records: &[],
    };
    struct MockLay;
    impl Codec for MockLay {
        fn schema(&self) -> &'static LayerSchema {
            &LAY_SCHEMA
        }
        fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
            Ok(3)
        }
        fn write(
            &self,
            _spec: &LayerSpec,
            _ctx: &mut crate::encode::EncodeCtx,
        ) -> Result<(), EncodeError> {
            Ok(())
        }
        fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
            if bytes.len() < 3 {
                return ReadOutcome::Anomaly(
                    crate::error::DecodeError::Truncated {
                        kind: "mocklay",
                        need: 3,
                        have: bytes.len(),
                    },
                    Next::Payload,
                );
            }
            let mut fields = BTreeMap::new();
            fields.insert("f".into(), Value::Int(0x1234));
            fields.insert("g".into(), Value::List(vec![Value::Str("a".into())]));
            fields.insert("flags".into(), Value::List(vec![Value::Str("syn".into())]));
            let view = LayerView {
                kind: "mocklay",
                span: ctx.offset..ctx.offset + 3,
                field_spans: Default::default(),
                fields,
            };
            ReadOutcome::Layer(view, Some(Next::Payload))
        }
        fn layouts(&self) -> &'static [(&'static str, Layout)] {
            &[
                ("f", Layout::Bytes { at: 0, len: 2 }),
                ("g", Layout::Bytes { at: 2, len: 1 }),
                (
                    "flags",
                    Layout::Bits {
                        at: 2,
                        shift: 0,
                        width: 8,
                    },
                ),
            ]
        }
    }

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
    fn net_facts_proto_accessor() {
        let v4 = NetFacts::V4 {
            src: Ipv4Addr::LOCALHOST,
            dst: Ipv4Addr::UNSPECIFIED,
            proto: 17,
        };
        assert_eq!(v4.proto(), 17);
        let v6 = NetFacts::V6 {
            src: Ipv6Addr::LOCALHOST,
            dst: Ipv6Addr::UNSPECIFIED,
            next_header: 58,
        };
        assert_eq!(v6.proto(), 58);
    }

    #[test]
    fn field_span_container_variants() {
        assert_eq!(FieldSpan::Bytes(2..5).container(), Some(2..5));
        assert_eq!(
            FieldSpan::Bits {
                container: 1..3,
                shift: 4,
                width: 8,
            }
            .container(),
            Some(1..3)
        );
        assert_eq!(FieldSpan::ReEncode(4..6).container(), Some(4..6));
        assert_eq!(FieldSpan::None.container(), None);
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
        // The synthetic layer's hex field carries its own span.
        assert_eq!(
            p.layers[0].field_spans.get("hex"),
            Some(&FieldSpan::Bytes(0..2))
        );
    }

    #[test]
    fn layer_reads_advance_offset_into_payload() {
        let mut r = Registry::empty();
        r.register(&MockMini);
        let p = dissect(&r, &[0x0a, 0x0b, 0xcc, 0xdd], "mocki");
        assert_eq!(p.start, "mocki");
        assert_eq!(p.layers.len(), 1);
        assert_eq!(p.layers[0].span, 0..2);
        // The terminal payload starts after the consumed header.
        assert_eq!(&p.payload[..], &[0xcc, 0xdd]);
        // Truncated read: never fatal, the remainder is retained.
        let t = dissect(&r, &[0x0a], "mocki");
        assert_eq!(t.layers.len(), 1);
        assert_eq!(t.layers[0].kind, "unknown");
        assert_eq!(&t.frame[..], &[0x0a]);
    }

    // A codec with EXACTLY ONE layout-derived field, a FlagSet aggregate:
    // sub-bit derivation must not depend on other layout entries.
    static SOLO_FIELDS: &[FieldSchema] = &[FieldSchema {
        name: "flags",
        kind: FieldKind::FlagSet,
        bit_names: &["syn", "fin"],
        default: Value::Int(0),
        required: false,
        doc: "flags (Bits-layout flagset, solo)",
    }];
    static SOLO_SCHEMA: LayerSchema = LayerSchema {
        kind: "mocksolo",
        rank: 5,
        parents: &[],
        doc: "solo flagset mock",
        fields: SOLO_FIELDS,
        records: &[],
    };
    struct MockSolo;
    impl Codec for MockSolo {
        fn schema(&self) -> &'static LayerSchema {
            &SOLO_SCHEMA
        }
        fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
            Ok(1)
        }
        fn write(
            &self,
            _spec: &LayerSpec,
            _ctx: &mut crate::encode::EncodeCtx,
        ) -> Result<(), EncodeError> {
            Ok(())
        }
        fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
            if bytes.is_empty() {
                return ReadOutcome::Anomaly(
                    crate::error::DecodeError::Truncated {
                        kind: "mocksolo",
                        need: 1,
                        have: bytes.len(),
                    },
                    Next::Payload,
                );
            }
            let mut fields = BTreeMap::new();
            fields.insert("flags".into(), Value::List(vec![Value::Str("syn".into())]));
            let view = LayerView {
                kind: "mocksolo",
                span: ctx.offset..ctx.offset + 1,
                field_spans: Default::default(),
                fields,
            };
            ReadOutcome::Layer(view, Some(Next::Payload))
        }
        fn layouts(&self) -> &'static [(&'static str, Layout)] {
            &[(
                "flags",
                Layout::Bits {
                    at: 0,
                    shift: 0,
                    width: 8,
                },
            )]
        }
    }

    #[test]
    fn populate_spans_derives_subbits_for_solo_aggregate() {
        let mut r = Registry::empty();
        r.register(&MockSolo);
        let p = dissect(&r, &[0x02], "mocksolo");
        let spans = &p.layers[0].field_spans;
        assert_eq!(
            spans.get("flags"),
            Some(&FieldSpan::Bits {
                container: 0..1,
                shift: 0,
                width: 8,
            })
        );
        // Sub-bit derivation for the solo layout-derived aggregate:
        // MSB-first inside its own window (syn = bit 1 → shift 6).
        assert_eq!(
            spans.get("flags.syn"),
            Some(&FieldSpan::Bits {
                container: 0..1,
                shift: 6,
                width: 1,
            })
        );
        assert_eq!(
            spans.get("flags.fin"),
            Some(&FieldSpan::Bits {
                container: 0..1,
                shift: 7,
                width: 1,
            })
        );
    }

    #[test]
    fn populate_spans_merges_layouts_and_derives_subbits() {
        let mut r = Registry::empty();
        r.register(&MockLay);
        let p = dissect(&r, &[0x12, 0x34, 0x56, 0xff], "mocklay");
        let spans = &p.layers[0].field_spans;
        // Static table: absolute (base + at..at+len).
        assert_eq!(spans.get("f"), Some(&FieldSpan::Bytes(0..2)));
        assert_eq!(spans.get("g"), Some(&FieldSpan::Bytes(2..3)));
        assert_eq!(
            spans.get("flags"),
            Some(&FieldSpan::Bits {
                container: 2..3,
                shift: 0,
                width: 8,
            })
        );
        // Sub-bit paths of layout-derived FlagSet aggregates: one bit
        // each, MSB-first inside the aggregate's own window.
        assert_eq!(
            spans.get("g.a"),
            Some(&FieldSpan::Bits {
                container: 2..3,
                shift: 6,
                width: 1,
            })
        );
        assert_eq!(
            spans.get("flags.syn"),
            Some(&FieldSpan::Bits {
                container: 2..3,
                shift: 6,
                width: 1,
            })
        );
        assert_eq!(
            spans.get("flags.fin"),
            Some(&FieldSpan::Bits {
                container: 2..3,
                shift: 7,
                width: 1,
            })
        );
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
