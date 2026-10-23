use crate::value::Value;

/// The primitive kinds a protocol field can take.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FieldKind {
    U8,
    U16,
    U32,
    U64,
    U128,
    Ipv4,
    Ipv6,
    Mac,
    Bytes,
    FlagSet,
    Str,
    ByteList,
}

impl FieldKind {
    /// Inclusive upper bound for integer field kinds; `None` otherwise.
    pub const fn int_max(self) -> Option<u128> {
        match self {
            FieldKind::U8 => Some(u8::MAX as u128),
            FieldKind::U16 => Some(u16::MAX as u128),
            FieldKind::U32 => Some(u32::MAX as u128),
            FieldKind::U64 => Some(u64::MAX as u128),
            FieldKind::U128 => Some(u128::MAX),
            _ => None,
        }
    }

    pub const fn type_name(self) -> &'static str {
        match self {
            FieldKind::U8 => "u8",
            FieldKind::U16 => "u16",
            FieldKind::U32 => "u32",
            FieldKind::U64 => "u64",
            FieldKind::U128 => "u128",
            FieldKind::Ipv4 => "ipv4",
            FieldKind::Ipv6 => "ipv6",
            FieldKind::Mac => "mac",
            FieldKind::Bytes => "bytes",
            FieldKind::FlagSet => "flagset",
            FieldKind::Str => "str",
            FieldKind::ByteList => "bytelist",
        }
    }
}

/// One settable field of a layer.
///
/// `bit_names` is only meaningful for [`FieldKind::FlagSet`] and is listed
/// most-significant bit first (e.g. TCP `[cwr,ece,urg,ack,psh,rst,syn,fin]`):
/// `bit_names[0]` ↔ the highest bit of the unit.
#[derive(Clone, Debug)]
pub struct FieldSchema {
    pub name: &'static str,
    pub kind: FieldKind,
    pub bit_names: &'static [&'static str],
    pub default: Value,
    pub required: bool,
    pub doc: &'static str,
}

impl FieldSchema {
    /// Bit position for a flag name within its unit, MSB-first.
    pub fn bit_pos(&self, name: &str) -> Option<u8> {
        let n = self.bit_names.len();
        if n == 0 || n > 8 {
            return None;
        }
        let index = self.bit_names.iter().position(|b| *b == name)?;
        Some((n - 1 - index) as u8)
    }

    pub fn bit_mask(&self, name: &str) -> Option<u128> {
        self.bit_pos(name).map(|pos| 1 << pos)
    }
}

/// A layer type in the protocol registry.
#[derive(Clone, Debug)]
pub struct LayerSchema {
    pub kind: &'static str,
    /// Encapsulation ordering rank (eth=10, arp/ipv4=20, icmp/udp/tcp=30,
    /// dns=40).
    pub rank: u16,
    /// Kinds this layer may stack on (empty = valid stack start).
    pub parents: &'static [&'static str],
    /// Layer-level documentation (mirrors the crate/module rustdoc);
    /// rendered by `wrex fields` and the man-page generator.
    pub doc: &'static str,
    pub fields: &'static [FieldSchema],
    /// Repeated record sections (tranche 3; empty for every tranche-1
    /// codec). A layer may carry a variable number of records per
    /// section (`dns` questions/answers); record fields surface in
    /// dissected layers under `<record>.<index>.<field>` paths.
    pub records: &'static [RecordSchema],
}

/// One repeated record section of a layer.
///
/// Paths are `<record>.<index>.<field>` with **exact** indices
/// (`dns.an.0.type`); wildcards are a deliberate deferral.
///
/// - Dissect-only sections (`settable: false`) never generate craft
///   flags (the tranche-3 `dns` an/ns/ar sections).
/// - A settable section bounded by `max: Some(1)` gets an unindexed
///   flag shorthand (`--dns-name` → `qd.0.name`); future tranches may
///   lift the bound with indexed flags.
#[derive(Clone, Debug)]
pub struct RecordSchema {
    /// Section prefix in paths (`"qd"`, `"an"`, …).
    pub name: &'static str,
    /// Fields of ONE record instance.
    pub fields: &'static [FieldSchema],
    /// Craft may set instances (dissect-only otherwise).
    pub settable: bool,
    /// Craft bound (`Some(1)` → flag shorthand; `None` = dissect-only).
    pub max: Option<usize>,
    pub doc: &'static str,
}

impl RecordSchema {
    /// Whole record fields only.
    pub const fn field(&self, name: &str) -> Option<&'static FieldSchema> {
        let mut i = 0;
        while i < self.fields.len() {
            if crate::str_eq(self.fields[i].name, name) {
                return Some(&self.fields[i]);
            }
            i += 1;
        }
        None
    }
}

/// Const proof helper (the schema invariant): a field table carries no
/// duplicate names. Every codec's `FIELDS`/record table asserts this at
/// compile time via `const _` — wrong tables fail the build, not first use.
pub const fn field_names_unique(fields: &[FieldSchema]) -> bool {
    let mut i = 0;
    while i < fields.len() {
        let mut j = i + 1;
        while j < fields.len() {
            if crate::str_eq(fields[i].name, fields[j].name) {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}

/// Fixed wire layout of one field (tranche 11b): byte offset + length
/// within the layer header, or a bit window for bit-packed subfields.
///
/// Declared per codec as a static table through [`crate::codec::Codec::layouts`]
/// (a default trait method so test mocks and dynamic-layout codecs — dns,
/// dhcp until their tranche-11b slice — inherit empty). The dissect engine
/// populates [`crate::dissect::LayerView::field_spans`] from these;
/// fields absent from the table (dynamic regions: ipv4/tcp `options`,
/// record sections) resolve to [`crate::dissect::FieldSpan::None`] — the
/// **total-presence invariant**: every dissected field key gets a span
/// entry, and the *variant* carries the policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// `len` bytes at byte offset `at` of the layer.
    Bytes { at: usize, len: usize },
    /// `width` bits at bit offset `shift` (MSB-first) within the
    /// big-endian byte window starting at `at`. The container is
    /// `ceil((shift + width) / 8)` bytes.
    Bits { at: usize, shift: u8, width: u8 },
    /// The value re-encodes at this range (the schema-side mirror of
    /// [`crate::dissect::FieldSpan::ReEncode`]): the codec's
    /// [`crate::codec::Codec::reencode`] hook (tranche 13a) serializes
    /// the edit value into the region replacement — dhcp sname/file
    /// (value + NUL + zero-padding re-encoded at the span).
    ReEncode { at: usize, len: usize },
}

impl Layout {
    /// Container byte length of the layout's byte window.
    pub const fn container_len(&self) -> usize {
        match *self {
            Layout::Bytes { len, .. } | Layout::ReEncode { len, .. } => len,
            Layout::Bits { shift, width, .. } => {
                let len = (shift as usize + width as usize).div_ceil(8);
                // (const: `Ord::max` is trait dispatch — spelled out.)
                if len > 1 { len } else { 1 }
            }
        }
    }
}

/// One derived-field recomputation the wire→wire consistency walk can
/// perform (tranche 11b): the declarative mirror of the encode-side
/// deferred [`crate::encode::Patch`] resolution, addressed by field and
/// driven by edit invalidation under a caller-selected
/// [`crate::patch::Scope`] instead of autofill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Derived {
    /// `u16 at` = frame end − [`LengthBase`]: `ipv4.total_len` and
    /// `udp.length` count from the layer START (the field includes the
    /// header it lives in); `ipv6.payload_len` counts from the header
    /// END (payload only). The tranche-14 corpus sweep caught the
    /// start-only formula writing 52 for a 12-byte v6 payload — the
    /// encode side was always correct (`Patch::Length { base }`).
    Length {
        field: &'static str,
        at: usize,
        base: LengthBase,
        /// Quantization of the covered length (tranche 17a): the v6
        /// extension-header `len` fields count in 4- or 8-octet units
        /// with a bias (see [`LengthUnits`]). `Bytes` is every
        /// pre-17a field.
        units: LengthUnits,
    },
    /// Internet checksum at `u16 at`, accumulated over the covered
    /// range plus the pseudo-header when `pseudo` selects one.
    Checksum {
        field: &'static str,
        at: usize,
        /// Range **start**: at the layer's own start (`Layer`, e.g.
        /// the ipv4 header checksum) or at the upper-layer packet
        /// (`UpperPacket`, tranche 17a: the RFC 8200 §8.1 L4
        /// checksums cover the v6 extension headers before the L4
        /// layer — `Layer == UpperPacket` on every ext-free stack, so
        /// the udp/tcp/icmpv6 switch is behavior-identical today).
        start: ChecksumStart,
        /// Range end: to the frame end (`Frame`) or to the layer's span
        /// end (`Layer`, e.g. the ipv4 header including options).
        end: ChecksumEnd,
        /// Pseudo-header provenance: none (ipv4 header checksum), or
        /// from the dissected net facts (udp/tcp/icmpv6 — family
        /// follows the network-layer parent).
        pseudo: PseudoSource,
    },
}

impl Derived {
    /// The field name this derivation owns (`"checksum"`, `"length"`).
    pub const fn field(&self) -> &'static str {
        match *self {
            Derived::Length { field, .. } => field,
            Derived::Checksum { field, .. } => field,
        }
    }
}

/// Covered-range end of a [`Derived::Checksum`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumEnd {
    /// To the end of the frame (payload included: icmp, udp, tcp).
    Frame,
    /// To the end of this layer's span (ipv4 header incl. options).
    Layer,
}

/// Where a [`Derived::Length`] counts from (tranche-14 fix: the v6
/// payload length excludes the 40-byte header).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LengthBase {
    /// frame end − layer start: the field counts the header it lives
    /// in (`ipv4.total_len`, `udp.length`).
    LayerStart,
    /// frame end − layer end: payload only (`ipv6.payload_len`).
    LayerEnd,
    /// layer end − layer start: the field counts **its own header**
    /// (tranche 17a — the ext `len` fields: hopopts/dstopts/routing
    /// `hdr_ext_len` covers `(len+1)*8` bytes of layer, AH's
    /// `payload_len` covers `(len+2)*4`; frame-end arithmetic cannot
    /// express it, the dstopts-twice corpus normalize proved it).
    Span,
}

/// Quantization of a [`Derived::Length`] (tranche 17a): the IPv6
/// extension-header `len` fields count in fixed octet units with a
/// bias — `hdr_ext_len = (octets / 8) − 1` (hop-by-hop, destination
/// options, routing) and AH's `payload_len = (octets / 4) − 2`
/// (RFC 4302 §2.2). The variants also fix the field's write width:
/// `Bytes` is the pre-17a u16 (2-byte BE write), the quantized
/// forms are the u8 `len` fields (1-byte write).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LengthUnits {
    /// Plain byte count, written as u16 (`ipv4.total_len`,
    /// `udp.length`, `ipv6.payload_len`).
    Bytes,
    /// `(octets / 4) − 2`, written as u8 — the AH length field.
    Octlets4,
    /// `(octets / 8) − 1`, written as u8 — hopopts/dstopts/routing
    /// `hdr_ext_len`.
    Octlets8,
}

impl LengthUnits {
    /// The octet quantum this field counts in (`Bytes` = plain).
    pub const fn unit(self) -> usize {
        match self {
            LengthUnits::Bytes => 1,
            LengthUnits::Octlets4 => 4,
            LengthUnits::Octlets8 => 8,
        }
    }

    /// The cell bias: the wire value is `(octets / unit) − bias`
    /// (hdr_ext_len counts 8-octet units *minus the first*; AH's
    /// payload_len counts 4-octet units *minus the fixed two*).
    pub const fn bias(self) -> usize {
        match self {
            LengthUnits::Bytes => 0,
            LengthUnits::Octlets4 => 2,
            LengthUnits::Octlets8 => 1,
        }
    }

    /// Quantize a covered byte length into the field's u8 value.
    /// `None` = off-grid (the length is not a multiple of the unit —
    /// the pointed [`crate::patch::PatchError::LengthNotQuantized`],
    /// never a silent truncation) or a plain `Bytes` field (not
    /// quantized; the caller writes the u16 path). A below-bias cell
    /// count saturates to 0 (the RFC minimum), an above-u8 count
    /// truncates — both analyzer-visible, matching the pre-17a
    /// `val as u16` truncation behavior of the `Bytes` arm.
    pub const fn quantize(self, covered: usize) -> Option<u8> {
        let (unit, bias) = (self.unit(), self.bias());
        if unit == 1 || !covered.is_multiple_of(unit) {
            return None;
        }
        let cells = (covered / unit).saturating_sub(bias);
        // (const: `Ord::min` is trait dispatch — spelled out.)
        let cells = if cells > u8::MAX as usize {
            u8::MAX as usize
        } else {
            cells
        };
        Some(cells as u8)
    }
}

/// Kani proofs (tranche 17a): the quantized-length fold — the ext
/// `len` fields' `(octets / unit) − bias` arithmetic. Scoped tight
/// (a single symbolic covered length, no loops — the T4
/// chunked-decoder/checksum pattern; measured against the 6 GB
/// ceiling in the kani job, retire per the dns-proof precedent if
/// the solver state ever grows past it).
#[cfg(kani)]
mod kani_proofs {
    use super::LengthUnits;

    /// Panic-freedom + the grid roundtrip: for ANY covered length the
    /// fold never panics; for every on-grid, u8-representable length
    /// the quantized value folds back to exactly the input
    /// (`(v + bias) * unit == covered` — hdr_ext_len/AH semantics),
    /// and every off-grid length is the pointed `None`.
    #[kani::proof]
    fn quantized_length_fold_roundtrip() {
        let covered = kani::any::<u32>() as usize;
        for units in [LengthUnits::Octlets8, LengthUnits::Octlets4] {
            let (unit, bias) = (units.unit(), units.bias());
            let v = units.quantize(covered);
            if covered % unit == 0 {
                let cells = covered / unit;
                if (bias..=u8::MAX as usize + bias).contains(&cells) {
                    // On-grid and representable: the exact roundtrip.
                    let v = v.expect("on-grid, representable lengths quantize");
                    assert_eq!((v as usize + bias) * unit, covered);
                } else {
                    // Saturating/truncating extremes: still Some, never
                    // a panic (analyzer-visible, the documented policy).
                    assert!(v.is_some());
                }
            } else {
                // Off-grid: no consistent value exists — the pointed
                // error at the call site, never a silent truncation.
                assert!(v.is_none());
            }
        }
    }
}

/// Range start of a [`Derived::Checksum`] (tranche 17a).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumStart {
    /// The layer's own span start (ipv4 header checksum: covers only
    /// itself).
    Layer,
    /// The upper-layer packet start — the offset the net-layer codec
    /// recorded in [`crate::dissect::Facts::upper_start`] (falls back
    /// to the layer's own start when no net parent recorded it).
    /// udp/tcp/icmpv6: RFC 8200 §8.1 counts the v6 extension headers
    /// into the L4 checksum, so an edit in a hopopts region must heal
    /// the udp checksum over the ext bytes too.
    UpperPacket,
}

/// Pseudo-header provenance of a [`Derived::Checksum`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PseudoSource {
    /// No pseudo-header (the ipv4 header checksum covers only itself).
    None,
    /// From the dissected net facts — family follows the network-layer
    /// parent (udp/tcp over v4 or v6, icmpv6 always v6).
    FromFacts,
}

/// A dotted-path lookup against a [`LayerSchema`].
///
/// `Field` is a whole-field reference; `FlagBit` is a per-bit subpath of a
/// [`FieldKind::FlagSet`] aggregate (`tcp.flags.syn`), where `bit` follows the
/// same MSB-first convention as [`FieldSchema::bit_names`];
/// `RecordField` is an indexed record field (`dns.an.0.type`).
#[derive(Clone, Copy, Debug)]
pub enum ResolvedField {
    Field(&'static FieldSchema),
    FlagBit {
        parent: &'static FieldSchema,
        bit: u8,
    },
    RecordField {
        record: &'static RecordSchema,
        index: usize,
        field: &'static FieldSchema,
    },
}

impl LayerSchema {
    /// Whole fields only (no dotted subpaths). (const: index loop —
    /// `iter().find(closure)` is not const-callable.)
    pub const fn field(&self, name: &str) -> Option<&'static FieldSchema> {
        // `self.fields` is `&'static [FieldSchema]`, so iterated items are
        // `'static` — no lifetime gymnastics needed.
        let mut i = 0;
        while i < self.fields.len() {
            if crate::str_eq(self.fields[i].name, name) {
                return Some(&self.fields[i]);
            }
            i += 1;
        }
        None
    }

    /// A record section by name.
    pub const fn record(&self, name: &str) -> Option<&'static RecordSchema> {
        let mut i = 0;
        while i < self.records.len() {
            if crate::str_eq(self.records[i].name, name) {
                return Some(&self.records[i]);
            }
            i += 1;
        }
        None
    }

    /// Resolve `name`, a dotted flag subpath (`flags.syn`) or an
    /// indexed record field (`an.0.type`).
    ///
    /// Flat fields shadow record sections of the same name.
    pub fn resolve(&self, path: &str) -> Option<ResolvedField> {
        if let Some(f) = self.field(path) {
            return Some(ResolvedField::Field(f));
        }
        let (head, tail) = path.split_once('.')?;
        if let Some(record) = self.record(head) {
            let (index_raw, field_raw) = tail.split_once('.')?;
            let index: usize = index_raw.parse().ok()?;
            let field = record.field(field_raw)?;
            return Some(ResolvedField::RecordField {
                record,
                index,
                field,
            });
        }
        let parent = self.field(head)?;
        if parent.kind != FieldKind::FlagSet {
            return None;
        }
        let bit = parent.bit_pos(tail)?;
        Some(ResolvedField::FlagBit { parent, bit })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(kind: FieldKind) -> FieldSchema {
        FieldSchema {
            name: "f",
            kind,
            bit_names: &[],
            default: Value::zero_for(kind),
            required: false,
            doc: "",
        }
    }

    #[test]
    fn int_max_table() {
        assert_eq!(FieldKind::U8.int_max(), Some(255));
        assert_eq!(FieldKind::U16.int_max(), Some(65535));
        assert_eq!(FieldKind::U32.int_max(), Some(u32::MAX as u128));
        assert_eq!(FieldKind::U64.int_max(), Some(u64::MAX as u128));
        assert_eq!(FieldKind::U128.int_max(), Some(u128::MAX));
        assert_eq!(FieldKind::Ipv4.int_max(), None);
        assert_eq!(FieldKind::Ipv6.int_max(), None);
        assert_eq!(FieldKind::FlagSet.int_max(), None);
    }

    #[test]
    fn flag_bit_pos_msb_first() {
        let mut fs = f(FieldKind::FlagSet);
        fs.name = "flags";
        fs.bit_names = &["cwr", "ece", "urg", "ack", "psh", "rst", "syn", "fin"];
        assert_eq!(fs.bit_pos("cwr"), Some(7));
        assert_eq!(fs.bit_pos("syn"), Some(1));
        assert_eq!(fs.bit_pos("fin"), Some(0));
        assert_eq!(fs.bit_pos("nope"), None);

        let mut fs2 = f(FieldKind::FlagSet);
        fs2.name = "flags";
        fs2.bit_names = &["df", "mf"];
        assert_eq!(fs2.bit_pos("df"), Some(1));
        assert_eq!(fs2.bit_pos("mf"), Some(0));
    }

    static AN_FIELDS: &[FieldSchema] = &[FieldSchema {
        name: "type",
        kind: FieldKind::Str,
        bit_names: &[],
        default: Value::Str(std::borrow::Cow::Borrowed("")),
        required: false,
        doc: "",
    }];
    static AN_RECORDS: &[RecordSchema] = &[RecordSchema {
        name: "an",
        fields: AN_FIELDS,
        settable: false,
        max: None,
        doc: "",
    }];

    #[test]
    fn resolve_paths() {
        let schema = LayerSchema {
            kind: "tcp",
            rank: 30,
            parents: &["ipv4"],
            doc: "test stand-in",
            fields: &[FieldSchema {
                name: "flags",
                kind: FieldKind::FlagSet,
                bit_names: &["cwr", "ece", "urg", "ack", "psh", "rst", "syn", "fin"],
                default: Value::Int(0),
                required: false,
                doc: "",
            }],
            records: AN_RECORDS,
        };
        assert!(matches!(
            schema.resolve("flags"),
            Some(ResolvedField::Field(_))
        ));
        match schema.resolve("flags.syn") {
            Some(ResolvedField::FlagBit { bit, .. }) => assert_eq!(bit, 1),
            other => panic!("unexpected: {other:?}"),
        }
        match schema.resolve("an.0.type") {
            Some(ResolvedField::RecordField {
                record,
                index,
                field,
            }) => {
                assert_eq!(record.name, "an");
                assert_eq!(index, 0);
                assert_eq!(field.name, "type");
            }
            other => panic!("unexpected: {other:?}"),
        }
        // exact indices only: wildcards and non-numeric indices reject
        assert!(schema.resolve("an.*.type").is_none());
        assert!(schema.resolve("an.x.type").is_none());
        assert!(schema.resolve("an.0").is_none());
        assert!(schema.resolve("an.0.nope").is_none());
        assert!(schema.resolve("nope").is_none());
        assert!(schema.resolve("flags.nope").is_none());
    }

    #[test]
    fn kind_names() {
        assert_eq!(FieldKind::U8.type_name(), "u8");
        assert_eq!(FieldKind::FlagSet.type_name(), "flagset");
        let _ = f(FieldKind::U8);
    }
}
