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
    Mac,
    Bytes,
    FlagSet,
    Str,
    ByteList,
}

impl FieldKind {
    /// Inclusive upper bound for integer field kinds; `None` otherwise.
    pub fn int_max(self) -> Option<u128> {
        match self {
            FieldKind::U8 => Some(u8::MAX as u128),
            FieldKind::U16 => Some(u16::MAX as u128),
            FieldKind::U32 => Some(u32::MAX as u128),
            FieldKind::U64 => Some(u64::MAX as u128),
            FieldKind::U128 => Some(u128::MAX),
            _ => None,
        }
    }

    pub fn type_name(self) -> &'static str {
        match self {
            FieldKind::U8 => "u8",
            FieldKind::U16 => "u16",
            FieldKind::U32 => "u32",
            FieldKind::U64 => "u64",
            FieldKind::U128 => "u128",
            FieldKind::Ipv4 => "ipv4",
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
    /// Encapsulation ordering rank (eth=10, arp/ipv4=20, icmp/udp/tcp=30).
    pub rank: u16,
    /// Kinds this layer may stack on (empty = valid stack start).
    pub parents: &'static [&'static str],
    /// Layer-level documentation (mirrors the crate/module rustdoc);
    /// rendered by `wrex fields` and the man-page generator.
    pub doc: &'static str,
    pub fields: &'static [FieldSchema],
}

/// A dotted-path lookup against a [`LayerSchema`].
///
/// `Field` is a whole-field reference; `FlagBit` is a per-bit subpath of a
/// [`FieldKind::FlagSet`] aggregate (`tcp.flags.syn`), where `bit` follows the
/// same MSB-first convention as [`FieldSchema::bit_names`].
#[derive(Clone, Copy, Debug)]
pub enum ResolvedField {
    Field(&'static FieldSchema),
    FlagBit {
        parent: &'static FieldSchema,
        bit: u8,
    },
}

impl LayerSchema {
    /// Whole fields only (no dotted subpaths).
    pub fn field(&self, name: &str) -> Option<&'static FieldSchema> {
        // `self.fields` is `&'static [FieldSchema]`, so iterated items are
        // `'static` — no lifetime gymnastics needed.
        self.fields.iter().find(|f| f.name == name)
    }

    /// Resolve `name` or a dotted flag subpath (`flags.syn`).
    pub fn resolve(&self, path: &str) -> Option<ResolvedField> {
        if let Some(f) = self.field(path) {
            return Some(ResolvedField::Field(f));
        }
        let (head, tail) = path.split_once('.')?;
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
        };
        assert!(matches!(
            schema.resolve("flags"),
            Some(ResolvedField::Field(_))
        ));
        match schema.resolve("flags.syn") {
            Some(ResolvedField::FlagBit { bit, .. }) => assert_eq!(bit, 1),
            other => panic!("unexpected: {other:?}"),
        }
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
