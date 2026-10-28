#![forbid(unsafe_code)]
//! wrex-core: field/value model, schema, codec traits, encode/dissect
//! engines, checksums, filters.

pub mod checksum;
pub mod codec;
pub mod dissect;
pub mod encode;
pub mod error;
pub mod filter;
pub mod options;
pub mod patch;
pub mod render;
pub mod schema;
pub mod spec;
pub mod time;
pub mod value;

pub use checksum::{ChecksumAccumulator, PseudoHeader, internet_checksum};
pub use codec::{Codec, Next, ReadOutcome, Registry};
pub use dissect::{
    Anomaly, DecodeCtx, DissectedPacket, Facts, FieldSpan, LayerView, NetFacts, auto_start, dissect,
};
pub use encode::{EncodeCtx, EncodeOpts, Encoded, Patch, Violation, encode, serialize_field_value};
pub use error::{DecodeError, EncodeError, FilterError, SpecError};
pub use filter::{Filter, Op as FilterOp};
pub use patch::{Edit, PatchError, Scope, patch};
pub use schema::{
    ChecksumEnd, Derived, FieldKind, FieldSchema, LayerSchema, Layout, LengthBase, PseudoSource,
    RecordSchema, ResolvedField,
};
pub use spec::{LayerSpec, PacketSpec};
pub use time::parse_duration;
pub use value::{Value, mac_string, parse_bool, parse_value, stdin_bytes};

/// Const byte-wise string equality (`==` on `str` is `PartialEq`
/// trait dispatch — not const-callable; str *pattern* matching is not
/// const either). Lets the codec dispatch tables (`kind_to_proto`,
/// `kind_to_ethertype`, …) run in const contexts.
pub const fn str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod smoke {
    #[test]
    fn core_scaffold() {
        assert!(env!("CARGO_PKG_NAME") == "wrex-core");
    }
}
