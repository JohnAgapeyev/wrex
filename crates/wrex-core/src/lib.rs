#![forbid(unsafe_code)]
//! wrex-core: field/value model, schema, codec traits, encode/dissect
//! engines, checksums, filters.

pub mod checksum;
pub mod codec;
pub mod dissect;
pub mod encode;
pub mod error;
pub mod filter;
pub mod render;
pub mod schema;
pub mod spec;
pub mod time;
pub mod value;

pub use checksum::{ChecksumAccumulator, PseudoHeader, internet_checksum};
pub use codec::{Codec, Next, ReadOutcome, Registry};
pub use dissect::{
    Anomaly, DecodeCtx, DissectedPacket, Facts, LayerView, NetFacts, auto_start, dissect,
};
pub use encode::{EncodeCtx, EncodeOpts, Encoded, Patch, Violation, encode};
pub use error::{DecodeError, EncodeError, FilterError, SpecError};
pub use filter::{Filter, Op as FilterOp};
pub use schema::{FieldKind, FieldSchema, LayerSchema, RecordSchema, ResolvedField};
pub use spec::{LayerSpec, PacketSpec};
pub use time::parse_duration;
pub use value::{Value, mac_string, parse_bool, parse_value, stdin_bytes};

#[cfg(test)]
mod smoke {
    #[test]
    fn core_scaffold() {
        assert!(env!("CARGO_PKG_NAME") == "wrex-core");
    }
}
