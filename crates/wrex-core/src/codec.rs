//! Codec contract and the compile-time protocol registry.

use std::ops::Range;

use crate::dissect::{DecodeCtx, LayerView};
use crate::encode::EncodeCtx;
use crate::error::{DecodeError, EncodeError};
use crate::schema::{Derived, LayerSchema, Layout};
use crate::spec::LayerSpec;

/// Dissection chain continuation returned by [`Codec::read`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next {
    /// Terminal payload; remaining bytes become `DissectedPacket::payload`.
    Payload,
    /// Continue the chain at this layer kind.
    Kind(&'static str),
}

/// Result of [`Codec::read`].
#[derive(Debug)]
pub enum ReadOutcome {
    /// A layer was parsed; `Option<Next>` continues the chain (`None` acts
    /// as [`Next::Payload`]).
    Layer(LayerView, Option<Next>),
    /// Structural failure (e.g. truncation): the engine records the anomaly,
    /// keeps the remaining bytes as a synthetic `unknown` layer, and stops.
    Anomaly(DecodeError, Next),
    /// Nothing to read (empty input region).
    Empty,
}

/// A protocol codec. Implemented once per protocol crate; registered into a
/// [`Registry`] at composition time.
pub trait Codec: Send + Sync {
    fn schema(&self) -> &'static LayerSchema;
    /// Header byte length for this spec (payload excluded). Fixed for
    /// header-only protocols; options-driven where applicable.
    fn header_len(&self, spec: &LayerSpec) -> Result<usize, EncodeError>;
    /// Append this layer's header to `ctx.buf`; record deferred fields
    /// (lengths/checksums) via [`EncodeCtx::defer`].
    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError>;
    /// Parse `bytes` (the packet from this layer onward) into a
    /// [`LayerView`] plus chain continuation; push non-fatal anomalies
    /// (checksum mismatches…) to `ctx.anomalies`. Never fatal: structural
    /// failures return [`ReadOutcome::Anomaly`].
    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome;

    /// Fixed wire layouts (tranche 11b): a static table of field name →
    /// [`Layout`] for fixed-header codecs. Empty (the default) for
    /// dynamic-layout codecs and test mocks; the dissect engine
    /// populates [`crate::dissect::LayerView::field_spans`] from these.
    /// Fields absent from the table resolve to
    /// [`crate::dissect::FieldSpan::None`] (total presence).
    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        &[]
    }

    /// Derived-field recomputation specs (tranche 11b): what the
    /// wire→wire consistency walk may recompute under a caller-selected
    /// [`crate::patch::Scope`]. Empty (the default) for codecs with no
    /// derived fields (eth, vlan, arp) and test mocks.
    fn derived(&self) -> &'static [Derived] {
        &[]
    }

    /// Serialize a [`crate::patch::Edit::SetField`] value into the
    /// replacement bytes of a [`crate::dissect::FieldSpan::ReEncode`]
    /// region (tranche 13a): the value *does not* splice verbatim —
    /// the codec owns the region's encoding (NUL padding, wire-name
    /// rules) and returns the full `region.len()`-byte replacement.
    ///
    /// `field` is the full field key within the layer (`"sname"`,
    /// `"an.0.name"`); `value` is the edit's raw bytes; `region` is
    /// the absolute frame range. The engine enforces the returned
    /// width. `None` (the default) = the field does not re-encode —
    /// the patch is a pointed [`crate::patch::PatchError::UnsupportedPath`]
    /// (mocks and dynamic codecs inherit); `Some(Err(reason))` is a
    /// pointed rejection (over-length value, malformed wire name, …).
    fn reencode(
        &self,
        field: &str,
        value: &[u8],
        region: Range<usize>,
    ) -> Option<Result<Vec<u8>, String>> {
        let _ = (field, value, region);
        None
    }
}

/// Compile-time protocol registry (no dynamic loading).
#[derive(Default)]
pub struct Registry {
    codecs: Vec<&'static dyn Codec>,
    kinds: Vec<&'static str>,
}

impl Registry {
    pub fn empty() -> Self {
        Self {
            codecs: Vec::new(),
            kinds: Vec::new(),
        }
    }

    /// Register a codec. Later registrations win on kind collisions
    /// (last one is returned by [`Registry::get`]).
    pub fn register(&mut self, codec: &'static dyn Codec) {
        self.kinds.push(codec.schema().kind);
        self.codecs.push(codec);
    }

    pub fn get(&self, kind: &str) -> Option<&'static dyn Codec> {
        self.codecs
            .iter()
            .copied()
            .rev()
            .find(|c| c.schema().kind == kind)
    }

    pub fn kinds(&self) -> &[&'static str] {
        &self.kinds
    }

    pub fn schema(&self, kind: &str) -> Option<&'static LayerSchema> {
        self.get(kind).map(|c| c.schema())
    }
}

impl core::fmt::Debug for Registry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_set().entries(self.kinds.iter().copied()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{FieldKind, FieldSchema, LayerSchema};
    use crate::value::Value;

    /// Minimal fixed-schema codec for registry semantics.
    struct Mock {
        schema: &'static LayerSchema,
    }
    impl Mock {
        fn new(kind: &'static str) -> &'static Self {
            let fields: Vec<FieldSchema> = vec![FieldSchema {
                name: "x",
                kind: FieldKind::U8,
                bit_names: &[],
                default: Value::Int(0),
                required: false,
                doc: "",
            }];
            let schema = LayerSchema {
                kind,
                rank: 1,
                parents: &[],
                doc: "",
                fields: Box::leak(fields.into_boxed_slice()),
                records: &[],
            };
            let this = Self {
                schema: Box::leak(Box::new(schema)),
            };
            Box::leak(Box::new(this))
        }
    }
    impl Codec for Mock {
        fn schema(&self) -> &'static LayerSchema {
            self.schema
        }
        fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
            Ok(0)
        }
        fn write(&self, _spec: &LayerSpec, _ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
            Ok(())
        }
        fn read<'a>(&self, _bytes: &'a [u8], _ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
            ReadOutcome::Empty
        }
    }

    #[test]
    fn registry_register_get_and_collision() {
        let mut r = Registry::empty();
        assert!(r.get("a").is_none());
        assert!(r.kinds().is_empty());
        r.register(Mock::new("a"));
        r.register(Mock::new("b"));
        assert_eq!(r.kinds(), ["a", "b"]);
        assert_eq!(r.get("a").unwrap().schema().kind, "a");
        assert_eq!(r.get("b").unwrap().schema().kind, "b");
        assert_eq!(r.schema("b").map(|s| s.kind), Some("b"));
        // Last registration wins on kind collisions.
        r.register(Mock::new("a"));
        assert_eq!(r.kinds(), ["a", "b", "a"]);
        assert_eq!(
            r.get("a").map(|c| c.schema().rank),
            Some(1),
            "get must resolve the LAST `a`"
        );
        // Case-sensitive kinds; unknown misses.
        assert!(r.get("A").is_none());
        assert!(r.get("nope").is_none());
    }

    #[test]
    fn registry_debug_lists_kinds() {
        let mut r = Registry::empty();
        r.register(Mock::new("eth"));
        r.register(Mock::new("ipv4"));
        assert_eq!(format!("{r:?}"), r#"{"eth", "ipv4"}"#);
    }
}
