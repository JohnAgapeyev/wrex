//! Codec contract and the compile-time protocol registry.

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
