//! The span-patch engine (tranche 11b): buffer + edits + caller-selected
//! consistency, on the retained [`crate::dissect::DissectedPacket::frame`].
//!
//! The model (settled at the T11 planning pass): an **ordered edit list**
//! applies byte-level changes against the frame by splice (zero copy
//! outside edited regions); a **consistency scope** — an explicit,
//! caller-selected set of derived fields, with layer-wise shorthand —
//! decides which derived fields (checksums, lengths) get recomputed
//! afterwards. Edits decide bytes; scope decides recomputation; the
//! two never fight (an edit inside scope is a pointed error).
//!
//! The engine never *heals* silently: derived fields outside the scope
//! are copied verbatim, wrongness included. `normalize`-style full spec
//! re-encode stays a verb intent at the caller, never a patch-engine
//! policy.
//!
//! Determinism: representability, edit ordering, and the recomputation
//! walk are pure functions of the frame + edit set — same inputs, same
//! bytes out.

use std::ops::Range;

use bytes::{Bytes, BytesMut};

use crate::checksum::ChecksumAccumulator;
use crate::codec::Registry;
use crate::dissect::{DissectedPacket, FieldSpan};
use crate::schema::{ChecksumEnd, Derived, PseudoSource};

/// One byte-level edit against a dissected frame, in **pre-edit frame
/// coordinates**.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Edit {
    /// Overwrite a dissected field path (`"tcp.seq"`, `"vlan.vid"`,
    /// `"ipv4.flags.df"`) with big-endian field bytes. The span must
    /// exist (`FieldSpan::None` → a pointed error; a `ReEncode` span
    /// routes through the codec's [`crate::codec::Codec::reencode`]
    /// hook, tranche 13a) and the width must match (`Bytes`: exactly;
    /// `Bits`: `ceil(width/8)` bytes, masked into the container).
    SetField { path: String, bytes: Bytes },
    /// Insert bytes at an absolute frame offset (shape change).
    Insert { at: usize, bytes: Bytes },
    /// Delete an absolute byte range (shape change).
    Delete { at: Range<usize> },
}

/// The caller-selected consistency scope (tranche 11b): which derived
/// fields the wire→wire walk recomputes after the edits. **Selection is
/// explicit** — the engine never infers it: the DAG's derived specs are
/// the candidates, the scope is the decision.
///
/// - [`Scope::all`] — every derived field (the default; the eBPF-style
///   translation/NAT archetype: minimal edits, whole message consistent).
/// - [`Scope::none`] — no recomputation (craft-invalidity: deliberate
///   transport-header garbage).
/// - Selective — outer-only (`ipv4:*`, `udp:*`), inner-only, or any
///   per-field pick (`"udp.checksum"`), via [`Scope::select`].
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Scope {
    selections: Vec<ScopeSel>,
    all: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ScopeSel {
    /// Whole-layer shorthand (`"udp.*"`): every derived field of the
    /// kind. Any kind string is accepted; a selection that matches no
    /// derived field simply selects nothing.
    Layer(String),
    /// One derived-field path (`"udp.checksum"`).
    Field(String),
}

impl Scope {
    /// Recompute every derived field (the default archetype).
    pub const fn all() -> Scope {
        Scope {
            selections: Vec::new(),
            all: true,
        }
    }

    /// No recomputation at all — every derived field stays verbatim,
    /// wrong or not. (const: spelled out — `Default::default` is not
    /// const-callable.)
    pub const fn none() -> Scope {
        Scope {
            selections: Vec::new(),
            all: false,
        }
    }

    /// Build a selective scope from path selectors: `"udp.*"` selects the
    /// whole layer's derived set, `"udp.checksum"` one field. An empty
    /// list = [`Scope::none`]. Kind names are not validated here (a
    /// selection matching no derived field selects nothing) — malformed
    /// paths are.
    pub fn select(paths: &[&str]) -> Result<Scope, PatchError> {
        let mut selections = Vec::new();
        for p in paths {
            let (kind, field) = p
                .split_once('.')
                .ok_or_else(|| PatchError::BadScope(p.to_string()))?;
            if field == "*" || field == "all" {
                selections.push(ScopeSel::Layer(kind.to_string()));
            } else {
                selections.push(ScopeSel::Field(p.to_string()));
            }
        }
        Ok(Scope {
            selections,
            all: false,
        })
    }

    /// Does this scope select the derived field at `path`
    /// (`"<kind>.<field>"`)?
    fn selects(&self, path: &str) -> bool {
        if self.all {
            return true;
        }
        let Some((kind, _)) = path.split_once('.') else {
            return false;
        };
        self.selections.iter().any(|s| match s {
            ScopeSel::Layer(k) => k == kind,
            ScopeSel::Field(f) => f == path,
        })
    }

    /// Does this scope select the derived field at `path`
    /// (`"<kind>.<field>"`)? Public mirror for callers that pre-check
    /// the edit/scope conflict statically (tranche 14: the `wrex
    /// patch` verb validates the whole edit grammar before any frame
    /// is read).
    pub fn selects_path(&self, path: &str) -> bool {
        self.selects(path)
    }
}

/// A patch-engine failure. Every one is pointed; the engine never
/// partially applies an edit set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatchError {
    /// `SetField` path resolved to no layer/field.
    UnresolvedPath(String),
    /// `SetField` path has no patchable span (`FieldSpan::None` —
    /// dynamic regions) or the codec provides no `reencode` hook for
    /// its `ReEncode` region. Fall back to spec re-encode at the
    /// caller if the edit must land.
    UnsupportedPath(String),
    /// The codec's [`crate::codec::Codec::reencode`] hook refused the
    /// value (over-length, embedded NUL, malformed wire name, …) —
    /// pointed, never a silent wrong-width splice.
    ReEncodeFailed { path: String, reason: String },
    /// `SetField` bytes do not match the field's wire width.
    WidthMismatch {
        path: String,
        want: usize,
        got: usize,
    },
    /// `SetField` span lies outside the frame (truncated layer).
    OutOfBounds { path: String },
    /// Two edits claim overlapping bytes (or two inserts collide at one
    /// offset) — ambiguity is never resolved by chance.
    Overlap,
    /// An edit touches a field the scope also selects for recomputation:
    /// edits decide bytes, scope decides recomputation — the conflict is
    /// pointed, never last-write-wins.
    EditScopeConflict(String),
    /// A scope selector is malformed or names an unknown layer.
    BadScope(String),
    /// A quantized derived length (ext-header `len`, tranche 17a)
    /// cannot be recomputed: the covered length is not a multiple of
    /// its unit — an insert/delete broke the 8- or 4-octet grid. Pad
    /// to the grid at the caller; the engine never writes a value
    /// that would not re-derive.
    LengthNotQuantized {
        path: String,
        unit: u8,
        remainder: usize,
    },
}

impl std::fmt::Display for PatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PatchError::UnresolvedPath(p) => write!(f, "no dissected field at path {p:?}"),
            PatchError::UnsupportedPath(p) => {
                write!(
                    f,
                    "field {p:?} has no patchable span (unsupported under span-patch)"
                )
            }
            PatchError::ReEncodeFailed { path, reason } => {
                write!(f, "re-encode of {path:?} refused: {reason}")
            }
            PatchError::WidthMismatch { path, want, got } => {
                write!(f, "field {path:?} wants {want} bytes, got {got}")
            }
            PatchError::OutOfBounds { path } => {
                write!(f, "field {path:?} span lies outside the frame")
            }
            PatchError::LengthNotQuantized {
                path,
                unit,
                remainder,
            } => write!(
                f,
                "field {path:?} covers a length not divisible by {unit} \
                 (remainder {remainder}); pad to the grid to recompute"
            ),
            PatchError::Overlap => write!(f, "edits overlap"),
            PatchError::EditScopeConflict(p) => {
                write!(f, "edit touches {p:?}, which the scope also recomputes")
            }
            PatchError::BadScope(s) => write!(f, "bad scope selector {s:?}"),
        }
    }
}

impl std::error::Error for PatchError {}

/// A resolved byte-level operation in pre-edit coordinates.
#[derive(Clone, Debug)]
enum Op {
    Overwrite {
        span: Range<usize>,
        bytes: Bytes,
    },
    /// Masked bit-window write into a container (Bits fields).
    WriteBits {
        container: Range<usize>,
        shift: u8,
        width: u8,
        value: u128,
    },
    Insert {
        at: usize,
        bytes: Bytes,
    },
    Delete {
        span: Range<usize>,
    },
}

/// Apply `edits` against `packet`'s retained frame, then recompute the
/// derived fields the `scope` selects (the wire→wire consistency walk:
/// the declarative mirror of the encode-side deferred-`Patch`
/// resolution, driven by edit invalidation instead of autofill).
///
/// Never partial: representability and overlap are checked for the
/// **whole set** before anything applies — the set lands complete, or
/// errors, or the caller falls back to spec re-encode.
pub fn patch(
    registry: &Registry,
    packet: &DissectedPacket,
    edits: &[Edit],
    scope: &Scope,
) -> Result<Bytes, PatchError> {
    // --- pre-pass: resolve + validate every edit, old coordinates -----
    let mut ops: Vec<Op> = Vec::with_capacity(edits.len());
    for edit in edits {
        match edit {
            Edit::SetField { path, bytes } => {
                let (kind, field) = path
                    .split_once('.')
                    .ok_or_else(|| PatchError::UnresolvedPath(path.to_string()))?;
                let span = resolve_span(packet, path)?;
                // Edits decide bytes; scope decides recomputation. The
                // conflict is narrow and pointed: an edit on a field
                // that is a *derived target* of its codec AND selected
                // by the scope. Non-derived fields never conflict.
                if let Some(codec) = registry.get(kind)
                    && codec.derived().iter().any(|d| d.field() == field)
                    && scope.selects(path)
                {
                    return Err(PatchError::EditScopeConflict(path.clone()));
                }
                match span {
                    FieldSpan::Bytes(r) => {
                        if bytes.len() != r.len() {
                            return Err(PatchError::WidthMismatch {
                                path: path.clone(),
                                want: r.len(),
                                got: bytes.len(),
                            });
                        }
                        if r.end > packet.frame.len() {
                            return Err(PatchError::OutOfBounds { path: path.clone() });
                        }
                        ops.push(Op::Overwrite {
                            span: r,
                            bytes: bytes.clone(),
                        });
                    }
                    FieldSpan::Bits {
                        container,
                        shift,
                        width,
                    } => {
                        // value: ceil(width/8) big-endian bytes, masked
                        // into the container window.
                        let want = (width as usize).div_ceil(8);
                        if bytes.len() != want {
                            return Err(PatchError::WidthMismatch {
                                path: path.clone(),
                                want,
                                got: bytes.len(),
                            });
                        }
                        if container.end > packet.frame.len() {
                            return Err(PatchError::OutOfBounds { path: path.clone() });
                        }
                        let mut value: u128 = 0;
                        for b in &bytes[..] {
                            value = (value << 8) | *b as u128;
                        }
                        ops.push(Op::WriteBits {
                            container,
                            shift,
                            width,
                            value,
                        });
                    }
                    // Tranche 13a: a ReEncode span routes through the
                    // codec's `reencode` hook — the codec owns the
                    // region's encoding (NUL padding, wire-name rules)
                    // and returns the full region replacement.
                    FieldSpan::ReEncode(r) => {
                        let Some(codec) = registry.get(kind) else {
                            return Err(PatchError::UnsupportedPath(path.clone()));
                        };
                        match codec.reencode(field, bytes, r.clone()) {
                            None => {
                                return Err(PatchError::UnsupportedPath(path.clone()));
                            }
                            Some(Err(reason)) => {
                                return Err(PatchError::ReEncodeFailed {
                                    path: path.clone(),
                                    reason,
                                });
                            }
                            Some(Ok(region_bytes)) => {
                                if region_bytes.len() != r.len() {
                                    return Err(PatchError::ReEncodeFailed {
                                        path: path.clone(),
                                        reason: format!(
                                            "hook returned {} bytes for a {}-byte region",
                                            region_bytes.len(),
                                            r.len()
                                        ),
                                    });
                                }
                                if r.end > packet.frame.len() {
                                    return Err(PatchError::OutOfBounds { path: path.clone() });
                                }
                                ops.push(Op::Overwrite {
                                    span: r,
                                    bytes: region_bytes.into(),
                                });
                            }
                        }
                    }
                    FieldSpan::None => {
                        return Err(PatchError::UnsupportedPath(path.clone()));
                    }
                }
            }
            Edit::Insert { at, bytes } => {
                if *at > packet.frame.len() {
                    return Err(PatchError::OutOfBounds {
                        path: format!("insert@{at}"),
                    });
                }
                ops.push(Op::Insert {
                    at: *at,
                    bytes: bytes.clone(),
                });
            }
            Edit::Delete { at } => {
                if at.end > packet.frame.len() || at.start > at.end {
                    return Err(PatchError::OutOfBounds {
                        path: format!("delete@{:?}", at),
                    });
                }
                ops.push(Op::Delete { span: at.clone() });
            }
        }
    }
    // Order + non-overlap: edits must resolve to disjoint byte claims;
    // equal starts (two inserts, insert-over-overwrite) are ambiguous.
    ops.sort_by_key(|op| op.start());
    for w in ops.windows(2) {
        let (a, b) = (&w[0], &w[1]);
        if a.start() == b.start() || a.end() > b.start() {
            return Err(PatchError::Overlap);
        }
    }

    // --- splice: apply the edits ---------------------------------------
    let mut out = BytesMut::with_capacity(packet.frame.len());
    let mut cursor = 0usize;
    let frame = &packet.frame[..];
    for op in &ops {
        match op {
            Op::Overwrite { span, bytes } => {
                out.extend_from_slice(&frame[cursor..span.start]);
                out.extend_from_slice(bytes);
                cursor = span.end;
            }
            Op::WriteBits {
                container,
                shift,
                width,
                value,
            } => {
                out.extend_from_slice(&frame[cursor..container.start]);
                // Copy the container, masked-write the bit window, then
                // append — the only bytes touched are the window's.
                let mut unit = frame[container.start..container.end].to_vec();
                write_bits_window(&mut unit, *shift, *width, *value);
                out.extend_from_slice(&unit);
                cursor = container.end;
            }
            Op::Insert { at, bytes } => {
                out.extend_from_slice(&frame[cursor..*at]);
                out.extend_from_slice(bytes);
                cursor = *at;
            }
            Op::Delete { span } => {
                out.extend_from_slice(&frame[cursor..span.start]);
                cursor = span.end;
            }
        }
    }
    out.extend_from_slice(&frame[cursor..]);

    // --- wire→wire consistency walk: recompute scoped derived fields --
    let fresh = crate::dissect::dissect(registry, &out, packet.start);
    let mut frame = out;
    for layer in &fresh.layers {
        let Some(codec) = registry.get(layer.kind) else {
            continue;
        };
        for d in codec.derived() {
            let path = format!("{}.{}", layer.kind, d.field());
            if !scope.selects(&path) {
                continue;
            }
            recompute(&mut frame, layer, *d, &fresh)?;
        }
    }
    Ok(frame.freeze())
}

/// Resolve a field path (`"<kind>.<field>"`, first matching layer) to
/// its [`FieldSpan`] in the dissected packet.
fn resolve_span(packet: &DissectedPacket, path: &str) -> Result<FieldSpan, PatchError> {
    let (kind, field) = path
        .split_once('.')
        .ok_or_else(|| PatchError::UnresolvedPath(path.to_string()))?;
    for layer in &packet.layers {
        if layer.kind != kind {
            continue;
        }
        if let Some(span) = layer.field_spans.get(field) {
            return Ok(span.clone());
        }
        // first layer of the kind without the field: try the next one
        // (fields are per-layer conditional: icmp echo vs rest).
        return Err(PatchError::UnresolvedPath(path.to_string()));
    }
    Err(PatchError::UnresolvedPath(path.to_string()))
}

/// Recompute one derived field in place (new coordinates).
fn recompute(
    frame: &mut BytesMut,
    layer: &crate::dissect::LayerView,
    d: Derived,
    fresh: &DissectedPacket,
) -> Result<(), PatchError> {
    match d {
        Derived::Length {
            at, base, units, ..
        } => {
            // Tranche-14 fix: the base is per-field (ipv6 payload_len
            // counts from the header END — the corpus sweep caught the
            // old start-only formula writing 52 for a 12-byte v6 payload).
            // Tranche 17a: the ext-header `len` fields are quantized
            // (RFC 8200 §4.3.1 / RFC 4302 §2.2) — a non-multiple
            // covered length has no consistent value, which is a
            // pointed error, never a silent truncation.
            let covered = match base {
                crate::schema::LengthBase::LayerStart => frame.len() - layer.span.start,
                crate::schema::LengthBase::LayerEnd => frame.len() - layer.span.end,
                // The ext `len` fields count their own header
                // (tranche 17a): layer end − layer start.
                crate::schema::LengthBase::Span => layer.span.end - layer.span.start,
            };
            let pos = layer.span.start + at;
            let path = format!("{}.{}", layer.kind, d.field());
            match units {
                crate::schema::LengthUnits::Bytes => {
                    let val = covered as u16;
                    if pos + 2 > frame.len() {
                        return Err(PatchError::OutOfBounds { path });
                    }
                    frame[pos..pos + 2].copy_from_slice(&val.to_be_bytes());
                }
                crate::schema::LengthUnits::Octlets8 | crate::schema::LengthUnits::Octlets4 => {
                    match units.quantize(covered) {
                        None => {
                            return Err(PatchError::LengthNotQuantized {
                                path,
                                unit: units.unit() as u8,
                                remainder: covered % units.unit(),
                            });
                        }
                        Some(v) => {
                            if pos + 1 > frame.len() {
                                return Err(PatchError::OutOfBounds { path });
                            }
                            frame[pos] = v;
                        }
                    }
                }
            }
        }
        Derived::Checksum {
            at,
            start: start_sel,
            end,
            pseudo,
            ..
        } => {
            // UpperPacket == Layer since the HP3-b convention fix: the
            // L4 pseudo-header covers the L4 message ONLY — RFC 8200
            // §8.1 as every real stack implements it (the kernel's own
            // MLD frames disagree with the old ext-inclusive fold by a
            // constant; the foreign-capture corpus demanded the fix).
            // The arm stays for schema compatibility (pre-1.0 additive
            // vocabulary) and resolves to the same start as Layer.
            let start = match start_sel {
                crate::schema::ChecksumStart::Layer | crate::schema::ChecksumStart::UpperPacket => {
                    layer.span.start
                }
            };
            let stop = match end {
                ChecksumEnd::Frame => frame.len(),
                ChecksumEnd::Layer => layer.span.end,
            };
            let pos = layer.span.start + at;
            // The checksum field must live inside the covered range
            // (pos ≥ start AND pos+2 ≤ stop): the UpperPacket/Layer
            // collapse (HP3-b convention fix) means the guard can no
            // longer lean on upper_start sitting past the field — the
            // empty-covered-range mock caught the missing bound.
            if stop > frame.len()
                || pos + 2 > frame.len()
                || start >= stop
                || pos < start
                || pos + 2 > stop
            {
                return Err(PatchError::OutOfBounds {
                    path: format!("{}.{}", layer.kind, d.field()),
                });
            }
            // RFC 1071: the checksum's own bytes count as zero during
            // the fold (the encode-side placeholder rule, mirrored) —
            // fold the covered range *excluding* the checksum field.
            let mut acc = ChecksumAccumulator::new();
            acc.add_bytes(&frame[start..pos]);
            acc.add_bytes(&frame[pos + 2..stop]);
            if let PseudoSource::FromFacts = pseudo {
                let len = stop - start;
                if let Some(net) = &fresh.facts.net {
                    let ph = match *net {
                        crate::dissect::NetFacts::V4 { src, dst, proto } => {
                            crate::checksum::PseudoHeader::V4 { src, dst, proto }
                        }
                        crate::dissect::NetFacts::V6 {
                            src,
                            dst,
                            next_header,
                        } => crate::checksum::PseudoHeader::V6 {
                            src,
                            dst,
                            proto: next_header,
                        },
                    };
                    ph.accumulate_into(&mut acc, len);
                }
            }
            let sum = acc.value();
            frame[pos..pos + 2].copy_from_slice(&sum.to_be_bytes());
        }
    }
    Ok(())
}

impl Op {
    const fn start(&self) -> usize {
        match self {
            Op::Overwrite { span, .. } => span.start,
            Op::WriteBits { container, .. } => container.start,
            Op::Insert { at, .. } => *at,
            Op::Delete { span } => span.start,
        }
    }

    /// End of the byte claim (inserts are points: start == end).
    const fn end(&self) -> usize {
        match self {
            Op::Overwrite { span, .. } => span.end,
            Op::WriteBits { container, .. } => container.end,
            Op::Insert { at, .. } => *at,
            Op::Delete { span } => span.end,
        }
    }
}

/// Masked bit-window write (MSB-first `shift`/`width`) into a container
/// slice: clear the window bits, OR the value in. Pure function of the
/// container + window + value — the determinism guarantee. (const: index
/// loops — `iter`/`iter_mut` are not const-callable.)
const fn write_bits_window(container: &mut [u8], shift: u8, width: u8, value: u128) {
    let bits = container.len() * 8;
    let (shift, width) = (shift as usize, width as usize);
    if shift + width > bits {
        return;
    }
    // Whole container as one big-endian integer.
    let mut acc: u128 = 0;
    let mut i = 0;
    while i < container.len() {
        acc = (acc << 8) | container[i] as u128;
        i += 1;
    }
    let mask: u128 = if width >= 128 {
        u128::MAX
    } else {
        ((1u128 << width) - 1) << (bits - shift - width)
    };
    acc = (acc & !mask) | ((value << (bits - shift - width)) & mask);
    let n = container.len();
    let mut i = 0;
    while i < n {
        let down = (n - 1 - i) * 8;
        container[i] = ((acc >> down) & 0xff) as u8;
        i += 1;
    }
}

#[cfg(kani)]
mod kani_proofs {
    //! Kani proofs for the span-patch engine's offset arithmetic (the
    //! pass-2 formal-coverage plan; the unit/proptest suites carry the
    //! empirical side). The registry-level proofs (splice geometry,
    //! determinism, derived healing) live in `mod tests` below — the
    //! mock codec with layouts + derived fields compiles under
    //! `cfg(any(test, kani))`, and ADR 3 keeps wrex-core off the real
    //! proto crates.
    use super::*;

    /// The masked bit-window write never panics for any in-bounds
    /// (shift, width), touches ONLY the window's bytes (every byte
    /// outside the window is preserved bit-for-bit), and leaves the
    /// container untouched entirely when the window overruns (the
    /// early return).
    ///
    /// 8-byte container (an Ethernet address' width class), symbolic
    /// shift/width/value: the loops unwind 8 iterations each.
    #[kani::proof]
    #[kani::unwind(12)]
    fn write_bits_window_spills_nothing() {
        const N: usize = 8;
        let before = [0u8; N];
        let shift = kani::any::<u8>() as usize;
        let width = kani::any::<u8>() as usize;
        let value = kani::any::<u128>();
        // In-bounds windows only (the pre-pass guarantees these; the
        // overrun case is covered below).
        kani::assume(shift + width <= N * 8);
        let mut container = before;
        write_bits_window(&mut container, shift as u8, width as u8, value);
        // Every byte fully outside the window is preserved. A byte i is
        // outside when the window doesn't intersect its 8-bit lane.
        for (i, (b, a)) in container.iter().zip(before.iter()).enumerate() {
            let lane_lo = i * 8;
            let lane_hi = lane_lo + 8;
            let win_lo = shift;
            let win_hi = shift + width;
            if lane_hi <= win_lo || lane_lo >= win_hi {
                assert_eq!(b, a, "byte {i} outside the window changed");
            }
        }
    }

    /// An out-of-bounds window (shift + width > bits) is a silent
    /// no-op: the container is untouched, never a panic.
    #[kani::proof]
    #[kani::unwind(12)]
    fn write_bits_window_overrun_is_noop() {
        const N: usize = 8;
        let shift = kani::any::<u8>() as usize;
        let width = kani::any::<u8>() as usize;
        kani::assume(shift + width > N * 8);
        let mut container = [0u8; N];
        let before = container;
        write_bits_window(
            &mut container,
            shift as u8,
            width as u8,
            kani::any::<u128>(),
        );
        assert_eq!(
            container, before,
            "an overrun window must not touch anything"
        );
    }
}
#[cfg(any(test, kani))]
mod tests {
    use super::*;
    use crate::codec::{Codec, Next, ReadOutcome, Registry};
    use crate::dissect::DecodeCtx;
    use crate::encode::EncodeCtx;
    use crate::error::EncodeError;
    use crate::schema::{FieldKind, FieldSchema, LayerSchema, Layout};
    use crate::spec::LayerSpec;
    use crate::value::Value;
    use bytes::Bytes;

    static FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "a",
            kind: FieldKind::U16,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "a",
        },
        FieldSchema {
            name: "len",
            kind: FieldKind::U16,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "len",
        },
        FieldSchema {
            name: "ck",
            kind: FieldKind::U16,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "ck",
        },
        FieldSchema {
            name: "nib",
            kind: FieldKind::U8,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "nib",
        },
        FieldSchema {
            name: "re",
            kind: FieldKind::Bytes,
            bit_names: &[],
            default: Value::Int(0), // unused in the mock (read builds runtime values)
            required: false,
            doc: "re (ReEncode region, hooked)",
        },
        FieldSchema {
            name: "rn",
            kind: FieldKind::Bytes,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "rn (ReEncode region, NOT hooked)",
        },
    ];
    static SCHEMA: LayerSchema = LayerSchema {
        kind: "mock",
        rank: 5,
        parents: &[],
        doc: "patch-engine mock",
        fields: FIELDS,
        records: &[],
    };
    struct MockCodec;
    impl Codec for MockCodec {
        fn schema(&self) -> &'static LayerSchema {
            &SCHEMA
        }
        fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
            Ok(7)
        }
        fn write(&self, _spec: &LayerSpec, _ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
            Ok(())
        }
        fn read<'b>(&self, bytes: &'b [u8], ctx: &mut DecodeCtx<'b>) -> ReadOutcome {
            if bytes.len() < 7 {
                return ReadOutcome::Anomaly(
                    crate::error::DecodeError::Truncated {
                        kind: "mock",
                        need: 7,
                        have: bytes.len(),
                    },
                    Next::Payload,
                );
            }
            let mut fields = std::collections::BTreeMap::new();
            fields.insert(
                "a".to_string(),
                Value::Int(u16::from_be_bytes([bytes[0], bytes[1]]) as u128),
            );
            fields.insert("len".to_string(), Value::Int(9u128));
            fields.insert("ck".to_string(), Value::Int(7u128));
            fields.insert("nib".to_string(), Value::Int((bytes[6] >> 4) as u128));
            fields.insert(
                "re".to_string(),
                Value::Bytes(Bytes::copy_from_slice(&bytes[7..9])),
            );
            fields.insert(
                "rn".to_string(),
                Value::Bytes(Bytes::copy_from_slice(&bytes[7..9])),
            );
            let view = crate::dissect::LayerView {
                kind: "mock",
                span: ctx.offset..ctx.offset + 7,
                field_spans: Default::default(),
                fields,
            };
            ReadOutcome::Layer(view, Some(Next::Payload))
        }
        fn layouts(&self) -> &'static [(&'static str, Layout)] {
            &[
                ("a", Layout::Bytes { at: 0, len: 2 }),
                ("len", Layout::Bytes { at: 2, len: 2 }),
                ("ck", Layout::Bytes { at: 4, len: 2 }),
                (
                    "nib",
                    Layout::Bits {
                        at: 6,
                        shift: 0,
                        width: 4,
                    },
                ),
                ("re", Layout::ReEncode { at: 7, len: 2 }),
                ("rn", Layout::ReEncode { at: 7, len: 2 }),
            ]
        }
        fn derived(&self) -> &'static [Derived] {
            &[
                Derived::Length {
                    field: "len",
                    at: 2,
                    base: crate::schema::LengthBase::LayerStart,
                    units: crate::schema::LengthUnits::Bytes,
                },
                Derived::Checksum {
                    field: "ck",
                    at: 4,
                    start: crate::schema::ChecksumStart::Layer,
                    end: ChecksumEnd::Frame,
                    pseudo: PseudoSource::None,
                },
            ]
        }

        /// Tranche-13a hook: `re` pads with NULs (the dhcp sname/file
        /// rule); `rn` stays unhooked (the default `None`).
        fn reencode(
            &self,
            field: &str,
            value: &[u8],
            region: std::ops::Range<usize>,
        ) -> Option<Result<Vec<u8>, String>> {
            if field != "re" {
                return None;
            }
            if value.len() > region.len() {
                return Some(Err(format!(
                    "value is {} bytes, region is {}",
                    value.len(),
                    region.len()
                )));
            }
            let mut out = value.to_vec();
            out.resize(region.len(), 0);
            Some(Ok(out))
        }
    }

    fn reg() -> Registry {
        let mut r = Registry::default();
        r.register(&MockCodec);
        r
    }

    fn frame() -> crate::dissect::DissectedPacket {
        let reg = reg();
        // 7-byte mock header (a=0x1111, len=9, ck=0, nib=2 → 0x20) + payload
        let bytes: Bytes = [0x11u8, 0x11, 0x00, 0x09, 0x00, 0x00, 0x20, 0xde, 0xad]
            .as_slice()
            .into();
        crate::dissect::dissect(&reg, &bytes, "mock")
    }

    /// A quantized derived length over a NON-grid span is the pointed
    /// `LengthNotQuantized` (tranche 17a) — unreachable through the ext
    /// family's own dissectors (their spans are grid-aligned by
    /// construction), so the guard is pinned here over a synthetic
    /// 7-byte span with an Octlets8 `len`.
    static QUANT_FIELDS: &[FieldSchema] = &[FieldSchema {
        name: "qlen",
        kind: FieldKind::U8,
        bit_names: &[],
        default: Value::Int(0),
        required: false,
        doc: "quantized len",
    }];
    static QUANT_SCHEMA: LayerSchema = LayerSchema {
        kind: "mockq",
        rank: 5,
        parents: &[],
        doc: "patch-engine quantized mock",
        fields: QUANT_FIELDS,
        records: &[],
    };
    struct MockQuantized;
    impl Codec for MockQuantized {
        fn schema(&self) -> &'static LayerSchema {
            &QUANT_SCHEMA
        }
        fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
            Ok(7)
        }
        fn write(&self, _spec: &LayerSpec, _ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
            Ok(())
        }
        fn read<'b>(&self, bytes: &'b [u8], ctx: &mut DecodeCtx<'b>) -> ReadOutcome {
            if bytes.len() < 7 {
                return ReadOutcome::Anomaly(
                    crate::error::DecodeError::Truncated {
                        kind: "mockq",
                        need: 7,
                        have: bytes.len(),
                    },
                    Next::Payload,
                );
            }
            let mut fields = std::collections::BTreeMap::new();
            fields.insert("qlen".to_string(), Value::Int(bytes[0] as u128));
            let mut spans = std::collections::BTreeMap::new();
            spans.insert(
                "qlen".to_string(),
                crate::dissect::FieldSpan::Bytes(ctx.offset..ctx.offset + 1),
            );
            ReadOutcome::Layer(
                crate::dissect::LayerView {
                    kind: "mockq",
                    span: ctx.offset..ctx.offset + 7,
                    field_spans: spans,
                    fields,
                },
                Some(Next::Payload),
            )
        }
        fn layouts(&self) -> &'static [(&'static str, crate::schema::Layout)] {
            static L: &[(&str, crate::schema::Layout)] =
                &[("qlen", crate::schema::Layout::Bytes { at: 0, len: 1 })];
            L
        }
        fn derived(&self) -> &'static [Derived] {
            static D: &[Derived] = &[Derived::Length {
                field: "qlen",
                at: 0,
                base: crate::schema::LengthBase::Span,
                units: crate::schema::LengthUnits::Octlets8,
            }];
            D
        }
    }

    #[test]
    fn quantized_length_off_grid_is_pointed() {
        let mut reg = Registry::default();
        reg.register(&MockQuantized);
        let bytes: Bytes = [0x00u8, 1, 2, 3, 4, 5, 6].as_slice().into();
        let p = crate::dissect::dissect(&reg, &bytes, "mockq");
        // The 7-byte span is not a multiple of 8: no consistent value
        // exists — pointed, never a silent truncation.
        match patch(&reg, &p, &[], &Scope::all()) {
            Err(PatchError::LengthNotQuantized {
                path,
                unit,
                remainder,
            }) => {
                assert_eq!(path, "mockq.qlen");
                assert_eq!(unit, 8);
                assert_eq!(remainder, 7);
            }
            other => panic!("expected LengthNotQuantized, got {other:?}"),
        }
    }

    // A quantized-length mock at the frame edge: q7 writes its last
    // in-bounds byte (pos + 1 == len), q8 sits past it (pos + 1 > len).
    static QEDGE_FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "q7",
            kind: FieldKind::U8,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "quantized len at the last byte",
        },
        FieldSchema {
            name: "q8",
            kind: FieldKind::U8,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "quantized len past the last byte",
        },
    ];
    static QEDGE_SCHEMA: LayerSchema = LayerSchema {
        kind: "mocke",
        rank: 5,
        parents: &[],
        doc: "quantized-edge mock",
        fields: QEDGE_FIELDS,
        records: &[],
    };
    struct MockQuantEdge;
    impl Codec for MockQuantEdge {
        fn schema(&self) -> &'static LayerSchema {
            &QEDGE_SCHEMA
        }
        fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
            Ok(8)
        }
        fn write(&self, _spec: &LayerSpec, _ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
            Ok(())
        }
        fn read<'b>(&self, bytes: &'b [u8], ctx: &mut DecodeCtx<'b>) -> ReadOutcome {
            if bytes.len() < 8 {
                return ReadOutcome::Anomaly(
                    crate::error::DecodeError::Truncated {
                        kind: "mocke",
                        need: 8,
                        have: bytes.len(),
                    },
                    Next::Payload,
                );
            }
            let mut fields = std::collections::BTreeMap::new();
            fields.insert("q7".to_string(), Value::Int(0));
            fields.insert("q8".to_string(), Value::Int(0));
            let view = crate::dissect::LayerView {
                kind: "mocke",
                span: ctx.offset..ctx.offset + 8,
                field_spans: Default::default(),
                fields,
            };
            ReadOutcome::Layer(view, Some(Next::Payload))
        }
        fn layouts(&self) -> &'static [(&'static str, Layout)] {
            &[
                ("q7", Layout::Bytes { at: 7, len: 1 }),
                ("q8", Layout::Bytes { at: 8, len: 1 }),
            ]
        }
        fn derived(&self) -> &'static [Derived] {
            &[
                Derived::Length {
                    field: "q7",
                    at: 7,
                    base: crate::schema::LengthBase::LayerStart,
                    units: crate::schema::LengthUnits::Octlets8,
                },
                Derived::Length {
                    field: "q8",
                    at: 8,
                    base: crate::schema::LengthBase::LayerStart,
                    units: crate::schema::LengthUnits::Octlets8,
                },
            ]
        }
    }

    #[test]
    fn quantized_length_write_bounds_at_frame_edge() {
        let mut reg = Registry::default();
        reg.register(&MockQuantEdge);
        let p = crate::dissect::dissect(&reg, &[0u8; 8], "mocke");
        // q7@pos7 → 7 + 1 = 8 > 8 false: the last in-bounds byte.
        // covered = 8 (LayerStart) → (8/8) − 1 = 0.
        let s7 = Scope::select(&["mocke.q7"]).expect("scope");
        let out = patch(&reg, &p, &[], &s7).expect("boundary quantized length");
        assert_eq!(out[7], 0);
        // q8@pos8 → 9 > 8 → Err.
        let s8 = Scope::select(&["mocke.q8"]).expect("scope");
        assert!(matches!(
            patch(&reg, &p, &[], &s8).unwrap_err(),
            PatchError::OutOfBounds { .. }
        ));
    }

    #[test]
    fn scope_all_recomputes_len_and_checksum() {
        let reg = reg();
        let p = frame();
        // Grow the frame: the Length must recompute (9 → 12).
        let out = patch(
            &reg,
            &p,
            &[Edit::Insert {
                at: 7,
                bytes: Bytes::from_static(&[1, 2, 3]),
            }],
            &Scope::all(),
        )
        .expect("patch");
        assert_eq!(out[0], 0x11);
        assert_eq!(out[1], 0x11);
        assert_eq!(out[6], 0x20, "nib byte untouched by the insert/recompute");
        // len recomputed: frame end (12) − layer start (0)
        assert_eq!(&out[2..4], &12u16.to_be_bytes());
        // ck recomputed over [0..12]: fold the covered range *excluding*
        // the checksum itself, one's complement.
        let mut acc = crate::checksum::ChecksumAccumulator::new();
        acc.add_bytes(&out[..4]);
        acc.add_bytes(&out[6..12]);
        assert_eq!(&out[4..6], &acc.value().to_be_bytes());
    }

    #[test]
    fn scope_none_preserves_stale_derived() {
        let reg = reg();
        let p = frame();
        let out = patch(
            &reg,
            &p,
            &[Edit::Insert {
                at: 7,
                bytes: Bytes::from_static(&[1, 2, 3]),
            }],
            &Scope::none(),
        )
        .expect("patch");
        // stale len (9) and stale ck (0) preserved verbatim
        assert_eq!(&out[2..4], &9u16.to_be_bytes());
        assert_eq!(&out[4..6], &0u16.to_be_bytes());
    }

    #[test]
    fn selective_scope_recomputes_only_selection() {
        let reg = reg();
        let p = frame();
        let scope = Scope::select(&["mock.len"]).expect("scope");
        let out = patch(
            &reg,
            &p,
            &[Edit::Insert {
                at: 7,
                bytes: Bytes::from_static(&[1, 2, 3]),
            }],
            &scope,
        )
        .expect("patch");
        assert_eq!(&out[2..4], &12u16.to_be_bytes(), "len recomputed");
        assert_eq!(&out[4..6], &0u16.to_be_bytes(), "ck stays stale");
    }

    #[test]
    fn layer_shorthand_selects_whole_layer() {
        let reg = reg();
        let p = frame();
        let scope = Scope::select(&["mock.*"]).expect("scope");
        let out = patch(
            &reg,
            &p,
            &[Edit::Insert {
                at: 7,
                bytes: Bytes::from_static(&[1, 2, 3]),
            }],
            &scope,
        )
        .expect("patch");
        assert_eq!(&out[2..4], &12u16.to_be_bytes());
        let mut acc = crate::checksum::ChecksumAccumulator::new();
        acc.add_bytes(&out[..4]);
        acc.add_bytes(&out[6..12]);
        assert_eq!(&out[4..6], &acc.value().to_be_bytes());
    }

    #[test]
    fn set_field_overwrite_and_bits_mask() {
        let reg = reg();
        let p = frame();
        // nib is the top nibble of byte 6 (value 2 → byte 0x20).
        // Scope none: pure byte edit, zero recomputation.
        let out = patch(
            &reg,
            &p,
            &[Edit::SetField {
                path: "mock.nib".to_string(),
                bytes: Bytes::from_static(&[0x0b]), // 1 byte, width 4
            }],
            &Scope::none(),
        )
        .expect("patch");
        // low nibble (0) preserved, high nibble = 0xb
        assert_eq!(out[6], 0xb0);
        // untouched prefix (ck stays stale 0 under scope none)
        assert_eq!(&out[..6], &[0x11, 0x11, 0x00, 0x09, 0x00, 0x00]);
    }

    #[test]
    fn edit_scope_conflict_is_pointed() {
        let reg = reg();
        let p = frame();
        let err = patch(
            &reg,
            &p,
            &[Edit::SetField {
                path: "mock.ck".to_string(),
                bytes: Bytes::from_static(&[0, 1]),
            }],
            &Scope::all(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::EditScopeConflict(_)), "{err}");
        // not under a scope that leaves it alone
        patch(
            &reg,
            &p,
            &[Edit::SetField {
                path: "mock.ck".to_string(),
                bytes: Bytes::from_static(&[0, 1]),
            }],
            &Scope::none(),
        )
        .expect("no conflict");
    }

    #[test]
    fn pointed_errors_unresolved_width_overlap_bounds() {
        let reg = reg();
        let p = frame();
        assert!(matches!(
            patch(
                &reg,
                &p,
                &[Edit::SetField {
                    path: "mock.nothing".to_string(),
                    bytes: Bytes::new(),
                }],
                &Scope::none()
            )
            .unwrap_err(),
            PatchError::UnresolvedPath(_)
        ));
        assert!(matches!(
            patch(
                &reg,
                &p,
                &[Edit::SetField {
                    path: "mock.a".to_string(),
                    bytes: Bytes::from_static(&[1]), // wants 2
                }],
                &Scope::none()
            )
            .unwrap_err(),
            PatchError::WidthMismatch {
                want: 2,
                got: 1,
                ..
            }
        ));
        // two edits on the same span overlap
        assert!(matches!(
            patch(
                &reg,
                &p,
                &[
                    Edit::SetField {
                        path: "mock.a".to_string(),
                        bytes: Bytes::from_static(&[0, 0]),
                    },
                    Edit::SetField {
                        path: "mock.a".to_string(),
                        bytes: Bytes::from_static(&[0, 1]),
                    },
                ],
                &Scope::none()
            )
            .unwrap_err(),
            PatchError::Overlap
        ));
        // out of bounds
        assert!(matches!(
            patch(&reg, &p, &[Edit::Delete { at: 0..1000 }], &Scope::none()).unwrap_err(),
            PatchError::OutOfBounds { .. }
        ));
    }

    #[test]
    fn determinism_same_edits_same_bytes() {
        let reg = reg();
        let p = frame();
        let edits = vec![Edit::SetField {
            path: "mock.a".to_string(),
            bytes: Bytes::from_static(&[0xaa, 0xbb]),
        }];
        let a = patch(&reg, &p, &edits, &Scope::all()).expect("patch");
        let b = patch(&reg, &p, &edits, &Scope::all()).expect("patch");
        assert_eq!(a, b);
        // empty edit set + scope none: byte-identical to the frame (the
        // T11a property; replay/fuzz retransmit are this degenerate).
        let c = patch(&reg, &p, &[], &Scope::none()).expect("patch");
        assert_eq!(&c[..], &p.frame[..]);
        // empty edit set + scope all: consistency enforcement still
        // recomputes the scoped derived fields — "normalize" is this
        // degenerate, deliberately (the caller selected it).
        let d = patch(&reg, &p, &[], &Scope::all()).expect("patch");
        let mut acc = crate::checksum::ChecksumAccumulator::new();
        acc.add_bytes(&d[..4]);
        acc.add_bytes(&d[6..9]);
        assert_eq!(&d[4..6], &acc.value().to_be_bytes(), "stale ck healed");
    }

    #[test]
    fn write_bits_window_masks() {
        let mut c = [0x20u8];
        write_bits_window(&mut c, 0, 4, 0xb);
        assert_eq!(c, [0xb0]);
        let mut c2 = [0x0fu8];
        write_bits_window(&mut c2, 4, 4, 0x5);
        assert_eq!(c2, [0x05]); // low nibble window: high nibble cleared
        // 12-bit window in a u16 container: shift 4, width 12
        let mut c3 = [0xab, 0xcd];
        write_bits_window(&mut c3, 4, 12, 0x0123);
        assert_eq!(c3, [0xa1, 0x23]);
        // A window in the *low* bits of byte 0: shift 4, width 4.
        let mut c4 = [0xff, 0xff];
        write_bits_window(&mut c4, 4, 4, 0x2);
        assert_eq!(c4, [0xf2, 0xff]); // only the low nibble of byte 0
    }

    // --- Scope / error-display coverage ----------------------------------

    #[test]
    fn scope_selection_semantics() {
        assert!(Scope::all().selects_path("udp.checksum"));
        assert!(Scope::all().selects_path("anything.at.all"));
        assert!(!Scope::none().selects_path("udp.checksum"));
        let s = Scope::select(&["udp.checksum"]).expect("scope");
        assert!(s.selects_path("udp.checksum"));
        assert!(!s.selects_path("udp.length"));
        assert!(!s.selects_path("tcp.checksum"));
        let s = Scope::select(&["udp.*"]).expect("scope");
        assert!(s.selects_path("udp.checksum"));
        assert!(s.selects_path("udp.length"));
        assert!(!s.selects_path("tcp.checksum"));
        // A path without a dot never matches a selective scope.
        let s = Scope::select(&["udp.checksum"]).expect("scope");
        assert!(!s.selects_path("nopath"));
        // Malformed selectors are pointed errors; an empty list is none.
        assert!(Scope::select(&["nokind"]).is_err());
        assert_eq!(Scope::select(&[]).unwrap(), Scope::none());
        // "all" is a layer shorthand, not a keyword.
        let s = Scope::select(&["all.*"]).expect("scope");
        assert!(s.selects_path("all.checksum"));
        assert!(!s.selects_path("udp.checksum"));
    }

    #[test]
    fn patch_error_display_is_pointed() {
        assert_eq!(PatchError::Overlap.to_string(), "edits overlap");
        assert!(
            PatchError::UnresolvedPath("tcp.seq".into())
                .to_string()
                .contains("no dissected field at path \"tcp.seq\"")
        );
        assert!(
            PatchError::UnsupportedPath("ipv4.options".into())
                .to_string()
                .contains("no patchable span")
        );
        assert!(
            PatchError::ReEncodeFailed {
                path: "dhcp.sname".into(),
                reason: "over-length".into()
            }
            .to_string()
            .contains("refused")
        );
        assert_eq!(
            PatchError::WidthMismatch {
                path: "tcp.seq".into(),
                want: 4,
                got: 2,
            }
            .to_string(),
            "field \"tcp.seq\" wants 4 bytes, got 2"
        );
        assert!(
            PatchError::OutOfBounds {
                path: "ipv4.src".into()
            }
            .to_string()
            .contains("outside the frame")
        );
        assert!(
            PatchError::EditScopeConflict("udp.checksum".into())
                .to_string()
                .contains("which the scope also recomputes")
        );
        assert!(
            PatchError::BadScope("udp".into())
                .to_string()
                .contains("bad scope selector \"udp\"")
        );
        assert!(
            PatchError::LengthNotQuantized {
                path: "hopopts.hdr_ext_len".into(),
                unit: 8,
                remainder: 3,
            }
            .to_string()
            .contains("divisible by 8")
        );
    }

    // --- hand-built packets: span geometry at the frame edge ---------------

    /// A packet whose layers/spans are hand-built (no codec roundtrip):
    /// the engine reads `field_spans` verbatim, so synthetic entries are
    /// enough to pin the bounds checks. `kind` selects the registry codec
    /// the patch pre-pass resolves (its `reencode` hook contract).
    fn synthetic_packet(
        kind: &'static str,
        frame: &[u8],
        spans: &[(&str, FieldSpan)],
    ) -> DissectedPacket {
        let mut field_spans = std::collections::BTreeMap::new();
        let mut fields = std::collections::BTreeMap::new();
        for (name, span) in spans {
            field_spans.insert(name.to_string(), span.clone());
            fields.insert(name.to_string(), Value::Bytes(Bytes::new()));
        }
        DissectedPacket {
            start: kind,
            layers: vec![crate::dissect::LayerView {
                kind,
                span: 0..2,
                field_spans,
                fields,
            }],
            payload: Bytes::new(),
            anomalies: vec![],
            frame: Bytes::copy_from_slice(frame),
            facts: Default::default(),
        }
    }

    #[test]
    fn spans_and_edits_at_the_frame_end_are_in_bounds() {
        let reg = reg();
        let p = synthetic_packet(
            "mock",
            &[0x00, 0x00],
            &[
                ("a", FieldSpan::Bytes(0..2)), // ends exactly at the frame end
                (
                    "nib",
                    FieldSpan::Bits {
                        container: 0..2,
                        shift: 4,
                        width: 4,
                    },
                ),
            ],
        );
        // Bytes overwrite ending at frame.len(): in bounds, lands.
        let out = patch(
            &reg,
            &p,
            &[Edit::SetField {
                path: "mock.a".to_string(),
                bytes: Bytes::from_static(&[0x11, 0x22]),
            }],
            &Scope::none(),
        )
        .expect("bytes span at frame end is in bounds");
        assert_eq!(&out[..], &[0x11, 0x22]);
        // Bits container ending at frame.len(): in bounds, masked write.
        let p2 = synthetic_packet(
            "mock",
            &[0x00, 0x00],
            &[(
                "nib",
                FieldSpan::Bits {
                    container: 0..2,
                    shift: 4,
                    width: 12,
                },
            )],
        );
        // width 12 → 2 value bytes, BE, masked into the window
        // [bit4..bit16): 0x0123 → [0x01, 0x23] (multi-byte value
        // packing; a 1-byte window would alias it).
        let out2 = patch(
            &reg,
            &p2,
            &[Edit::SetField {
                path: "mock.nib".to_string(),
                bytes: Bytes::from_static(&[0x01, 0x23]),
            }],
            &Scope::none(),
        )
        .expect("bits container at frame end is in bounds");
        assert_eq!(&out2[..], &[0x01, 0x23]);
        // Insert at exactly frame.len(): appends (a point at the end).
        let out3 = patch(
            &reg,
            &p,
            &[Edit::Insert {
                at: 2,
                bytes: Bytes::from_static(&[0x99]),
            }],
            &Scope::none(),
        )
        .expect("insert at frame end is in bounds");
        assert_eq!(&out3[..], &[0x00, 0x00, 0x99]);
        // Delete the full range / an empty range / a range ending at the end.
        let out4 =
            patch(&reg, &p, &[Edit::Delete { at: 0..2 }], &Scope::none()).expect("full delete");
        assert!(out4.is_empty());
        let out5 = patch(&reg, &p, &[Edit::Delete { at: 1..1 }], &Scope::none())
            .expect("empty delete is a no-op");
        assert_eq!(&out5[..], &[0x00, 0x00]);
        // Out of bounds stays pointed on every edit shape: a Bytes span
        // lying past the frame end (width matches, bounds do not).
        let short = synthetic_packet("mock", &[0x00], &[("a", FieldSpan::Bytes(0..2))]);
        assert!(matches!(
            patch(
                &reg,
                &short,
                &[Edit::SetField {
                    path: "mock.a".to_string(),
                    bytes: Bytes::from_static(&[1, 2]),
                }],
                &Scope::none()
            )
            .unwrap_err(),
            PatchError::OutOfBounds { .. }
        ));
        assert!(matches!(
            patch(
                &reg,
                &p,
                &[Edit::Insert {
                    at: 3,
                    bytes: Bytes::new(),
                }],
                &Scope::none()
            )
            .unwrap_err(),
            PatchError::OutOfBounds { .. }
        ));
        assert!(matches!(
            patch(&reg, &p, &[Edit::Delete { at: 0..3 }], &Scope::none()).unwrap_err(),
            PatchError::OutOfBounds { .. }
        ));
        // start > end is a pointed error (a reversed range is never
        // silently treated as a reverse iteration here).
        #[allow(clippy::reversed_empty_ranges)]
        let reversed = [Edit::Delete { at: 2..1 }];
        assert!(matches!(
            patch(&reg, &p, &reversed, &Scope::none()).unwrap_err(),
            PatchError::OutOfBounds { .. }
        ));
        // Interior delete of exactly the frame content.
        let out6 =
            patch(&reg, &p, &[Edit::Delete { at: 0..1 }], &Scope::none()).expect("interior delete");
        assert_eq!(&out6[..], &[0x00]);
    }

    #[test]
    fn multi_edit_ordering_and_overlap() {
        let reg = reg();
        let p = frame();
        // Two disjoint edits: both land, in pre-edit coordinate order.
        let out = patch(
            &reg,
            &p,
            &[
                Edit::SetField {
                    path: "mock.len".to_string(),
                    bytes: Bytes::from_static(&[0x0a, 0x0b]),
                },
                Edit::SetField {
                    path: "mock.a".to_string(),
                    bytes: Bytes::from_static(&[0xaa, 0xbb]),
                },
            ],
            &Scope::none(),
        )
        .expect("disjoint edits");
        assert_eq!(&out[0..2], &[0xaa, 0xbb]);
        assert_eq!(&out[2..4], &[0x0a, 0x0b]);
        // Adjacent (touching, non-overlapping) edits are fine.
        let out = patch(
            &reg,
            &p,
            &[
                Edit::SetField {
                    path: "mock.a".to_string(),
                    bytes: Bytes::from_static(&[0x00, 0x01]),
                },
                Edit::SetField {
                    path: "mock.len".to_string(),
                    bytes: Bytes::from_static(&[0x00, 0x02]),
                },
            ],
            &Scope::none(),
        )
        .expect("adjacent edits do not overlap");
        assert_eq!(&out[0..4], &[0x00, 0x01, 0x00, 0x02]);
        // Partial overlap (0..2 vs insert@1): ambiguous → pointed error.
        assert!(matches!(
            patch(
                &reg,
                &p,
                &[
                    Edit::SetField {
                        path: "mock.a".to_string(),
                        bytes: Bytes::from_static(&[0, 0]),
                    },
                    Edit::Insert {
                        at: 1,
                        bytes: Bytes::from_static(&[0xff]),
                    },
                ],
                &Scope::none()
            )
            .unwrap_err(),
            PatchError::Overlap
        ));
        // Equal starts (two inserts at one offset): ambiguous → error.
        assert!(matches!(
            patch(
                &reg,
                &p,
                &[
                    Edit::Insert {
                        at: 7,
                        bytes: Bytes::from_static(&[1]),
                    },
                    Edit::Insert {
                        at: 7,
                        bytes: Bytes::from_static(&[2]),
                    },
                ],
                &Scope::none()
            )
            .unwrap_err(),
            PatchError::Overlap
        ));
    }

    /// Tranche 13a: a `ReEncode` span on a codec WITHOUT a `reencode`
    /// hook defers pointedly — the default `None` is the deferral
    /// contract, never a silent wrong-width splice.
    #[test]
    fn reencode_default_none_defers_pointedly() {
        let reg = reg();
        let p = frame();
        let err = patch(
            &reg,
            &p,
            &[Edit::SetField {
                path: "mock.rn".to_string(), // ReEncode span, no hook
                bytes: Bytes::from_static(&[0x00, 0x00]),
            }],
            &Scope::none(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::UnsupportedPath(_)), "{err}");
    }

    /// The TRAIT-default `reencode` (no codec override): a `ReEncode` span
    /// on a hook-less codec defers pointedly — `None` (or a wrong-width
    /// `Some`) is never silently accepted as a region replacement.
    #[test]
    fn reencode_trait_default_defers_pointedly() {
        let mut reg = Registry::default();
        reg.register(&MockQuantized); // no `reencode` override
        // A 1-byte region: a `Some(Ok(vec![…]))` default of any concrete
        // width is either rejected (0/2 bytes) or wrong (1 byte) — only
        // `None` (the real default) defers.
        let p = synthetic_packet("mockq", &[0x00], &[("zz", FieldSpan::ReEncode(0..1))]);
        let err = patch(
            &reg,
            &p,
            &[Edit::SetField {
                path: "mockq.zz".to_string(),
                bytes: Bytes::from_static(&[0x00]),
            }],
            &Scope::none(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::UnsupportedPath(_)), "{err}");
    }

    /// A hooked `ReEncode` region strictly inside the frame (end < frame
    /// len) is in bounds and lands: only regions past the frame edge are
    /// the pointed `OutOfBounds`.
    #[test]
    fn reencode_region_strictly_inside_frame_lands() {
        let reg = reg();
        let p = synthetic_packet(
            "mock",
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[("re", FieldSpan::ReEncode(0..2))],
        );
        let out = patch(
            &reg,
            &p,
            &[Edit::SetField {
                path: "mock.re".to_string(),
                bytes: Bytes::from_static(&[0x41]), // 1 byte → NUL-padded to 2
            }],
            &Scope::none(),
        )
        .expect("in-frame region is in bounds");
        assert_eq!(&out[0..2], &[0x41, 0x00]);
        assert_eq!(&out[2..], &[0, 0, 0, 0]);
    }

    // --- wire→wire recompute fixtures: net → l4 → l5 -----------------------
    //
    // MOCK above pins the flat engine; these pin the arithmetic the
    // flat single-layer-at-0 case leaves aliased: LayerStart/LayerEnd/
    // Span bases at nonzero offsets, UpperPacket/FromFacts checksums,
    // quantized units, and the pos/stop boundary cases.

    static NET_FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "src",
            kind: FieldKind::Ipv4,
            bit_names: &[],
            default: Value::Ipv4(std::net::Ipv4Addr::UNSPECIFIED),
            required: false,
            doc: "src",
        },
        FieldSchema {
            name: "dst",
            kind: FieldKind::Ipv4,
            bit_names: &[],
            default: Value::Ipv4(std::net::Ipv4Addr::UNSPECIFIED),
            required: false,
            doc: "dst",
        },
        FieldSchema {
            name: "proto",
            kind: FieldKind::U8,
            bit_names: &[],
            default: Value::Int(17),
            required: false,
            doc: "proto",
        },
    ];
    static NET_SCHEMA: LayerSchema = LayerSchema {
        kind: "mocknet",
        rank: 20,
        parents: &[],
        doc: "recompute-test net mock",
        fields: NET_FIELDS,
        records: &[],
    };

    static L4_FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "ck",
            kind: FieldKind::U16,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "ck (pos == start)",
        },
        FieldSchema {
            name: "tlen",
            kind: FieldKind::U16,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "tlen (LayerStart)",
        },
        FieldSchema {
            name: "plen",
            kind: FieldKind::U16,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "plen (LayerEnd)",
        },
        FieldSchema {
            name: "q4",
            kind: FieldKind::U8,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "q4 (Span/Octlets4)",
        },
        FieldSchema {
            name: "ckf",
            kind: FieldKind::U16,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "ckf (UpperPacket/FromFacts)",
        },
    ];
    static L4_SCHEMA: LayerSchema = LayerSchema {
        kind: "mockl4",
        rank: 30,
        parents: &["mocknet"],
        doc: "recompute-test l4 mock",
        fields: L4_FIELDS,
        records: &[],
    };

    static L5_SCHEMA: LayerSchema = LayerSchema {
        kind: "mockl5",
        rank: 31,
        parents: &["mockl4"],
        doc: "recompute-test l5 mock",
        fields: L4_FIELDS,
        records: &[],
    };

    fn net_read<'b>(bytes: &'b [u8], ctx: &mut DecodeCtx<'b>) -> ReadOutcome {
        if bytes.len() < 12 {
            return ReadOutcome::Anomaly(
                crate::error::DecodeError::Truncated {
                    kind: "mocknet",
                    need: 12,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let src = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
        let dst = std::net::Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
        let proto = bytes[8];
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("src".to_string(), Value::Ipv4(src));
        fields.insert("dst".to_string(), Value::Ipv4(dst));
        fields.insert("proto".to_string(), Value::Int(proto as u128));
        let mut spans = std::collections::BTreeMap::new();
        spans.insert(
            "src".to_string(),
            FieldSpan::Bytes(ctx.offset..ctx.offset + 4),
        );
        spans.insert(
            "dst".to_string(),
            FieldSpan::Bytes(ctx.offset + 4..ctx.offset + 8),
        );
        spans.insert(
            "proto".to_string(),
            FieldSpan::Bytes(ctx.offset + 8..ctx.offset + 9),
        );
        ctx.facts.net = Some(crate::dissect::NetFacts::V4 { src, dst, proto });
        ctx.facts.upper_start = Some(ctx.offset + 12);
        let view = crate::dissect::LayerView {
            kind: "mocknet",
            span: ctx.offset..ctx.offset + 12,
            field_spans: spans,
            fields,
        };
        ReadOutcome::Layer(view, Some(Next::Kind("mockl4")))
    }

    fn l4_read<'b>(kind: &'static str) -> impl Fn(&[u8], &mut DecodeCtx<'b>) -> ReadOutcome {
        move |bytes, ctx| {
            if bytes.len() < 12 {
                return ReadOutcome::Anomaly(
                    crate::error::DecodeError::Truncated {
                        kind,
                        need: 12,
                        have: bytes.len(),
                    },
                    Next::Payload,
                );
            }
            let mut fields = std::collections::BTreeMap::new();
            fields.insert("ck".to_string(), Value::Int(0));
            fields.insert("tlen".to_string(), Value::Int(0));
            fields.insert("plen".to_string(), Value::Int(0));
            fields.insert("q4".to_string(), Value::Int(0));
            fields.insert("ckf".to_string(), Value::Int(0));
            let view = crate::dissect::LayerView {
                kind,
                span: ctx.offset..ctx.offset + 12,
                field_spans: Default::default(),
                fields,
            };
            ReadOutcome::Layer(view, Some(Next::Kind("mockl5")))
        }
    }

    fn l5_read<'b>(bytes: &'b [u8], ctx: &mut DecodeCtx<'b>) -> ReadOutcome {
        if bytes.len() < 4 {
            return ReadOutcome::Anomaly(
                crate::error::DecodeError::Truncated {
                    kind: "mockl5",
                    need: 4,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("ck".to_string(), Value::Int(0));
        fields.insert("c5".to_string(), Value::Int(0));
        let view = crate::dissect::LayerView {
            kind: "mockl5",
            span: ctx.offset..ctx.offset + 4,
            field_spans: Default::default(),
            fields,
        };
        ReadOutcome::Layer(view, Some(Next::Payload))
    }

    /// net(12) | l4(12) | l5(4) — derived fields per layer:
    ///   l4: ck@0 Checksum{Layer, Frame}, tlen@2 Length{LayerStart},
    ///       plen@4 Length{LayerEnd}, q4@6 Length{Span, Octlets4},
    ///       ckf@10 Checksum{UpperPacket, Layer, FromFacts}
    ///   l5: ck@0 Checksum{Layer, Layer}, c5@2 Length{LayerStart}
    /// (ck and c5 share the tlen/plen/q4/ckf field *table* for brevity —
    /// the derived() entries drive what gets recomputed, so a field may
    /// appear in several roles across layers.)
    struct MockNet;
    impl Codec for MockNet {
        fn schema(&self) -> &'static LayerSchema {
            &NET_SCHEMA
        }
        fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
            Ok(12)
        }
        fn write(&self, _spec: &LayerSpec, _ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
            Ok(())
        }
        fn read<'b>(&self, bytes: &'b [u8], ctx: &mut DecodeCtx<'b>) -> ReadOutcome {
            net_read(bytes, ctx)
        }
        fn derived(&self) -> &'static [Derived] {
            // The net layer's own UpperPacket/Layer checksum: start (12)
            // == stop (12) — an empty covered range is the pointed error,
            // never a silent zero-byte fold.
            &[Derived::Checksum {
                field: "nck",
                at: 12,
                start: crate::schema::ChecksumStart::UpperPacket,
                end: ChecksumEnd::Layer,
                pseudo: PseudoSource::None,
            }]
        }
    }

    struct MockL4;
    impl Codec for MockL4 {
        fn schema(&self) -> &'static LayerSchema {
            &L4_SCHEMA
        }
        fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
            Ok(12)
        }
        fn write(&self, _spec: &LayerSpec, _ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
            Ok(())
        }
        fn read<'b>(&self, bytes: &'b [u8], ctx: &mut DecodeCtx<'b>) -> ReadOutcome {
            l4_read("mockl4")(bytes, ctx)
        }
        fn layouts(&self) -> &'static [(&'static str, Layout)] {
            &[
                ("ck", Layout::Bytes { at: 0, len: 2 }),
                ("tlen", Layout::Bytes { at: 2, len: 2 }),
                ("plen", Layout::Bytes { at: 4, len: 2 }),
                ("q4", Layout::Bytes { at: 6, len: 1 }),
                ("ckf", Layout::Bytes { at: 10, len: 2 }),
            ]
        }
        fn derived(&self) -> &'static [Derived] {
            &[
                Derived::Checksum {
                    field: "ck",
                    at: 0,
                    start: crate::schema::ChecksumStart::Layer,
                    end: ChecksumEnd::Frame,
                    pseudo: PseudoSource::None,
                },
                Derived::Length {
                    field: "tlen",
                    at: 2,
                    base: crate::schema::LengthBase::LayerStart,
                    units: crate::schema::LengthUnits::Bytes,
                },
                Derived::Length {
                    field: "plen",
                    at: 4,
                    base: crate::schema::LengthBase::LayerEnd,
                    units: crate::schema::LengthUnits::Bytes,
                },
                Derived::Length {
                    field: "q4",
                    at: 6,
                    base: crate::schema::LengthBase::Span,
                    units: crate::schema::LengthUnits::Octlets4,
                },
                Derived::Checksum {
                    field: "ckf",
                    at: 10,
                    start: crate::schema::ChecksumStart::UpperPacket,
                    end: ChecksumEnd::Layer,
                    pseudo: PseudoSource::FromFacts,
                },
            ]
        }
    }

    struct MockL5;
    impl Codec for MockL5 {
        fn schema(&self) -> &'static LayerSchema {
            &L5_SCHEMA
        }
        fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
            Ok(4)
        }
        fn write(&self, _spec: &LayerSpec, _ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
            Ok(())
        }
        fn read<'b>(&self, bytes: &'b [u8], ctx: &mut DecodeCtx<'b>) -> ReadOutcome {
            l5_read(bytes, ctx)
        }
        fn layouts(&self) -> &'static [(&'static str, Layout)] {
            &[
                ("ck", Layout::Bytes { at: 0, len: 2 }),
                ("c5", Layout::Bytes { at: 2, len: 2 }),
            ]
        }
        fn derived(&self) -> &'static [Derived] {
            &[
                Derived::Checksum {
                    field: "ck",
                    at: 0,
                    start: crate::schema::ChecksumStart::Layer,
                    end: ChecksumEnd::Layer,
                    pseudo: PseudoSource::None,
                },
                Derived::Length {
                    field: "c5",
                    at: 2,
                    base: crate::schema::LengthBase::LayerStart,
                    units: crate::schema::LengthUnits::Bytes,
                },
            ]
        }
    }

    fn net_registry() -> Registry {
        let mut r = Registry::default();
        r.register(&MockNet);
        r.register(&MockL4);
        r.register(&MockL5);
        r
    }

    fn net_frame(payload: &[u8]) -> crate::dissect::DissectedPacket {
        let reg = net_registry();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2, 17, 0, 0, 0]); // net(12)
        bytes.extend_from_slice(&[0; 12]); // l4(12)
        bytes.extend_from_slice(&[0; 4]); // l5(4)
        bytes.extend_from_slice(payload);
        crate::dissect::dissect(&reg, &bytes, "mocknet")
    }

    #[test]
    fn recompute_length_bases_at_nonzero_offsets() {
        let reg = net_registry();
        let p = net_frame(&[]);
        // Selective scope: the lengths under test (Scope::all would also
        // hit nck, the pointed empty-range checksum below).
        let scope = Scope::select(&["mockl4.tlen", "mockl4.plen", "mockl4.q4", "mockl5.c5"])
            .expect("scope");
        let out = patch(&reg, &p, &[], &scope).expect("patch");
        assert_eq!(out.len(), 28);
        let l4 = 12; // l4 layer start
        // tlen (LayerStart): frame end − l4 start = 28 − 12 = 16.
        assert_eq!(&out[l4 + 2..l4 + 4], &16u16.to_be_bytes()[..], "tlen");
        // plen (LayerEnd): frame end − l4 end = 28 − 24 = 4.
        assert_eq!(&out[l4 + 4..l4 + 6], &4u16.to_be_bytes()[..], "plen");
        // q4 (Span, Octlets4): 12 covered octets → (12/4) − 2 = 1.
        assert_eq!(out[l4 + 6], 1, "q4");
        // l5 c5 (LayerStart): frame end − l5 start = 28 − 24 = 4.
        assert_eq!(&out[24 + 2..24 + 4], &4u16.to_be_bytes()[..], "c5");
        // With a payload of 4: frame = 32 — every covered length moves.
        let p2 = net_frame(&[0xde, 0xad, 0xbe, 0xef]);
        let out2 = patch(&reg, &p2, &[], &scope).expect("patch");
        assert_eq!(out2.len(), 32);
        assert_eq!(&out2[l4 + 2..l4 + 4], &20u16.to_be_bytes()[..], "tlen");
        assert_eq!(&out2[l4 + 4..l4 + 6], &8u16.to_be_bytes()[..], "plen");
        assert_eq!(&out2[24 + 2..24 + 4], &8u16.to_be_bytes()[..], "c5");
    }

    #[test]
    fn recompute_checksum_covers_and_pseudo_header() {
        let reg = net_registry();
        let p = net_frame(&[0xde, 0xad]);
        // Each derived checksum recomputed in isolation (a shared scope
        // would let one derivation's writes feed the next fold — order
        // dependence belongs to the caller's scope choice, not here).
        let only = |field: &str| Scope::select(&[field]).expect("scope");
        let u16_at = |o: &Bytes, i: usize| u16::from_be_bytes([o[i], o[i + 1]]);

        // ckf: UpperPacket start (net records 12) → l4 span end (24),
        // FromFacts pseudo (v4 10.0.0.1→10.0.0.2, proto 17), checksum at
        // l4+10; the covered region excludes the checksum field itself.
        let out = patch(&reg, &p, &[], &only("mockl4.ckf")).expect("patch");
        let l4 = 12;
        let mut acc = ChecksumAccumulator::new();
        crate::checksum::PseudoHeader::V4 {
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            proto: 17,
        }
        .accumulate_into(&mut acc, 24 - 12); // stop − start
        acc.add_bytes(&out[12..l4 + 10]);
        acc.add_bytes(&out[l4 + 12..24]);
        assert_eq!(u16_at(&out, l4 + 10), acc.value(), "ckf");

        // l5 ck (Layer/Layer): pos == start (24), stop = span end (28):
        // the covered region is [24..24) ∪ [26..28) — no pseudo-header.
        let out = patch(&reg, &p, &[], &only("mockl5.ck")).expect("patch");
        let mut acc2 = ChecksumAccumulator::new();
        acc2.add_bytes(&out[26..28]);
        assert_eq!(u16_at(&out, 24), acc2.value(), "l5 ck");

        // l4 ck (pos == start, end Frame): covered region [12..12) ∪
        // [14..30) — the payload rides in, the checksum's own bytes do not.
        let out = patch(&reg, &p, &[], &only("mockl4.ck")).expect("patch");
        let mut acc3 = ChecksumAccumulator::new();
        acc3.add_bytes(&out[14..30]);
        assert_eq!(u16_at(&out, l4), acc3.value(), "l4 ck");
    }

    /// The net layer's own UpperPacket/Layer checksum: start (12) ==
    /// stop (12) — an empty covered range is the pointed error, never a
    /// silent zero-byte fold.
    #[test]
    fn empty_covered_range_checksum_is_pointed() {
        let reg = net_registry();
        let p = net_frame(&[]);
        let scope = Scope::select(&["mocknet.nck"]).expect("scope");
        assert!(matches!(
            patch(&reg, &p, &[], &scope).unwrap_err(),
            PatchError::OutOfBounds { .. }
        ));
    }

    /// The net fixture's own geometry: absolute field spans, recorded
    /// facts, and the truncation boundary at exactly 12 bytes.
    #[test]
    fn net_fixture_geometry_and_truncation() {
        let reg = net_registry();
        // Full parse: spans are absolute (offset 0 here), facts recorded.
        let p = net_frame(&[]);
        assert_eq!(p.layers[0].kind, "mocknet");
        assert_eq!(p.layers[0].span, 0..12);
        assert_eq!(
            p.layers[0].field_spans.get("src"),
            Some(&FieldSpan::Bytes(0..4))
        );
        assert_eq!(
            p.layers[0].field_spans.get("dst"),
            Some(&FieldSpan::Bytes(4..8))
        );
        assert_eq!(
            p.layers[0].field_spans.get("proto"),
            Some(&FieldSpan::Bytes(8..9))
        );
        assert_eq!(p.facts.upper_start, Some(12));
        // Exactly 12: the last good net length (the `==` boundary); l4
        // then sees 0 bytes and truncates.
        let p12 = crate::dissect::dissect(&reg, &[0u8; 12], "mocknet");
        assert_eq!(p12.layers[0].kind, "mocknet");
        assert_eq!(p12.layers[1].kind, "unknown");
        // 11: net-truncated → never fatal, unknown tail.
        let p11 = crate::dissect::dissect(&reg, &[0u8; 11], "mocknet");
        assert_eq!(p11.layers[0].kind, "unknown");
        // 24 (net 12 + l4 12, no l5 bytes): l4 parses at its exact
        // minimum; 23 is the l4 truncation.
        let p24 = crate::dissect::dissect(&reg, &[0u8; 24], "mocknet");
        assert_eq!(p24.layers[1].kind, "mockl4");
        let p23 = crate::dissect::dissect(&reg, &[0u8; 23], "mocknet");
        assert_eq!(p23.layers[1].kind, "unknown");
    }

    // --- recompute bounds: the pos/stop boundary errors -------------------
    //
    // A 2-byte mock with TWO derived checksums (at 1 and at 4) driven over
    // frames of 2/3/5/6 bytes pins every `pos + 2 > frame.len()` mutant:
    // Err on the far side, Ok on the exact boundary.

    static BAD_FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "ck",
            kind: FieldKind::U16,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "ck",
        },
        FieldSchema {
            name: "ck4",
            kind: FieldKind::U16,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "ck4",
        },
    ];
    static BAD_SCHEMA: LayerSchema = LayerSchema {
        kind: "mockbad",
        rank: 5,
        parents: &[],
        doc: "recompute-bounds mock",
        fields: BAD_FIELDS,
        records: &[],
    };
    struct MockBad;
    impl Codec for MockBad {
        fn schema(&self) -> &'static LayerSchema {
            &BAD_SCHEMA
        }
        fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
            Ok(2)
        }
        fn write(&self, _spec: &LayerSpec, _ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
            Ok(())
        }
        fn read<'b>(&self, bytes: &'b [u8], ctx: &mut DecodeCtx<'b>) -> ReadOutcome {
            if bytes.len() < 2 {
                return ReadOutcome::Anomaly(
                    crate::error::DecodeError::Truncated {
                        kind: "mockbad",
                        need: 2,
                        have: bytes.len(),
                    },
                    Next::Payload,
                );
            }
            let mut fields = std::collections::BTreeMap::new();
            fields.insert("ck".to_string(), Value::Int(0));
            fields.insert("ck4".to_string(), Value::Int(0));
            let view = crate::dissect::LayerView {
                kind: "mockbad",
                span: ctx.offset..ctx.offset + 2,
                field_spans: Default::default(),
                fields,
            };
            ReadOutcome::Layer(view, Some(Next::Payload))
        }
        fn layouts(&self) -> &'static [(&'static str, Layout)] {
            &[
                ("ck", Layout::Bytes { at: 1, len: 2 }),
                ("ck4", Layout::Bytes { at: 4, len: 2 }),
            ]
        }
        fn derived(&self) -> &'static [Derived] {
            &[
                Derived::Checksum {
                    field: "ck",
                    at: 1,
                    start: crate::schema::ChecksumStart::Layer,
                    end: ChecksumEnd::Frame,
                    pseudo: PseudoSource::None,
                },
                Derived::Checksum {
                    field: "ck4",
                    at: 4,
                    start: crate::schema::ChecksumStart::Layer,
                    end: ChecksumEnd::Frame,
                    pseudo: PseudoSource::None,
                },
                // Length fixtures at the frame edge: t2 writes its last
                // in-bounds u16 (pos + 2 == len), t3 straddles it (pos + 2
                // > len), t1 straddles it from 1 — the write-width bounds.
                Derived::Length {
                    field: "t2",
                    at: 2,
                    base: crate::schema::LengthBase::LayerStart,
                    units: crate::schema::LengthUnits::Bytes,
                },
                Derived::Length {
                    field: "t3",
                    at: 3,
                    base: crate::schema::LengthBase::LayerStart,
                    units: crate::schema::LengthUnits::Bytes,
                },
                Derived::Length {
                    field: "t1",
                    at: 1,
                    base: crate::schema::LengthBase::LayerStart,
                    units: crate::schema::LengthUnits::Bytes,
                },
            ]
        }
    }

    #[test]
    fn recompute_bounds_are_pointed_at_the_frame_edge() {
        let mut reg = Registry::default();
        reg.register(&MockBad);
        let dissected = |n: usize| {
            let bytes = vec![0u8; n];
            crate::dissect::dissect(&reg, &bytes, "mockbad")
        };
        // frame 2: ck@pos1 → 3 > 2 → OutOfBounds (and `&&` mutants
        // turn every bound into a no-op → a silent Ok, which is worse).
        let p = dissected(2);
        assert!(matches!(
            patch(&reg, &p, &[], &Scope::all()).unwrap_err(),
            PatchError::OutOfBounds { .. }
        ));
        // frame 3: ck@pos1 → 3 > 3 is false: the exact boundary is OK
        // (scoped to ck alone so ck4 does not error first).
        let p3 = dissected(3);
        let scope = Scope::select(&["mockbad.ck"]).expect("scope");
        let out = patch(&reg, &p3, &[], &scope).expect("boundary checksum");
        assert_eq!(out.len(), 3);
        // frame 5: ck4@pos4 → 6 > 5 → Err (and `pos − 2 > len` is the
        // alias that must NOT trigger here).
        let p5 = dissected(5);
        let scope4 = Scope::select(&["mockbad.ck4"]).expect("scope");
        assert!(matches!(
            patch(&reg, &p5, &[], &scope4).unwrap_err(),
            PatchError::OutOfBounds { .. }
        ));
        // frame 6: ck4@pos4 → 6 > 6 is false: in bounds.
        let p6 = dissected(6);
        let out6 = patch(&reg, &p6, &[], &scope4).expect("boundary ck4");
        assert_eq!(out6.len(), 6);
    }

    /// The derived-length write bounds (`pos + 2 > frame.len()`) at the
    /// frame edge: the last in-bounds u16 window (pos + 2 == len) writes;
    /// past it (pos + 2 > len) is the pointed error.
    #[test]
    fn derived_length_write_bounds_at_frame_edge() {
        let mut reg = Registry::default();
        reg.register(&MockBad);
        // frame 4, t2@pos2 → 4 > 4 false: writes the last window.
        let p4 = crate::dissect::dissect(&reg, &[0u8; 4], "mockbad");
        let s2 = Scope::select(&["mockbad.t2"]).expect("scope");
        let out = patch(&reg, &p4, &[], &s2).expect("boundary length");
        // covered = frame 4 − layer start 0 = 4 (u16 BE).
        assert_eq!(&out[2..4], &4u16.to_be_bytes()[..]);
        // frame 4, t3@pos3 → 5 > 4 → Err.
        let s3 = Scope::select(&["mockbad.t3"]).expect("scope");
        assert!(matches!(
            patch(&reg, &p4, &[], &s3).unwrap_err(),
            PatchError::OutOfBounds { .. }
        ));
        // frame 2, t1@pos1 → 1 + 2 = 3 > 2 → Err (and `pos − 2 > len`
        // never underflow-errors here: pos ≥ 1).
        let p2 = crate::dissect::dissect(&reg, &[0u8; 2], "mockbad");
        let s1 = Scope::select(&["mockbad.t1"]).expect("scope");
        assert!(matches!(
            patch(&reg, &p2, &[], &s1).unwrap_err(),
            PatchError::OutOfBounds { .. }
        ));
    }

    /// Tranche 13a: a `ReEncode` span routes through the codec hook —
    /// the codec serializes the value into the region replacement
    /// (here: NUL padding, the dhcp sname/file rule).
    #[test]
    fn reencode_hook_applies_and_rejects_pointedly() {
        let reg = reg();
        let p = frame();
        // `re` spans 7..9 (the "dead" payload): [0x41] pads to [41 00].
        let out = patch(
            &reg,
            &p,
            &[Edit::SetField {
                path: "mock.re".to_string(),
                bytes: Bytes::from_static(&[0x41]),
            }],
            &Scope::none(),
        )
        .expect("patch");
        assert_eq!(&out[7..9], &[0x41, 0x00]);
        assert_eq!(&out[..7], &[0x11, 0x11, 0x00, 0x09, 0x00, 0x00, 0x20]);

        // Over-length value: the hook's pointed rejection.
        let err = patch(
            &reg,
            &p,
            &[Edit::SetField {
                path: "mock.re".to_string(),
                bytes: Bytes::from_static(&[1, 2, 3]),
            }],
            &Scope::none(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::ReEncodeFailed { .. }), "{err}");

        // An unhooked ReEncode field: the default `None` → the pointed
        // deferral (mocks and dynamic codecs inherit).
        let err = patch(
            &reg,
            &p,
            &[Edit::SetField {
                path: "mock.rn".to_string(),
                bytes: Bytes::from_static(&[0, 0]),
            }],
            &Scope::none(),
        )
        .unwrap_err();
        assert!(matches!(err, PatchError::UnsupportedPath(_)), "{err}");
    }

    // --- Kani proofs (registry-level splice geometry) -------------------
    //
    // RETIRED (measured): `patch()` drives the full dissect engine
    // (the codec registry walk + BTreeMap fields + serde values), and
    // the solver state for even one concrete registry blows past the
    // 6GB CBMC ceiling — the `decode_name` retirement class (see
    // roadmap T4). The engine-level geometry is carried instead by:
    // the units in this mod, `crates/wrex/tests/patch_engine.rs` (the
    // population gate over every corpus frame),
    // `crates/wrex/tests/patch_sweep.rs` (256 proptest cases),
    // and the `fuzz_patch_engine` target. The *provable* core — the
    // bit-window mask arithmetic (`write_bits_window`) — is formally
    // covered in `mod kani_proofs` (pure functions, cheap solver
    // state; verified under the same ceiling).
}
