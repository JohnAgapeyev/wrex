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
            // Tranche 17a: UpperPacket starts at the net layer's
            // recorded upper-layer packet (the v6 ext headers count
            // into the L4 checksum, RFC 8200 §8.1); Layer is the
            // layer's own span. Equal on every ext-free stack.
            let start = match start_sel {
                crate::schema::ChecksumStart::Layer => layer.span.start,
                crate::schema::ChecksumStart::UpperPacket => {
                    fresh.facts.upper_start.unwrap_or(layer.span.start)
                }
            };
            let stop = match end {
                ChecksumEnd::Frame => frame.len(),
                ChecksumEnd::Layer => layer.span.end,
            };
            let pos = layer.span.start + at;
            if stop > frame.len() || pos + 2 > frame.len() || start >= stop || pos < start {
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
