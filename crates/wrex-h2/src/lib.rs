#![forbid(unsafe_code)]
//! wrex-h2: HTTP/2 (RFC 9113) — the T15 tranche. ADR 2 disposition
//! recorded at the T15 planning pass: the binary framing layer and
//! HPACK are **owned** (byte control over the wire is the point); the
//! session semantics are an owned sans-IO state machine (the T2/T4/T9
//! house pattern — the `h2` crate stays the oracle, never the
//! dependency); TLS stays delegated to rustls via the `wrex-tls`
//! adapter (T8a), which now negotiates ALPN.
//!
//! Layout:
//! - [`frame`]: the 9-octet frame header codec, the committed frame
//!   types with per-type flag grammar, settings payloads, preface.
//! - [`huffman`]: the RFC 7541 appendix B static Huffman code,
//!   decode side only (encode is a deliberate deferral).
//! - [`hpack`]: HPACK (RFC 7541) — full decode grammar, deterministic
//!   literal-only encode (no Huffman, no dynamic-table state on send).
//! - [`session`]: [`H2Session`] — one connection, N concurrent
//!   streams, flow-control-gated DATA, one [`wrex_http::HttpOutcome`]
//!   per queued request, over the frozen [`wrex_session::Session`]
//!   contract.
//!
//! Verification (the RFC-vector lineage — an owned codec's oracle is
//! the spec): RFC 7541 appendix C known-answer vectors (integers,
//! literals, indexed fields, the C.3/C.4 request sequences, the
//! C.5/C.6 response sequences with eviction and Huffman), RFC 9113
//! frame-header shape vectors, `fuzz_h2_frame_decoder` +
//! `fuzz_hpack` + `fuzz_h2_session` cargo-fuzz targets in the
//! extended-verification gate, and CLI ground truth against the
//! in-test rustls+ALPN h2 stub (`wrex_test::h2_stub`).
//!
//! Deliberate T15 deferrals: Huffman *encode*, HPACK incremental
//! indexing on the send side, h2c/prior-knowledge cleartext (`wrex
//! http --http-version 2` requires https + ALPN), extended CONNECT,
//! server push handling (never enabled), and the HTTP/2 server role.

pub mod frame;
pub mod hpack;
pub mod huffman;
pub mod session;

/// Default identity header value (the 1.1 serializer's rule).
pub const DEFAULT_USER_AGENT: &str = "wrex/0.1.0";

pub use frame::{
    DEFAULT_MAX_FRAME, DEFAULT_WINDOW, FrameHeader, FrameStep, FrameType, HEADER_LEN, PREFACE,
};
pub use hpack::{HpackDecoder, STATIC_TABLE};
pub use session::{H2Session, MAX_STREAMS};
