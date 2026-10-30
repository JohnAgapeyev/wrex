#![forbid(unsafe_code)]
//! wrex-http: the HTTP/1.1 client session (tranche 4) — sans-IO over
//! the frozen [`wrex_session::Session`] contract, on an httparse
//! substrate with `http`-crate types.
//!
//! Layout:
//! - [`request`]: [`HttpRequestSpec`] + deterministic wire
//!   serialization (headers in spec order; auto Host/User-Agent/
//!   Accept/Connection/Content-Length with explicit-wins semantics).
//! - [`chunked`]: the chunked-body framing decoder — standalone and
//!   pure so the Kani harness can prove it panic-free for all bounded
//!   inputs.
//! - [`response`]: [`HttpResponse`] + the head/trailer parsers.
//! - [`session`]: [`HttpClientSession`] — one request per connection
//!   (close-mode): send → status → headers → body
//!   {content-length | chunked | until-close} → done. Orderly EOF
//!   arrives as an empty frame (the `TcpDriver` stream convention).
//! - [`recipe`]: the committed JSON recipe schema (byte-identical
//!   replay; list-shaped for T6 mutation).
//! - [`cookies`]: the RFC 6265 cookie jar + the Netscape file format
//!   (tranche 19a; `-b`/`-c`).
//! - [`redirect`]: 3xx classification + RFC 3986 `Location`
//!   resolution (tranche 19a; the verb drives the re-issue).
//!
//! Deliberate T4 deferrals (documented in the verb help): keep-alive
//! (one exchange per connection), chunked *request* bodies
//! (Transfer-Encoding is rejected), multi-connection pipelining.
//! TLS closed its tranche-4 deferral at T8a: `https://` urls parse and
//! serialize like `http://` (transport-agnostic), the rustls-backed
//! driver living in the `wrex-tls` crate.

pub mod cookies;
pub mod recipe;
pub mod redirect;
pub mod request;
pub mod response;
pub mod session;

mod chunked;

pub use cookies::{Cookie, CookieJar};
pub use http;
pub use recipe::Recipe;
pub use redirect::Redirect;
pub use request::{DEFAULT_CHUNK_SIZE, HttpRequestSpec, RequestFraming};
pub use response::HttpResponse;
pub use session::{HttpClientSession, HttpConfig, HttpOutcome};

/// Wire form of a response body framing mode (docs/diagnostics).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyFraming {
    /// Exactly N bytes.
    ContentLength,
    /// RFC 9112 chunked framing with an optional trailer section.
    Chunked,
    /// Read until the connection closes.
    UntilClose,
    /// No body at all (HEAD / 1xx / 204 / 304).
    None,
}
