//! Request construction and deterministic wire serialization.
//!
//! The spec is fully materialized before the session starts: same
//! spec ⇒ byte-identical wire bytes (recipe replay), with explicit
//! user headers winning over every derived default, in spec order.

use std::str::FromStr;

use bytes::{BufMut, Bytes, BytesMut};

/// Request body wire framing (tranche 9a).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RequestFraming {
    /// `Content-Length` framing (the default; the T4 shape).
    #[default]
    Length,
    /// `Transfer-Encoding: chunked` with a **fixed** chunk size, so
    /// serialization stays deterministic (recipe replay / mutation
    /// substrates pin the exact wire bytes).
    Chunked,
}

/// Default fixed chunk size for [`RequestFraming::Chunked`] bodies.
pub const DEFAULT_CHUNK_SIZE: usize = 4096;

/// One fully-resolved HTTP/1.1 request.
#[derive(Clone, Debug)]
pub struct HttpRequestSpec {
    pub method: http::Method,
    /// Absolute `http(s)://` URI (transport-agnostic; the verb picks
    /// `TcpDriver` vs `wrex_tls::TlsDriver` on the scheme).
    pub url: http::Uri,
    /// User-supplied headers, in order (serialization preserves it).
    pub headers: Vec<(http::HeaderName, http::HeaderValue)>,
    pub body: Bytes,
    /// Body wire framing (length vs chunked; tranche 9a).
    pub framing: RequestFraming,
    /// Fixed chunk size for [`RequestFraming::Chunked`] (deterministic).
    pub chunk_size: usize,
}

/// Default identity header values.
pub const DEFAULT_USER_AGENT: &str = "wrex/0.1.0";

impl HttpRequestSpec {
    /// Parse method/URL/header triples from strings (CLI/recipe paths).
    /// Header names are normalized to lowercase; values are validated
    /// as header bytes.
    #[allow(clippy::type_complexity)]
    pub fn build(
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Bytes,
    ) -> Result<Self, String> {
        let method =
            http::Method::from_str(method).map_err(|e| format!("bad method `{method}`: {e}"))?;
        let url = http::Uri::from_str(url).map_err(|e| format!("bad url `{url}`: {e}"))?;
        // Fail fast on the scheme; serialize() re-checks (it is the
        // enforcement point for actual sends). http and https both
        // pass: serialization stays transport-agnostic, the https
        // transport (tranche 8a) is chosen by the verb on this gate.
        match url.scheme_str() {
            Some("http") | Some("https") => {}
            Some(other) => return Err(format!("unsupported url scheme `{other}`")),
            None => return Err("url needs an http:// or https:// scheme".to_string()),
        }
        let mut parsed = Vec::with_capacity(headers.len());
        for (name, value) in headers {
            let name = http::HeaderName::from_str(name)
                .map_err(|e| format!("bad header name `{name}`: {e}"))?;
            let value = http::HeaderValue::from_str(value)
                .map_err(|e| format!("bad header value for `{name}`: {e}"))?;
            parsed.push((name, value));
        }
        Ok(Self {
            method,
            url,
            headers: parsed,
            body,
            framing: RequestFraming::Length,
            chunk_size: DEFAULT_CHUNK_SIZE,
        })
    }

    /// Set the body wire framing (recipe `body_framing`/`chunk_size`).
    pub fn with_framing(mut self, framing: RequestFraming, chunk_size: usize) -> Self {
        self.framing = framing;
        self.chunk_size = chunk_size;
        self
    }

    /// Serialize to HTTP/1.1 wire bytes (close-mode: `Connection: close`,
    /// the T4 shape).
    pub fn serialize(&self) -> Result<Bytes, String> {
        self.serialize_connection(false)
    }

    /// Serialize with the `Connection` header the caller picked
    /// (keep-alive queues pass `true` for every request but the last).
    pub fn serialize_connection(&self, keep_alive: bool) -> Result<Bytes, String> {
        // Scheme gate: http and https serialize identically (the https
        // transport lives verb-side in wrex-tls); everything else is a
        // pointed usage error.
        match self.url.scheme_str() {
            Some("http") | Some("https") => {}
            Some(other) => return Err(format!("unsupported url scheme `{other}`")),
            None => return Err("url needs an http:// or https:// scheme".to_string()),
        }
        let authority = self
            .url
            .authority()
            .ok_or_else(|| "url has no host (authority)".to_string())?
            .as_str();
        let target = self
            .url
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());

        let has = |name: &str| self.headers.iter().any(|(n, _)| n.as_str() == name);
        // An explicit Transfer-Encoding always conflicts: the framing
        // knob owns the header (chunked) or rejects it (length).
        if has("transfer-encoding") {
            return Err(
                "Transfer-Encoding on requests is owned by the body framing knob \
                 (body_framing: chunked); remove the explicit header"
                    .to_string(),
            );
        }

        let mut buf = BytesMut::new();
        buf.put_slice(self.method.as_str().as_bytes());
        buf.put_u8(b' ');
        buf.put_slice(target.as_bytes());
        buf.put_slice(b" HTTP/1.1\r\n");

        // User headers first, in spec order.
        for (name, value) in &self.headers {
            buf.put_slice(name.as_str().as_bytes());
            buf.put_slice(b": ");
            buf.put_slice(value.as_bytes());
            buf.put_slice(b"\r\n");
        }
        // Derived defaults only where the user did not speak.
        if !has("host") {
            put_header(&mut buf, "Host", authority);
        }
        if !has("user-agent") {
            put_header(&mut buf, "User-Agent", DEFAULT_USER_AGENT);
        }
        if !has("accept") {
            put_header(&mut buf, "Accept", "*/*");
        }
        if !has("connection") {
            put_header(
                &mut buf,
                "Connection",
                if keep_alive { "keep-alive" } else { "close" },
            );
        }
        match self.framing {
            RequestFraming::Length => {
                if !self.body.is_empty() && !has("content-length") {
                    put_header(&mut buf, "Content-Length", &self.body.len().to_string());
                }
                buf.put_slice(b"\r\n");
                buf.put_slice(&self.body);
            }
            // Fixed-size chunks (never size-adaptive) so the same spec
            // replays byte-identically.
            RequestFraming::Chunked => {
                put_header(&mut buf, "Transfer-Encoding", "chunked");
                buf.put_slice(b"\r\n");
                put_chunked(&mut buf, &self.body, self.chunk_size);
            }
        }
        Ok(buf.freeze())
    }
}

/// RFC 9112 §7.1 chunked encoding with a **fixed** chunk size.
fn put_chunked(buf: &mut BytesMut, body: &[u8], chunk_size: usize) {
    let size = chunk_size.max(1);
    for piece in body.chunks(size) {
        buf.put_slice(format!("{:x}", piece.len()).as_bytes());
        buf.put_slice(b"\r\n");
        buf.put_slice(piece);
        buf.put_slice(b"\r\n");
    }
    buf.put_slice(b"0\r\n\r\n");
}

fn put_header(buf: &mut BytesMut, name: &str, value: &str) {
    buf.put_slice(name.as_bytes());
    buf.put_slice(b": ");
    buf.put_slice(value.as_bytes());
    buf.put_slice(b"\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_get() {
        let spec =
            HttpRequestSpec::build("GET", "http://example.com/a?b=1", &[], Bytes::new()).unwrap();
        let wire = spec.serialize().unwrap();
        assert_eq!(
            std::str::from_utf8(&wire).unwrap(),
            "GET /a?b=1 HTTP/1.1\r\n\
             Host: example.com\r\n\
             User-Agent: wrex/0.1.0\r\n\
             Accept: */*\r\n\
             Connection: close\r\n\
             \r\n"
        );
    }

    #[test]
    fn explicit_headers_win_and_keep_order() {
        let spec = HttpRequestSpec::build(
            "POST",
            "http://example.com:8080/x",
            &[
                ("User-Agent", "custom-agent"),
                ("X-First", "1"),
                ("content-length", "4"), // explicit CL wins (deliberately-invalid is a feature)
                ("X-Second", "2"),
            ],
            Bytes::from_static(b"abcd"),
        )
        .unwrap();
        let wire = String::from_utf8(spec.serialize().unwrap().to_vec()).unwrap();
        assert!(wire.starts_with("POST /x HTTP/1.1\r\n"));
        // user headers in spec order first…
        let first_lines: Vec<&str> = wire.split("\r\n").take(5).collect();
        assert_eq!(first_lines[1], "user-agent: custom-agent");
        assert_eq!(first_lines[2], "x-first: 1");
        assert_eq!(first_lines[3], "content-length: 4");
        assert_eq!(first_lines[4], "x-second: 2");
        // …then derived defaults, skipping the ones the user set
        assert!(!wire.contains("User-Agent: wrex/0.1.0"));
        assert!(!wire.contains("Content-Length: 4"));
        assert!(wire.contains("Host: example.com:8080"));
        assert!(wire.contains("Connection: close"));
        assert!(wire.ends_with("\r\n\r\nabcd"));
    }

    #[test]
    fn https_is_accepted_and_transport_agnostic() {
        // Same wire bytes for http and https: serialization never sees
        // the transport (the https driver is chosen verb-side).
        let https =
            HttpRequestSpec::build("GET", "https://example.com/", &[], Bytes::new()).unwrap();
        let http = HttpRequestSpec::build("GET", "http://example.com/", &[], Bytes::new()).unwrap();
        assert_eq!(https.serialize().unwrap(), http.serialize().unwrap());
    }

    #[test]
    fn other_schemes_are_pointed_errors() {
        for url in ["ftp://example.com/", "example.com"] {
            let err = HttpRequestSpec::build("GET", url, &[], Bytes::new()).unwrap_err();
            assert!(
                err.contains("unsupported url scheme") || err.contains("needs an http"),
                "{url}: {err}"
            );
        }
    }

    #[test]
    fn transfer_encoding_rejected() {
        let spec = HttpRequestSpec::build(
            "POST",
            "http://example.com/",
            &[("Transfer-Encoding", "chunked")],
            Bytes::new(),
        )
        .unwrap();
        assert!(spec.serialize().unwrap_err().contains("Transfer-Encoding"));
    }

    #[test]
    fn chunked_request_body_golden() {
        // 10-byte body, chunk size 4 → chunks 4/4/2 then the last chunk.
        let spec = HttpRequestSpec::build(
            "POST",
            "http://example.com/",
            &[],
            Bytes::from_static(b"0123456789"),
        )
        .unwrap()
        .with_framing(RequestFraming::Chunked, 4);
        let wire = String::from_utf8(spec.serialize().unwrap().to_vec()).unwrap();
        assert!(
            wire.contains("Transfer-Encoding: chunked\r\n"),
            "framing header derives: {wire}"
        );
        assert!(!wire.contains("Content-Length"), "{wire}");
        assert!(wire.ends_with("\r\n\r\n4\r\n0123\r\n4\r\n4567\r\n2\r\n89\r\n0\r\n\r\n"));
        // An empty chunked body is just the last chunk.
        let empty = HttpRequestSpec::build("POST", "http://example.com/", &[], Bytes::new())
            .unwrap()
            .with_framing(RequestFraming::Chunked, 4);
        let wire = String::from_utf8(empty.serialize().unwrap().to_vec()).unwrap();
        assert!(wire.ends_with("\r\n\r\n0\r\n\r\n"));
    }

    #[test]
    fn keepalive_header_and_determinism() {
        let spec = HttpRequestSpec::build("GET", "http://example.com/", &[], Bytes::new())
            .unwrap()
            .with_framing(RequestFraming::Chunked, 8);
        let ka = String::from_utf8(spec.serialize_connection(true).unwrap().to_vec()).unwrap();
        assert!(ka.contains("Connection: keep-alive\r\n"), "{ka}");
        // same spec ⇒ byte-identical (recipe replay / mutation substrate)
        assert_eq!(
            spec.serialize_connection(true).unwrap(),
            spec.serialize_connection(true).unwrap()
        );
    }

    #[test]
    fn determinism_same_spec_same_bytes() {
        let build = || {
            HttpRequestSpec::build(
                "GET",
                "http://example.com/",
                &[("X-A", "1"), ("X-B", "2")],
                Bytes::new(),
            )
            .unwrap()
            .serialize()
            .unwrap()
        };
        assert_eq!(build(), build());
    }
}
