//! Request construction and deterministic wire serialization.
//!
//! The spec is fully materialized before the session starts: same
//! spec ⇒ byte-identical wire bytes (recipe replay), with explicit
//! user headers winning over every derived default, in spec order.

use std::str::FromStr;

use bytes::{BufMut, Bytes, BytesMut};

/// One fully-resolved HTTP/1.1 request.
#[derive(Clone, Debug)]
pub struct HttpRequestSpec {
    pub method: http::Method,
    /// Absolute `http://` URI (`https` is out of charter).
    pub url: http::Uri,
    /// User-supplied headers, in order (serialization preserves it).
    pub headers: Vec<(http::HeaderName, http::HeaderValue)>,
    pub body: Bytes,
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
        // enforcement point for actual sends).
        match url.scheme_str() {
            Some("http") => {}
            Some("https") => {
                return Err(
                    "https:// requires TLS, which is out of the tranche-4 charter \
                     (wrex http speaks http:// only)"
                        .to_string(),
                );
            }
            Some(other) => return Err(format!("unsupported url scheme `{other}`")),
            None => return Err("url needs an http:// scheme".to_string()),
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
        })
    }

    /// Serialize to HTTP/1.1 wire bytes.
    pub fn serialize(&self) -> Result<Bytes, String> {
        // Scheme gate: https is out of charter with a pointed message.
        match self.url.scheme_str() {
            Some("http") => {}
            Some("https") => {
                return Err(
                    "https:// requires TLS, which is out of the tranche-4 charter \
                     (wrex http speaks http:// only)"
                        .to_string(),
                );
            }
            Some(other) => return Err(format!("unsupported url scheme `{other}`")),
            None => return Err("url needs an http:// scheme".to_string()),
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
        // Chunked requests are a documented deferral; reject loudly
        // rather than silently mis-framing a body.
        if has("transfer-encoding") {
            return Err("Transfer-Encoding on requests is unsupported at tranche 4 \
                 (send a Content-Length body)"
                .to_string());
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
            put_header(&mut buf, "Connection", "close");
        }
        if !self.body.is_empty() && !has("content-length") {
            put_header(&mut buf, "Content-Length", &self.body.len().to_string());
        }
        buf.put_slice(b"\r\n");
        buf.put_slice(&self.body);
        Ok(buf.freeze())
    }
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
    fn https_is_pointed_error() {
        let err =
            HttpRequestSpec::build("GET", "https://example.com/", &[], Bytes::new()).unwrap_err();
        assert!(err.contains("out of the tranche-4 charter"), "{err}");
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
