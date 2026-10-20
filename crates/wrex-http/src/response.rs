//! The response model plus the head (status + headers) and trailer
//! parsers on the httparse substrate.

use bytes::Bytes;

use crate::chunked::{ChunkHeader, parse_chunk_header};

/// One parsed response. `http`-typed where the crate has vocabulary
/// (status, version, headers); the reason phrase rides alongside
/// because `http::Response` does not carry one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: http::StatusCode,
    pub reason: String,
    pub version: http::Version,
    pub headers: http::HeaderMap,
    pub body: Bytes,
}

impl HttpResponse {
    /// Body framing implied by the status/method and head headers.
    /// (`request_method` = HEAD ⇒ no body regardless of framing.)
    pub fn framing(&self, request_method: &http::Method) -> crate::BodyFraming {
        if is_informational(self.status.as_u16()) {
            return crate::BodyFraming::None;
        }
        if *request_method == http::Method::HEAD
            || self.status == http::StatusCode::NO_CONTENT
            || self.status == http::StatusCode::NOT_MODIFIED
        {
            return crate::BodyFraming::None;
        }
        if self
            .headers
            .get("transfer-encoding")
            .is_some_and(|v| v.to_str().is_ok_and(|v| v.eq_ignore_ascii_case("chunked")))
        {
            return crate::BodyFraming::Chunked;
        }
        if self.headers.contains_key("content-length") {
            return crate::BodyFraming::ContentLength;
        }
        crate::BodyFraming::UntilClose
    }

    /// Content-Length value, if present and parseable.
    pub fn content_length(&self) -> Option<Result<u64, String>> {
        let raw = self.headers.get("content-length")?;
        let raw = raw
            .to_str()
            .map_err(|_| "non-ASCII content-length".to_string())
            .ok()?
            .trim();
        if raw.is_empty() {
            return Some(Err("empty content-length".to_string()));
        }
        match raw.parse::<u64>() {
            Ok(n) => Some(Ok(n)),
            Err(_) => Some(Err(format!("bad content-length `{raw}`"))),
        }
    }
}

/// 1xx: informational (the session skips these and keeps reading).
pub(crate) fn is_informational(code: u16) -> bool {
    (100..200).contains(&code)
}

/// One step of head parsing (status line + headers together, as
/// httparse drives them).
#[derive(Debug)]
pub(crate) enum HeadStep {
    NeedMore,
    Head {
        consumed: usize,
        code: u16,
        reason: String,
        version: http::Version,
        headers: http::HeaderMap,
    },
    Malformed(String),
}

/// Parse a response head (status line + header section) from `buf`.
/// httparse borrows `buf`; Complete results are copied out before the
/// caller advances the buffer.
pub(crate) fn parse_head(buf: &[u8]) -> HeadStep {
    let mut capacity = 64usize;
    loop {
        let mut headers: Vec<httparse::Header<'_>> = (0..capacity)
            .map(|_| httparse::Header {
                name: "",
                value: &[],
            })
            .collect();
        let mut resp = httparse::Response::new(&mut headers);
        match resp.parse(buf) {
            Ok(httparse::Status::Complete(consumed)) => {
                // httparse 1.10: fields are Option (set on Complete).
                let Some(code) = resp.code else {
                    return HeadStep::Malformed("missing status code".to_string());
                };
                let reason = resp.reason.unwrap_or("").to_string();
                let version = match resp.version {
                    Some(0) => http::Version::HTTP_10,
                    Some(1) => http::Version::HTTP_11,
                    Some(other) => {
                        return HeadStep::Malformed(format!("unsupported HTTP version {other}"));
                    }
                    None => return HeadStep::Malformed("missing HTTP version".to_string()),
                };
                let mut map = http::HeaderMap::new();
                for h in resp.headers.iter() {
                    let name = match http::HeaderName::from_bytes(h.name.as_bytes()) {
                        Ok(n) => n,
                        Err(_) => {
                            return HeadStep::Malformed(format!(
                                "bad response header name `{}`",
                                h.name
                            ));
                        }
                    };
                    let value = match http::HeaderValue::from_bytes(h.value) {
                        Ok(v) => v,
                        Err(_) => {
                            return HeadStep::Malformed(format!(
                                "bad response header value for `{}`",
                                h.name
                            ));
                        }
                    };
                    map.append(name, value);
                }
                return HeadStep::Head {
                    consumed,
                    code,
                    reason,
                    version,
                    headers: map,
                };
            }
            Ok(httparse::Status::Partial) => return HeadStep::NeedMore,
            Err(httparse::Error::TooManyHeaders) => {
                // Grow the scratch and retry (bounded: headers beyond a
                // couple hundred are hostile data).
                if capacity >= 512 {
                    return HeadStep::Malformed("too many response headers".to_string());
                }
                capacity *= 2;
                continue;
            }
            Err(e) => return HeadStep::Malformed(format!("malformed response head: {e}")),
        }
    }
}

/// One step of chunked-data parsing: header + payload + trailing CRLF.
#[derive(Debug)]
pub(crate) enum ChunkStep {
    NeedMore,
    /// A data chunk fully present in `buf`.
    Data {
        consumed: usize,
        size: usize,
    },
    /// The last chunk; the trailer section follows.
    Last {
        consumed: usize,
    },
    Malformed(String),
}

pub(crate) fn parse_chunk_data(buf: &[u8]) -> ChunkStep {
    match parse_chunk_header(buf) {
        ChunkHeader::NeedMore => ChunkStep::NeedMore,
        ChunkHeader::Invalid => ChunkStep::Malformed("bad chunk header".to_string()),
        ChunkHeader::Last { len } => ChunkStep::Last { consumed: len },
        ChunkHeader::Chunk { size, len } => {
            let Ok(size) = usize::try_from(size) else {
                return ChunkStep::Malformed("chunk too large for the platform".to_string());
            };
            // Overflow-safe end (a lying chunk size must not panic).
            let Some(end) = len.checked_add(size).and_then(|e| e.checked_add(2)) else {
                return ChunkStep::Malformed("chunk size overflows".to_string());
            };
            if buf.len() < end {
                return ChunkStep::NeedMore;
            }
            if &buf[len + size..len + size + 2] != b"\r\n" {
                return ChunkStep::Malformed("missing chunk data CRLF".to_string());
            }
            ChunkStep::Data {
                consumed: end,
                size,
            }
        }
    }
}

/// One step of trailer-section parsing: `*( field-line CRLF ) CRLF`.
/// Trailer headers are merged into the response header map (with their
/// own names; duplicates possible, HeaderMap appends).
#[derive(Debug)]
pub(crate) enum TrailersStep {
    NeedMore,
    Done {
        consumed: usize,
        headers: Vec<(String, String)>,
    },
    Malformed(String),
}

/// Trailer sections beyond this are hostile data, not "need more".
const MAX_TRAILERS_BYTES: usize = 8 * 1024;

pub(crate) fn parse_trailers(buf: &[u8]) -> TrailersStep {
    // Zero trailers: the section is just the final CRLF.
    if buf.starts_with(b"\r\n") {
        return TrailersStep::Done {
            consumed: 2,
            headers: Vec::new(),
        };
    }
    let Some(end) = find_double_crlf(buf) else {
        if buf.len() > MAX_TRAILERS_BYTES {
            return TrailersStep::Malformed("trailer section too long".to_string());
        }
        return TrailersStep::NeedMore;
    };
    let section = &buf[..end + 2]; // the trailer lines, final CRLF included
    let mut headers = Vec::new();
    for line in section.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue; // the final CRLF
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return TrailersStep::Malformed("trailer line without a colon".to_string());
        };
        let name = String::from_utf8_lossy(&line[..colon]).trim().to_string();
        let value = String::from_utf8_lossy(&line[colon + 1..])
            .trim()
            .to_string();
        if name.is_empty() {
            return TrailersStep::Malformed("empty trailer name".to_string());
        }
        headers.push((name, value));
    }
    TrailersStep::Done {
        consumed: end + 4,
        headers,
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}
