//! The recipe JSON schema: a fully materialized, deterministic
//! request description for `wrex http --recipe FILE`.
//!
//! Design notes:
//! - headers are an **ordered** `[name, value]` array (not a map) so
//!   wire bytes are reproducible and the format stays list-shaped for
//!   T6's mutation strategies;
//! - `body_hex` and `body_text` are mutually exclusive (exactly one or
//!   neither);
//! - the schema is input-only at T4 (no serialization), parsed by the
//!   CLI via serde_json and validated here.

use bytes::Bytes;

use crate::request::HttpRequestSpec;

/// Runtime knobs a recipe may override.
#[derive(Clone, Debug, Default)]
pub struct RecipeOverrides {
    pub timeout_ms: Option<u64>,
    pub retries: Option<u32>,
    pub max_bytes: Option<u64>,
    /// Accept any TLS certificate (https urls only; default false).
    pub tls_insecure: Option<bool>,
    /// Extra CA bundle path (https urls only; complements system roots).
    pub tls_ca: Option<String>,
    /// HTTP version for https urls: `1.1` (default) or `2` (tranche
    /// 15: ALPN `h2`, concurrent streams on one connection).
    pub http_version: Option<String>,
    /// Send-side HPACK policy for h2 (tranche 16a): `indexed`
    /// (default: dynamic table + Huffman-when-strictly-shorter) or
    /// `literal` (the T15 wire bytes verbatim).
    pub hpack: Option<String>,
    /// Follow 3xx redirects (tranche 19a; recipe wins over `--follow`).
    pub follow: Option<bool>,
    /// Redirect hop budget under `follow` (default 50, curl's).
    pub max_redirs: Option<u32>,
    /// Basic-auth credentials (tranche 19a; `USER[:PASS]`).
    pub user: Option<String>,
    /// Bearer token (tranche 19a; exclusive with `user`).
    pub bearer: Option<String>,
    /// Answer Digest 401s via the RFC 7616 dance (with `user`).
    pub digest: Option<bool>,
    /// Request/decode compressed content (tranche 19a).
    pub compressed: Option<bool>,
    /// Proxy endpoint (tranche 19b; `[http://|socks5://|socks5h://]HOST:PORT`).
    pub proxy: Option<String>,
    /// Proxy credentials (`USER[:PASS]`).
    pub proxy_user: Option<String>,
}

/// One recipe. Deserialize with serde (the CLI owns the JSON parsing).
#[derive(Clone, Debug, serde::Deserialize)]
pub struct Recipe {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
    pub body_hex: Option<String>,
    pub body_text: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub retries: Option<u32>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
    /// Accept any TLS certificate (https urls; default false).
    #[serde(default)]
    pub tls_insecure: Option<bool>,
    /// Extra CA bundle path, PEM or DER (https urls).
    #[serde(default)]
    pub tls_ca: Option<String>,
    /// HTTP version for https urls: `1.1` (default) or `2` (tranche
    /// 15: ALPN-negotiated h2, concurrent streams per connection).
    #[serde(default)]
    pub http_version: Option<String>,
    /// Send-side HPACK policy for h2 (tranche 16a): `indexed`
    /// (default) or `literal`.
    #[serde(default)]
    pub hpack: Option<String>,
    /// Body wire framing: `length` (default) or `chunked` (tranche 9a).
    #[serde(default)]
    pub body_framing: Option<String>,
    /// Fixed chunk size for `body_framing: "chunked"` (default 4096).
    #[serde(default)]
    pub chunk_size: Option<u64>,
    /// Follow 3xx redirects (tranche 19a; recipe wins over `--follow`).
    #[serde(default)]
    pub follow: Option<bool>,
    /// Redirect hop budget under `follow` (default 50, curl's).
    #[serde(default)]
    pub max_redirs: Option<u32>,
    /// Basic-auth credentials, `USER[:PASS]` (tranche 19a).
    #[serde(default)]
    pub user: Option<String>,
    /// Bearer token (exclusive with `user`).
    #[serde(default)]
    pub bearer: Option<String>,
    /// Answer Digest 401s via the RFC 7616 dance (with `user`).
    #[serde(default)]
    pub digest: Option<bool>,
    /// Request/decode compressed content (tranche 19a).
    #[serde(default)]
    pub compressed: Option<bool>,
    /// Proxy endpoint (tranche 19b).
    #[serde(default)]
    pub proxy: Option<String>,
    /// Proxy credentials.
    #[serde(default)]
    pub proxy_user: Option<String>,
}

impl Recipe {
    /// Parse a recipe **file**: a single recipe object (the T4 shape,
    /// byte-identical), a top-level array, or `{"requests": [...]}` —
    /// the tranche-9a keep-alive queue. The CLI owns nothing but this
    /// entry point.
    pub fn parse_recipes(raw: &str) -> Result<Vec<Recipe>, String> {
        let value: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| format!("bad recipe: {e}"))?;
        match value {
            serde_json::Value::Array(_) => serde_json::from_str::<Vec<Recipe>>(raw)
                .map_err(|e| format!("bad recipe array: {e}")),
            serde_json::Value::Object(_) => {
                if value.get("requests").is_some() {
                    #[derive(serde::Deserialize)]
                    struct File {
                        requests: Vec<Recipe>,
                    }
                    let file: File =
                        serde_json::from_str(raw).map_err(|e| format!("bad recipe file: {e}"))?;
                    if file.requests.is_empty() {
                        return Err("recipe file: `requests` is empty".to_string());
                    }
                    Ok(file.requests)
                } else {
                    Ok(vec![
                        serde_json::from_str::<Recipe>(raw)
                            .map_err(|e| format!("bad recipe: {e}"))?,
                    ])
                }
            }
            _ => Err("recipe: expected an object, an array, or {\"requests\": [...]}".to_string()),
        }
    }
    /// Validate and materialize into a request spec + overrides.
    /// All errors are usage-grade (exit 2 in the CLI).
    pub fn into_request(self) -> Result<(HttpRequestSpec, RecipeOverrides), String> {
        if self.body_hex.is_some() && self.body_text.is_some() {
            return Err("recipe: body_hex and body_text are mutually exclusive".to_string());
        }
        let body = if let Some(hex) = self.body_hex {
            parse_hex(&hex).map_err(|e| format!("recipe: bad body_hex: {e}"))?
        } else if let Some(text) = self.body_text {
            Bytes::from(text.into_bytes())
        } else {
            Bytes::new()
        };
        let header_refs: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let spec = HttpRequestSpec::build(&self.method, &self.url, &header_refs, body)?;
        if self.method.trim().is_empty() {
            return Err("recipe: empty method".to_string());
        }
        let spec = match self.body_framing.as_deref() {
            None => spec,
            Some("length") => spec,
            Some("chunked") => {
                let size = self
                    .chunk_size
                    .unwrap_or(crate::request::DEFAULT_CHUNK_SIZE as u64);
                if size == 0 || size > u32::MAX as u64 {
                    return Err(format!(
                        "recipe: chunk_size {size} out of range (1..=u32::MAX)"
                    ));
                }
                spec.with_framing(crate::request::RequestFraming::Chunked, size as usize)
            }
            Some(other) => {
                return Err(format!(
                    "recipe: unknown body_framing `{other}` (length|chunked)"
                ));
            }
        };
        if let Some(v) = self.http_version.as_deref()
            && !["1.1", "2"].contains(&v)
        {
            return Err(format!("recipe: unknown http_version `{v}` (1.1|2)"));
        }
        if let Some(v) = self.hpack.as_deref()
            && !["indexed", "literal"].contains(&v)
        {
            return Err(format!("recipe: unknown hpack `{v}` (indexed|literal)"));
        }
        let overrides = RecipeOverrides {
            timeout_ms: self.timeout_ms,
            retries: self.retries,
            max_bytes: self.max_bytes,
            tls_insecure: self.tls_insecure,
            tls_ca: self.tls_ca,
            http_version: self.http_version,
            hpack: self.hpack,
            follow: self.follow,
            max_redirs: self.max_redirs,
            user: self.user,
            bearer: self.bearer,
            digest: self.digest,
            compressed: self.compressed,
            proxy: self.proxy,
            proxy_user: self.proxy_user,
        };
        Ok((spec, overrides))
    }
}

/// Minimal hex decode (no dependency on wrex-core's value grammar).
fn parse_hex(raw: &str) -> Result<Bytes, String> {
    if !raw.len().is_multiple_of(2) {
        return Err("odd length".to_string());
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    let bytes = raw.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = hex_digit(pair[0])?;
        let lo = hex_digit(pair[1])?;
        out.push(hi << 4 | lo);
    }
    Ok(Bytes::from(out))
}

fn hex_digit(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex digit `{}`", b as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipe(json: &str) -> Recipe {
        serde_json::from_str(json).expect("recipe json")
    }

    #[test]
    fn minimal_and_full() {
        let r = recipe(r#"{"method": "GET", "url": "http://example.com/"}"#);
        let (spec, o) = r.into_request().unwrap();
        assert_eq!(spec.method, "GET");
        assert_eq!(spec.url, "http://example.com/");
        assert!(spec.body.is_empty());
        assert!(o.timeout_ms.is_none());

        let r = recipe(
            r#"{
                "method": "POST",
                "url": "http://example.com:8080/api",
                "headers": [["User-Agent", "probe/1"], ["X-A", "1"], ["X-A", "2"]],
                "body_hex": "deadbeef",
                "timeout_ms": 1500,
                "retries": 2,
                "max_bytes": 1024
            }"#,
        );
        let (spec, o) = r.into_request().unwrap();
        assert_eq!(spec.headers.len(), 3);
        assert_eq!(&spec.body[..], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(o.timeout_ms, Some(1500));
        assert_eq!(o.retries, Some(2));
        assert_eq!(o.max_bytes, Some(1024));
        // byte-identical replay
        let wire = spec.serialize().unwrap();
        let r2 = recipe(
            r#"{
                "method": "POST",
                "url": "http://example.com:8080/api",
                "headers": [["User-Agent", "probe/1"], ["X-A", "1"], ["X-A", "2"]],
                "body_hex": "deadbeef",
                "timeout_ms": 1500,
                "retries": 2,
                "max_bytes": 1024
            }"#,
        );
        assert_eq!(r2.into_request().unwrap().0.serialize().unwrap(), wire);
    }

    #[test]
    fn body_conflict_and_bad_values() {
        let r =
            recipe(r#"{"method": "GET", "url": "http://x/", "body_hex": "00", "body_text": "a"}"#);
        assert!(r.into_request().unwrap_err().contains("mutually exclusive"));
        let r = recipe(r#"{"method": "GET", "url": "http://x/", "body_hex": "abc"}"#);
        assert!(r.into_request().unwrap_err().contains("body_hex"));
        let r = recipe(r#"{"method": "GET", "url": "ftp://x/"}"#);
        assert!(
            r.into_request()
                .unwrap_err()
                .contains("unsupported url scheme")
        );
        let r = recipe(r#"{"method": "BOGUS?", "url": "http://x/"}"#);
        assert!(r.into_request().unwrap_err().contains("method"));
    }

    #[test]
    fn tls_fields_are_additive_defaults() {
        // Old recipes (no tls fields) parse with the new defaults — the
        // serde defaults keep the committed files byte-compatible.
        let r = recipe(r#"{"method": "GET", "url": "https://example.com/"}"#);
        let (_, o) = r.into_request().unwrap();
        assert_eq!(o.tls_insecure, None);
        assert_eq!(o.tls_ca, None);
        // New fields: honored into the overrides.
        let r = recipe(
            r#"{"method": "GET", "url": "https://example.com/",
                "tls_insecure": true, "tls_ca": "/etc/ca.pem"}"#,
        );
        let (spec, o) = r.into_request().unwrap();
        assert_eq!(spec.url.scheme_str(), Some("https"));
        assert_eq!(o.tls_insecure, Some(true));
        assert_eq!(o.tls_ca.as_deref(), Some("/etc/ca.pem"));
        // and an https recipe replays byte-identically now
        let wire = spec.serialize().unwrap();
        let r2 = recipe(
            r#"{"method": "GET", "url": "https://example.com/",
                "tls_insecure": true, "tls_ca": "/etc/ca.pem"}"#,
        );
        assert_eq!(r2.into_request().unwrap().0.serialize().unwrap(), wire);
    }

    #[test]
    fn http_version_knob() {
        // default: absent
        let r = recipe(r#"{"method": "GET", "url": "https://example.com/"}"#);
        let (_, o) = r.into_request().unwrap();
        assert_eq!(o.http_version, None);
        assert_eq!(o.hpack, None);
        // tranche 15: "2" rides through
        let r = recipe(r#"{"method": "GET", "url": "https://example.com/", "http_version": "2"}"#);
        let (_, o) = r.into_request().unwrap();
        assert_eq!(o.http_version.as_deref(), Some("2"));
        // tranche 16a: the hpack knob rides through
        let r = recipe(
            r#"{"method": "GET", "url": "https://example.com/", "http_version": "2", "hpack": "literal"}"#,
        );
        let (_, o) = r.into_request().unwrap();
        assert_eq!(o.hpack.as_deref(), Some("literal"));
        // old recipes (pre-T15) parse byte-identically: serde default
        // again; bad values are usage errors
        let r = recipe(r#"{"method": "GET", "url": "https://example.com/", "http_version": "3"}"#);
        assert!(r.into_request().unwrap_err().contains("http_version"));
        let r = recipe(r#"{"method": "GET", "url": "https://example.com/", "hpack": "bogus"}"#);
        assert!(r.into_request().unwrap_err().contains("hpack"));
    }

    // --- tranche 9a --------------------------------------------------------

    #[test]
    fn body_framing_knobs() {
        let r = recipe(
            r#"{"method": "POST", "url": "http://example.com/",
                "body_text": "0123456789", "body_framing": "chunked",
                "chunk_size": 4}"#,
        );
        let (spec, _) = r.into_request().unwrap();
        assert_eq!(spec.framing, crate::request::RequestFraming::Chunked);
        assert_eq!(spec.chunk_size, 4);
        let wire = String::from_utf8(spec.serialize().unwrap().to_vec()).unwrap();
        assert!(wire.ends_with("\r\n\r\n4\r\n0123\r\n4\r\n4567\r\n2\r\n89\r\n0\r\n\r\n"));
        // default chunk size when only framing is set
        let r = recipe(
            r#"{"method": "POST", "url": "http://x/", "body_text": "abc",
                "body_framing": "chunked"}"#,
        );
        let (spec, _) = r.into_request().unwrap();
        assert_eq!(spec.chunk_size, crate::request::DEFAULT_CHUNK_SIZE);
        // bad knob values are usage errors
        let r = recipe(r#"{"method": "GET", "url": "http://x/", "body_framing": "bogus"}"#);
        assert!(r.into_request().unwrap_err().contains("body_framing"));
        let r = recipe(
            r#"{"method": "GET", "url": "http://x/", "body_framing": "chunked", "chunk_size": 0}"#,
        );
        assert!(r.into_request().unwrap_err().contains("chunk_size"));
    }

    #[test]
    fn follow_knobs_are_additive() {
        // Old recipes: no follow fields → the overrides stay None (the
        // serde defaults keep committed files byte-compatible).
        let r = recipe(r#"{"method": "GET", "url": "http://example.com/"}"#);
        let (_, o) = r.into_request().unwrap();
        assert_eq!(o.follow, None);
        assert_eq!(o.max_redirs, None);
        // New knobs ride through.
        let r = recipe(
            r#"{"method": "GET", "url": "http://example.com/",
                "follow": true, "max_redirs": 3}"#,
        );
        let (_, o) = r.into_request().unwrap();
        assert_eq!(o.follow, Some(true));
        assert_eq!(o.max_redirs, Some(3));
    }

    #[test]
    fn auth_knobs_are_additive() {
        // Old recipes: no auth fields → the overrides stay None.
        let r = recipe(r#"{"method": "GET", "url": "http://example.com/"}"#);
        let (_, o) = r.into_request().unwrap();
        assert_eq!(o.user, None);
        assert_eq!(o.bearer, None);
        assert_eq!(o.digest, None);
        // New knobs ride through.
        let r = recipe(
            r#"{"method": "GET", "url": "http://example.com/",
                "user": "u:p", "digest": true}"#,
        );
        let (_, o) = r.into_request().unwrap();
        assert_eq!(o.user.as_deref(), Some("u:p"));
        assert_eq!(o.digest, Some(true));
        let r = recipe(r#"{"method": "GET", "url": "http://example.com/", "bearer": "tok"}"#);
        let (_, o) = r.into_request().unwrap();
        assert_eq!(o.bearer.as_deref(), Some("tok"));
    }

    #[test]
    fn parse_recipes_single_array_and_requests_key() {
        // single object (the T4 shape, still accepted)
        let one = Recipe::parse_recipes(r#"{"method": "GET", "url": "http://a/"}"#).unwrap();
        assert_eq!(one.len(), 1);
        // top-level array
        let arr = Recipe::parse_recipes(
            r#"[{"method": "GET", "url": "http://a/"},
                {"method": "POST", "url": "http://b/", "body_text": "x"}]"#,
        )
        .unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[1].method, "POST");
        // {"requests": [...]}
        let file =
            Recipe::parse_recipes(r#"{"requests": [{"method": "GET", "url": "http://a/"}]}"#)
                .unwrap();
        assert_eq!(file.len(), 1);
        // empty queue / non-object are usage errors
        assert!(
            Recipe::parse_recipes(r#"{"requests": []}"#)
                .unwrap_err()
                .contains("empty")
        );
        assert!(
            Recipe::parse_recipes("42")
                .unwrap_err()
                .contains("expected")
        );
        // every parsed recipe materializes
        for r in arr {
            r.into_request().unwrap();
        }
    }
}
