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
}

impl Recipe {
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
        let overrides = RecipeOverrides {
            timeout_ms: self.timeout_ms,
            retries: self.retries,
            max_bytes: self.max_bytes,
            tls_insecure: self.tls_insecure,
            tls_ca: self.tls_ca,
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
}
