//! HTTP authentication (tranche 19a): the `Basic`/`Bearer` header
//! sugar and the RFC 7616 `Digest` 401-dance.
//!
//! ADR-2 reuse: `base64` for Basic, RustCrypto `md-5`/`sha2` for the
//! digest hashes — challenge-response is not wire control. Owned and
//! small: the challenge parser (a quoted-string-aware param list) and
//! the response construction, with the RFC's own vectors as the
//! oracle. Scope: `algorithm` MD5, MD5-sess, SHA-256, SHA-256-sess;
//! `qop=auth` and the legacy no-qop shape; `auth-int` is a pointed
//! rejection (HA2 would need the body hash — recorded deferral).

use md5::Md5;
use sha2::Sha256;

/// The parsed parameters of a `WWW-Authenticate: Digest …` challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub opaque: Option<String>,
    /// The challenge's qop list, verbatim (`auth,auth-int`); `None`
    /// = the legacy shape (RFC 7616 §3.3's backwards compatibility).
    pub qop: Option<String>,
    /// `None` = MD5 (RFC 7616 §3.3's default).
    pub algorithm: Option<String>,
}

/// Find and parse the `Digest` challenge among a `WWW-Authenticate`
/// header's challenges (the header may list several schemes
/// comma-separated; values are quoted strings that may contain
/// commas). `None` = no Digest challenge present.
pub fn parse_digest_challenge(www_authenticate: &str) -> Option<DigestChallenge> {
    for segment in scheme_segments(www_authenticate) {
        let segment = segment.trim();
        let (scheme, rest) = segment.split_once(char::is_whitespace)?;
        if !scheme.eq_ignore_ascii_case("digest") {
            continue;
        }
        let mut realm = None;
        let mut nonce = None;
        let mut opaque = None;
        let mut qop = None;
        let mut algorithm = None;
        for (key, value) in parse_params(rest) {
            match key.to_ascii_lowercase().as_str() {
                "realm" => realm = Some(value),
                "nonce" => nonce = Some(value),
                "opaque" => opaque = Some(value),
                "qop" => qop = Some(value),
                "algorithm" => algorithm = Some(value),
                _ => {} // unknown params ride along ignored (§3.3)
            }
        }
        return Some(DigestChallenge {
            realm: realm?,
            nonce: nonce?,
            opaque,
            qop,
            algorithm,
        });
    }
    None
}

/// Split a `WWW-Authenticate` header into per-scheme segments: a new
/// segment starts at a comma OUTSIDE quotes whose next non-space
/// word is a known auth-scheme token followed by whitespace (params
/// always carry `=` before any space, scheme tokens never do).
fn scheme_segments(header: &str) -> Vec<&str> {
    const SCHEMES: [&str; 5] = ["basic", "digest", "bearer", "negotiate", "ntlm"];
    let bytes = header.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    let mut quote = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => quote = !quote,
            b',' if !quote => {
                let rest = header[i + 1..].trim_start();
                let word_end = rest
                    .find(|c: char| c.is_whitespace() || c == '=' || c == '"')
                    .unwrap_or(rest.len());
                let word = &rest[..word_end];
                if SCHEMES.iter().any(|s| word.eq_ignore_ascii_case(s)) {
                    out.push(&header[start..i]);
                    start = i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    out.push(&header[start..]);
    out
}

/// Comma-separated `key=value` params where values may be quoted
/// (and contain commas/escapes per RFC 7616 §3.2.1 — the minimal
/// backslash-escape handling).
fn parse_params(raw: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut depth_quote = false;
    let mut piece = String::new();
    let mut escaped = false;
    for c in raw.chars() {
        if escaped {
            piece.push(c);
            escaped = false;
            continue;
        }
        match c {
            '\\' if depth_quote => escaped = true,
            '"' => {
                depth_quote = !depth_quote;
                piece.push(c);
            }
            ',' if !depth_quote => {
                push_param(&mut out, &piece);
                piece.clear();
            }
            _ => piece.push(c),
        }
    }
    push_param(&mut out, &piece);
    out
}

fn push_param(out: &mut Vec<(String, String)>, piece: &str) {
    let piece = piece.trim();
    if piece.is_empty() {
        return;
    }
    match piece.split_once('=') {
        Some((k, v)) => {
            let k = k.trim().to_string();
            let v = v.trim();
            let v = v.strip_prefix('"').unwrap_or(v);
            let v = v.strip_suffix('"').unwrap_or(v);
            out.push((k, unquote_escapes(v)));
        }
        None => out.push((piece.to_string(), String::new())),
    }
}

fn unquote_escapes(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut escaped = false;
    for c in v.chars() {
        if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else {
            out.push(c);
        }
    }
    out
}

/// Hex lowercase MD5.
fn md5_hex(data: &str) -> String {
    use md5::Digest as _;
    let mut h = Md5::new();
    h.update(data.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Hex lowercase SHA-256.
fn sha256_hex(data: &str) -> String {
    use sha2::Digest as _;
    let mut h = Sha256::new();
    h.update(data.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// `user:pass` → `Authorization: Basic <base64>` (curl -u).
pub fn basic_authorization(user: &str, pass: &str) -> String {
    use base64::Engine as _;
    let raw = format!("{user}:{pass}");
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(raw.as_bytes())
    )
}

/// The `Authorization: Digest …` header value for one exchange
/// (RFC 7616 §3.4). `nc` is the request counter in hex-padded form
/// (the caller counts); `cnonce` is caller-supplied so the RFC's own
/// vectors pin the computation (the verb derives a deterministic one
/// — see `deterministic_cnonce`). Errors are pointed: an unsupported
/// algorithm, or a challenge that only offers `auth-int`.
pub fn digest_authorization(
    challenge: &DigestChallenge,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
    nc: u32,
    cnonce: &str,
) -> Result<String, String> {
    let algorithm = challenge.algorithm.as_deref().unwrap_or("MD5");
    let (hash, sess): (fn(&str) -> String, bool) = match algorithm.to_ascii_uppercase().as_str() {
        "MD5" => (md5_hex, false),
        "MD5-SESS" => (md5_hex, true),
        "SHA-256" => (sha256_hex, false),
        "SHA-256-SESS" => (sha256_hex, true),
        other => return Err(format!("unsupported digest algorithm `{other}`")),
    };
    let nc_hex = format!("{nc:08x}");
    // qop: prefer auth; legacy (absent) shape supported; auth-int
    // alone is a pointed rejection (HA2 needs the body hash).
    let qop = match &challenge.qop {
        Some(list) => {
            let has_auth = list
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("auth"));
            let has_int = list
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("auth-int"));
            if !has_auth {
                if has_int {
                    return Err(
                        "digest challenge offers only qop=auth-int (unsupported)".to_string()
                    );
                }
                return Err(format!("unsupported digest qop `{list}`"));
            }
            "auth"
        }
        None => "",
    };
    // HA1 (§3.4.2): H(user:realm:pass), recomputed per-nonce under -sess.
    let mut ha1 = hash(&format!("{username}:{}:{password}", challenge.realm));
    if sess {
        ha1 = hash(&format!("{ha1}:{}:{cnonce}", challenge.nonce));
    }
    // HA2 (§3.4.3): H(method:uri) under qop=auth.
    let ha2 = hash(&format!("{method}:{uri}"));
    // Response (§3.4.4).
    let response = if qop.is_empty() {
        hash(&format!("{ha1}:{}:{ha2}", challenge.nonce))
    } else {
        hash(&format!(
            "{ha1}:{}:{nc_hex}:{cnonce}:{qop}:{ha2}",
            challenge.nonce
        ))
    };
    let mut out = format!(
        "Digest username=\"{username}\", realm=\"{}\", nonce=\"{}\", uri=\"{uri}\", algorithm={algorithm}",
        challenge.realm, challenge.nonce
    );
    if !qop.is_empty() {
        out.push_str(&format!(", qop={qop}, nc={nc_hex}, cnonce=\"{cnonce}\""));
    }
    if let Some(opaque) = &challenge.opaque {
        out.push_str(&format!(", opaque=\"{opaque}\""));
    }
    out.push_str(&format!(", response=\"{response}\""));
    Ok(out)
}

/// The verb's client nonce: deterministic by construction (the
/// determinism doctrine — no randomness without a seed), derived
/// from the exchange's own facts.
pub fn deterministic_cnonce(nonce: &str, nc_hex: &str, uri: &str, username: &str) -> String {
    let raw = md5_hex(&format!("{nonce}:{nc_hex}:{uri}:{username}"));
    raw.chars().take(16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHALLENGE: &str = "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", \
         nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
         opaque=\"5ccc069c403ebaf9f0171e9517f40e41\", algorithm=MD5";

    fn challenge() -> DigestChallenge {
        parse_digest_challenge(CHALLENGE).expect("digest challenge")
    }

    #[test]
    fn basic_is_base64_of_user_pass() {
        assert_eq!(
            basic_authorization("aladdin", "opensesame"),
            "Basic YWxhZGRpbjpvcGVuc2VzYW1l"
        );
        assert_eq!(basic_authorization("u", ""), "Basic dTo=");
    }

    #[test]
    fn challenge_parsing() {
        let c = challenge();
        assert_eq!(c.realm, "testrealm@host.com");
        assert_eq!(c.nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093");
        assert_eq!(
            c.opaque.as_deref(),
            Some("5ccc069c403ebaf9f0171e9517f40e41")
        );
        assert_eq!(c.qop.as_deref(), Some("auth,auth-int"));
        assert_eq!(c.algorithm.as_deref(), Some("MD5"));
        // defaults: absent algorithm → None (MD5 per §3.3); a mixed
        // scheme list finds the Digest one; quoted commas survive.
        let c = parse_digest_challenge(
            "Basic realm=\"x\", Digest realm=\"a, b\", nonce=\"n1\", algorithm=SHA-256",
        )
        .expect("digest among schemes");
        assert_eq!(c.realm, "a, b");
        assert_eq!(c.nonce, "n1");
        assert_eq!(c.algorithm.as_deref(), Some("SHA-256"));
        assert!(parse_digest_challenge("Basic realm=\"x\"").is_none());
        // realm+nonce are mandatory: a challenge without them is not one
        assert!(parse_digest_challenge("Digest realm=\"only\"").is_none());
    }

    #[test]
    fn rfc7616_md5_vector() {
        // RFC 7616 §3.9.1 (the RFC 2617 §3.5 lineage): HA1/HA2 and
        // the response, with the RFC's own cnonce.
        let c = challenge();
        let auth = digest_authorization(
            &c,
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            1,
            "0a4f113b",
        )
        .unwrap();
        assert!(
            auth.contains("response=\"6629fae49393a05397450978507c4ef1\""),
            "{auth}"
        );
        assert!(auth.contains("nc=00000001"), "{auth}");
        assert!(auth.contains("qop=auth"), "{auth}");
        assert!(auth.contains("algorithm=MD5"), "{auth}");
        assert!(
            auth.contains("opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""),
            "{auth}"
        );
        assert!(auth.contains("realm=\"testrealm@host.com\""), "{auth}");
        assert!(auth.contains("username=\"Mufasa\""), "{auth}");
        // SHA-256 with the same inputs (pinned from python hashlib —
        // an independent lineage).
        let c = parse_digest_challenge(
            "Digest realm=\"testrealm@host.com\", qop=\"auth\", \
             nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", algorithm=SHA-256",
        )
        .unwrap();
        let auth = digest_authorization(
            &c,
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            1,
            "0a4f113b",
        )
        .unwrap();
        assert!(
            auth.contains(
                "response=\"5abdd07184ba512a22c53f41470e5eea7dcaa3a93a59b630c13dfe0a5dc6e38b\""
            ),
            "{auth}"
        );
        // MD5-sess (§3.4.2: HA1 folds the nonce + cnonce in).
        let c = parse_digest_challenge(
            "Digest realm=\"testrealm@host.com\", qop=\"auth\", \
             nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", algorithm=MD5-sess",
        )
        .unwrap();
        let auth = digest_authorization(
            &c,
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            1,
            "0a4f113b",
        )
        .unwrap();
        assert!(
            auth.contains("response=\"8e3825c57e897f5a0dec6c2d4e5059d0\""),
            "{auth}"
        );
    }

    #[test]
    fn legacy_no_qop_and_rejections() {
        // The pre-RFC-7616 shape (no qop ⇒ no nc/cnonce on the wire
        // and the §3.4.4.1 response).
        let c = DigestChallenge {
            realm: "testrealm@host.com".to_string(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".to_string(),
            opaque: None,
            qop: None,
            algorithm: Some("MD5".to_string()),
        };
        let auth = digest_authorization(
            &c,
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            1,
            "0a4f113b",
        )
        .unwrap();
        assert!(
            auth.contains("response=\"670fd8c2df070c60b045671b8b24ff02\""),
            "{auth}"
        );
        assert!(!auth.contains("qop="), "{auth}");
        assert!(!auth.contains("nc="), "{auth}");
        // auth-int only: pointed rejection; unknown algorithm too.
        let mut int_only = c.clone();
        int_only.qop = Some("auth-int".to_string());
        assert!(
            digest_authorization(&int_only, "u", "p", "GET", "/", 1, "c")
                .unwrap_err()
                .contains("auth-int")
        );
        let mut weird = c;
        weird.algorithm = Some("SHA-512".to_string());
        assert!(
            digest_authorization(&weird, "u", "p", "GET", "/", 1, "c")
                .unwrap_err()
                .contains("SHA-512")
        );
    }

    #[test]
    fn deterministic_cnonce_is_stable_and_short() {
        let a = deterministic_cnonce("n", "00000001", "/x", "u");
        let b = deterministic_cnonce("n", "00000001", "/x", "u");
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        assert_ne!(a, deterministic_cnonce("other", "00000001", "/x", "u"));
    }
}
