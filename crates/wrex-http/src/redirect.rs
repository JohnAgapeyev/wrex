//! Redirect classification + Location resolution (tranche 19a).
//!
//! [`classify`] turns a 3xx response into the next request (RFC 9110
//! §15.4 semantics; curl's method rules): 303 rewrites everything but
//! HEAD to a bodyless GET, 301/302 rewrite POST to GET, 307/308
//! preserve method and body. [`resolve_location`] is an RFC 3986 §5
//! reference resolver over the `http` crate's `Uri` — absolute,
//! network-path (`//host/…`) and relative Location spellings all
//! land on one absolute URI, fragments dropped (they never ride a
//! request line).

use http::Uri;

/// One classified redirect: where to go, how (method), and whether
/// the request body survives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Redirect {
    pub url: Uri,
    pub method: http::Method,
    pub drop_body: bool,
}

/// Is this response a redirect the client may follow? `None` = not a
/// redirect status, or a 3xx with no usable `Location` (such a
/// response is final data — the curl behavior). `Some(Err)` = a
/// `Location` that does not resolve (runtime error, exit 1).
pub fn classify(
    resp: &crate::HttpResponse,
    method: &http::Method,
    base: &Uri,
) -> Option<Result<Redirect, String>> {
    if !matches!(resp.status.as_u16(), 301 | 302 | 303 | 307 | 308) {
        return None;
    }
    let location = resp
        .headers
        .get("location")?
        .to_str()
        .ok()?
        .trim()
        .to_string();
    if location.is_empty() {
        return None;
    }
    let url = match resolve_location(base, &location) {
        Ok(u) => u,
        Err(e) => return Some(Err(e)),
    };
    // Method rules (RFC 9110 §15.4 + curl's POST practice): 303 ⇒ GET
    // (except HEAD); 301/302 ⇒ POST becomes GET; 307/308 preserve.
    let (method, drop_body) = match resp.status.as_u16() {
        303 if *method != http::Method::HEAD => (http::Method::GET, true),
        301 | 302 if *method == http::Method::POST => (http::Method::GET, true),
        _ => (method.clone(), false),
    };
    Some(Ok(Redirect {
        url,
        method,
        drop_body,
    }))
}

/// Do the two URIs point at the same origin (same scheme + authority,
/// default ports normalized)? Cross-origin redirects drop
/// `Authorization` (curl's rule) and reconnect.
pub fn same_origin(a: &Uri, b: &Uri) -> bool {
    authority_key(a) == authority_key(b) && a.scheme_str() == b.scheme_str()
}

/// The connection key: lowercase host + effective port (scheme
/// defaults applied), so `http://h/` and `http://h:80/` reuse one
/// connection.
pub fn authority_key(uri: &Uri) -> String {
    let host = uri
        .authority()
        .map(|a| a.host())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let port = uri
        .authority()
        .and_then(|a| a.port_u16())
        .unwrap_or(match uri.scheme_str() {
            Some("https") => 443,
            _ => 80,
        });
    format!("{host}:{port}")
}

/// RFC 3986 §5: resolve `location` against `base` into an absolute
/// http(s) URI. Fragments drop (request-targets carry none).
pub fn resolve_location(base: &Uri, location: &str) -> Result<Uri, String> {
    let loc = match location.find('#') {
        Some(i) => &location[..i],
        None => location,
    };
    let loc = loc.trim();
    let scheme = base.scheme_str().unwrap_or("http");
    let authority = base
        .authority()
        .ok_or_else(|| "base url has no host".to_string())?
        .as_str();
    let base_pq = base.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let (base_path, base_query) = match base_pq.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (base_pq, None),
    };

    // Absolute reference: a scheme of its own. A scheme-looking prefix
    // that fails to parse (e.g. `g:h` — RFC 3986 §5.4.1) is a pointed
    // error, not a relative path.
    if loc.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && !loc.starts_with("//")
        && loc.find(':').is_some_and(|i| {
            loc[..i]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
        })
    {
        return match loc.parse::<Uri>() {
            Ok(abs) => validate(abs),
            Err(e) => Err(format!("bad redirect location `{loc}`: {e}")),
        };
    }
    // Network-path: `//host:port/…` inherits the scheme.
    if let Some(rest) = loc.strip_prefix("//") {
        let parsed = format!("{scheme}://{rest}")
            .parse::<Uri>()
            .map_err(|e| format!("bad redirect location `{loc}`: {e}"))?;
        return validate(parsed);
    }
    // Absolute-path or a relative reference against the same
    // authority. An empty reference (a bare `#fragment`) keeps the
    // base path AND query (RFC 3986 §5.3: fragments never survive).
    let (path, query) = if loc.is_empty() {
        (base_path.to_string(), base_query.map(str::to_string))
    } else {
        match loc.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (loc.to_string(), None),
        }
    };
    let mut path = if path.is_empty() {
        // A bare `?query` keeps the base path.
        base_path.to_string()
    } else if path.starts_with('/') {
        path
    } else {
        // RFC 3986 §5.3 merge: base up to (not incl.) the last `/`, then
        // the relative path (a base without a slash merges onto `/`).
        match base_path.rfind('/') {
            Some(i) => format!("{}{}", &base_path[..=i], path),
            None => format!("/{path}"),
        }
    };
    path = remove_dot_segments(&path);
    let mut out = format!("{scheme}://{authority}{path}");
    if let Some(q) = query {
        out.push('?');
        out.push_str(&q);
    }
    let parsed = out
        .parse::<Uri>()
        .map_err(|e| format!("bad redirect location `{loc}`: {e}"))?;
    validate(parsed)
}

fn validate(uri: Uri) -> Result<Uri, String> {
    match uri.scheme_str() {
        Some("http") | Some("https") => Ok(uri),
        Some(other) => Err(format!("redirect to unsupported scheme `{other}`")),
        None => Err("redirect location has no scheme".to_string()),
    }
}

/// RFC 3986 §5.2.4 remove_dot_segments (segment-stack form; leading
/// `/` preserved, a trailing `..`/`.` leaves the implicit slash).
fn remove_dot_segments(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut trailing = false;
    for seg in path.split('/') {
        match seg {
            "." => trailing = true, // collapses: keep position
            ".." => {
                out.pop();
                trailing = true;
            }
            s => {
                out.push(s);
                trailing = false;
            }
        }
    }
    let mut result = out.join("/");
    if trailing && !result.ends_with('/') {
        result.push('/');
    }
    // join() above collapses a leading empty segment: restore the
    // absolute-path slash.
    if path.starts_with('/') && !result.starts_with('/') {
        result.insert(0, '/');
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::Method;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    /// String form of a resolved Uri (Display reconstructs from
    /// parts; the http crate normalizes the empty path to `/`).
    fn show(u: &Uri) -> String {
        u.to_string()
    }

    fn resp(status: u16, headers: &[(&str, &str)]) -> crate::HttpResponse {
        let mut map = http::HeaderMap::new();
        for (n, v) in headers {
            map.append(
                http::HeaderName::from_bytes(n.as_bytes()).unwrap(),
                http::HeaderValue::from_str(v).unwrap(),
            );
        }
        crate::HttpResponse {
            status: http::StatusCode::from_u16(status).unwrap(),
            reason: String::new(),
            version: http::Version::HTTP_11,
            headers: map,
            body: Bytes::new(),
        }
    }

    #[test]
    fn rfc3986_reference_resolution_table() {
        // RFC 3986 §5.4.1/§5.4.2 against the canonical base.
        let base = uri("http://a/b/c/d;p?q");
        for (reference, expected) in [
            ("g:h", "ERR"), // other scheme: not followed
            ("g", "http://a/b/c/g"),
            ("./g", "http://a/b/c/g"),
            ("g/", "http://a/b/c/g/"),
            ("/g", "http://a/g"),
            ("//g", "http://g/"),
            ("?y", "http://a/b/c/d;p?y"),
            ("g?y", "http://a/b/c/g?y"),
            ("#s", "http://a/b/c/d;p?q"), // bare fragment: base, query kept
            ("g#s", "http://a/b/c/g"),
            ("g?y#s", "http://a/b/c/g?y"),
            (";x", "http://a/b/c/;x"),
            ("g;x=1/./y", "http://a/b/c/g;x=1/y"),
            ("g;x=1/../y", "http://a/b/c/y"),
            ("./../g", "http://a/b/g"),
            ("./g/.", "http://a/b/c/g/"),
            ("../g", "http://a/b/g"),
            ("../../g", "http://a/g"),
            ("../../../g", "http://a/g"),
            ("../../../../g", "http://a/g"),
            ("/./g", "http://a/g"),
            ("/../g", "http://a/g"),
            ("g.", "http://a/b/c/g."),
            (".g", "http://a/b/c/.g"),
            ("g..", "http://a/b/c/g.."),
            ("..g", "http://a/b/c/..g"),
            ("./", "http://a/b/c/"),
            ("../", "http://a/b/"),
            ("../../", "http://a/"),
            ("g/./h", "http://a/b/c/g/h"),
            ("g/../h", "http://a/b/c/h"),
            ("g?y/./x", "http://a/b/c/g?y/./x"),
        ] {
            match resolve_location(&base, reference) {
                Ok(u) => assert_eq!(show(&u), expected, "reference {reference:?}"),
                Err(e) => assert!(expected == "ERR", "reference {reference:?}: unexpected {e}"),
            }
        }
    }

    #[test]
    fn absolute_and_network_path_locations() {
        let base = uri("http://a.example/b");
        assert_eq!(
            show(&resolve_location(&base, "https://s.example/x?q=1#frag").unwrap()),
            "https://s.example/x?q=1",
            "fragments drop; absolute passes through"
        );
        assert_eq!(
            show(&resolve_location(&base, "//other.example:8080/y").unwrap()),
            "http://other.example:8080/y"
        );
        // unsupported scheme is a pointed error
        assert!(
            resolve_location(&base, "ftp://x/")
                .unwrap_err()
                .contains("unsupported scheme")
        );
    }

    #[test]
    fn classification_rules() {
        let base = uri("http://a.example/");
        for status in [301u16, 302, 303, 307, 308] {
            let r = classify(
                &resp(status, &[("Location", "/next")]),
                &Method::POST,
                &base,
            )
            .expect("redirect")
            .unwrap();
            let expect_get = matches!(status, 301..=303);
            assert_eq!(
                r.method,
                if expect_get {
                    Method::GET
                } else {
                    Method::POST
                },
                "{status}"
            );
            assert_eq!(r.drop_body, expect_get, "{status}");
        }
        // HEAD survives even a 303
        let r = classify(&resp(303, &[("Location", "/n")]), &Method::HEAD, &base)
            .unwrap()
            .unwrap();
        assert_eq!(r.method, Method::HEAD);
        // non-redirect statuses: None; 3xx without Location: None (data)
        assert!(classify(&resp(200, &[("Location", "/x")]), &Method::GET, &base).is_none());
        assert!(classify(&resp(302, &[]), &Method::GET, &base).is_none());
        assert!(classify(&resp(302, &[("Location", "")]), &Method::GET, &base).is_none());
        // a bad Location is Some(Err)
        let bad = classify(&resp(302, &[("Location", "ftp://x/")]), &Method::GET, &base).unwrap();
        assert!(bad.is_err());
    }

    #[test]
    fn origin_keys() {
        assert_eq!(authority_key(&uri("http://a.example/")), "a.example:80");
        assert_eq!(authority_key(&uri("http://a.example:80/")), "a.example:80");
        assert_eq!(
            authority_key(&uri("http://A.Example:8080/x")),
            "a.example:8080"
        );
        assert_eq!(authority_key(&uri("https://a.example/")), "a.example:443");
        assert!(same_origin(
            &uri("http://a.example/x"),
            &uri("http://a.example:80/y")
        ));
        assert!(!same_origin(
            &uri("http://a.example/x"),
            &uri("https://a.example/y")
        ));
        assert!(!same_origin(
            &uri("http://a.example/x"),
            &uri("http://b.example/y")
        ));
    }
}
