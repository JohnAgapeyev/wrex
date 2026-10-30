//! The cookie engine (tranche 19a): an RFC 6265 storage model + the
//! Netscape jar file format curl's `-b`/`-c` speak.
//!
//! Own code, deliberately (ADR-2: small + the mutation surface of a
//! lab tool — the parser is ~a page, and Set-Cookie grammar decisions
//! are test data, not library behavior). The storage model follows
//! RFC 6265 §5.2 (parse) / §5.3 (storage) / §5.4 (retrieval) closely:
//! host-only vs domain cookies, default-path derivation, Max-Age
//! precedence over Expires, replace-on-(name, domain, path) keeping
//! the original creation time, longer-path-first + oldest-first send
//! order. Deliberate simplifications, recorded: no public-suffix
//! list (a PSL is a data dependency wrex does not carry; a
//! subdomain-set cookie for `com` is rejected only by the domain-match
//! rule), no cookie count/size eviction (the jar is per-invocation),
//! and `HttpOnly` is tracked for Netscape round-trip fidelity only
//! (wrex is not a browser; the flag is not enforced client-side).

use std::time::{SystemTime, UNIX_EPOCH};

/// One stored cookie (RFC 6265 §5.3's fields).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    /// Lowercase, no leading dot. For host-only cookies: the exact
    /// request host.
    pub domain: String,
    pub path: String,
    /// `None` = session cookie (dies with the process, like curl).
    pub expires: Option<SystemTime>,
    pub secure: bool,
    /// No Domain attribute was set: only the exact request host matches.
    pub host_only: bool,
    /// Tracked for the Netscape `#HttpOnly_` prefix round-trip only.
    pub http_only: bool,
    /// Storage order tiebreaker (RFC 6265 §5.4: older first).
    pub creation: SystemTime,
}

/// The per-invocation jar.
#[derive(Clone, Debug, Default)]
pub struct CookieJar {
    cookies: Vec<Cookie>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored cookies (test surface).
    pub fn len(&self) -> usize {
        self.cookies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// Store every `Set-Cookie` header of a response (RFC 6265 §5.2 +
    /// §5.3). `host`/`path` are the request's (default-path derivation
    /// needs the request path); malformed pairs are ignored per
    /// §5.2's "ignore the set-cookie-string entirely" rules — never
    /// fatal.
    pub fn store_response<'a>(
        &mut self,
        set_cookies: impl Iterator<Item = &'a str>,
        host: &str,
        path: &str,
        now: SystemTime,
    ) {
        for header in set_cookies {
            self.store_set_cookie(header, host, path, now);
        }
    }

    /// One `Set-Cookie:` header value (§5.2 parse, §5.3 storage).
    pub fn store_set_cookie(&mut self, header: &str, host: &str, path: &str, now: SystemTime) {
        let host = host.to_ascii_lowercase();
        let mut parts = header.split(';');
        // cookie-pair (§5.2: no '=' → ignore the whole string).
        let Some((name, value)) = parts.next().and_then(|s| s.split_once('=')) else {
            return;
        };
        let name = name.trim();
        if name.is_empty() {
            return;
        }
        let value = value.trim();
        // Control characters make the pair unrepresentable in a header
        // (RFC 6265 grammar: cookie-name/value octets exclude CTLs);
        // ignore the whole set-cookie-string, per §5.2's never-fatal
        // rule.
        if name.bytes().any(|b| b <= 0x20 || b == 0x7f)
            || value.bytes().any(|b| b <= 0x20 || b == 0x7f)
        {
            return;
        }
        let (mut domain, mut cookie_path, mut expires, mut secure, mut http_only) =
            (None, None, None, false, false);
        let mut max_age: Option<i64> = None;
        for attr in parts {
            let attr = attr.trim();
            let (key, val) = match attr.split_once('=') {
                Some((k, v)) => (k.trim().to_ascii_lowercase(), v.trim()),
                None => (attr.to_ascii_lowercase(), ""),
            };
            match key.as_str() {
                "domain" => {
                    let d = val.trim_start_matches('.').to_ascii_lowercase();
                    if !d.is_empty() {
                        domain = Some(d);
                    }
                }
                "path" => {
                    if val.starts_with('/') {
                        cookie_path = Some(val.to_string());
                    }
                }
                "expires" => expires = parse_http_date(val),
                "max-age" => max_age = val.parse::<i64>().ok(),
                "secure" => secure = true,
                "httponly" => http_only = true,
                _ => {} // unknown attributes ignored (§5.2)
            }
        }
        // Domain: host-only when absent (§5.3.4-6). A Domain that does
        // not domain-match the request host is REJECTED (§5.3.6).
        let (domain, host_only) = match domain {
            Some(d) => {
                if !domain_match(&host, &d) {
                    return;
                }
                (d, false)
            }
            None => (host.clone(), true),
        };
        // Path: the attribute when valid, else the request default
        // path (§5.1.4 / §5.3.5-6).
        let cookie_path = cookie_path
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| default_path(path));
        // Expiry: Max-Age wins over Expires (§4.1.2.2). A past or
        // overflowed Max-Age means already-expired — the deletion
        // path below then fires and nothing is stored.
        let expires = match max_age {
            Some(secs) => {
                let now_secs = now
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                now_secs.checked_add(secs).and_then(|t| {
                    if t <= 0 {
                        UNIX_EPOCH.checked_sub(std::time::Duration::from_secs(1))
                    } else {
                        UNIX_EPOCH.checked_add(std::time::Duration::from_secs(t as u64))
                    }
                })
            }
            None => expires,
        };
        // Replace-on-match keeps the original creation time (§5.3.11).
        let old_creation = self
            .cookies
            .iter()
            .find(|c| c.name == name && c.domain == domain && c.path == cookie_path)
            .map(|c| c.creation);
        self.cookies
            .retain(|c| !(c.name == name && c.domain == domain && c.path == cookie_path));
        if let Some(exp) = expires
            && exp <= now
        {
            return; // already expired: only the deletion happened
        }
        self.cookies.push(Cookie {
            name: name.to_string(),
            value: value.to_string(),
            domain,
            path: cookie_path,
            expires,
            secure,
            host_only,
            http_only,
            creation: old_creation.unwrap_or(now),
        });
    }

    /// The `Cookie:` request header value for this host/path (§5.4),
    /// or `None` when no cookie matches. `secure` = the request rode
    /// https (Secure cookies stay home).
    pub fn cookie_header(
        &self,
        host: &str,
        path: &str,
        secure: bool,
        now: SystemTime,
    ) -> Option<String> {
        let host = host.to_ascii_lowercase();
        let mut hits: Vec<&Cookie> = self
            .cookies
            .iter()
            .filter(|c| {
                c.expires.is_none_or(|t| t > now)
                    && if c.host_only {
                        c.domain == host
                    } else {
                        domain_match(&host, &c.domain)
                    }
                    && path_match(path, &c.path)
                    && (secure || !c.secure)
            })
            .collect();
        // §5.4 step 2: longer paths first, then earlier creation.
        hits.sort_by(|a, b| {
            b.path
                .len()
                .cmp(&a.path.len())
                .then_with(|| a.creation.cmp(&b.creation))
                .then_with(|| a.name.cmp(&b.name))
        });
        if hits.is_empty() {
            return None;
        }
        let mut out = String::new();
        for (i, c) in hits.iter().enumerate() {
            if i > 0 {
                out.push_str("; ");
            }
            out.push_str(&c.name);
            out.push('=');
            out.push_str(&c.value);
        }
        Some(out)
    }

    /// Merge a Netscape-format jar (curl `-b` input; `curl -c` files
    /// round-trip). Returns the number of cookies stored; malformed
    /// lines skip silently (curl's behavior), `#` comments skip,
    /// `#HttpOnly_` prefixed domains load with the flag set. Expiry
    /// `0` = session cookie.
    pub fn load_netscape(&mut self, raw: &str, now: SystemTime) -> usize {
        let mut n = 0;
        for line in raw.lines() {
            let (http_only, line) = match line.strip_prefix("#HttpOnly_") {
                Some(rest) => (true, rest),
                None => (false, line),
            };
            if line.starts_with('#') || line.trim().is_empty() {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() != 7 {
                continue;
            }
            let Ok(expiry) = fields[4].trim().parse::<i64>() else {
                continue;
            };
            let expires = if expiry <= 0 {
                None
            } else {
                UNIX_EPOCH.checked_add(std::time::Duration::from_secs(expiry.unsigned_abs()))
            };
            let domain = fields[0]
                .trim()
                .trim_start_matches('.')
                .to_ascii_lowercase();
            if domain.is_empty() {
                continue;
            }
            // Netscape column 2: TRUE = subdomains match (a Domain
            // cookie); FALSE = host-only.
            let host_only = !fields[1].trim().eq_ignore_ascii_case("TRUE");
            let path = if fields[2].trim().is_empty() {
                "/".to_string()
            } else {
                fields[2].trim().to_string()
            };
            let secure = fields[3].trim().eq_ignore_ascii_case("TRUE");
            self.cookies
                .retain(|c| !(c.name == fields[5] && c.domain == domain && c.path == path));
            self.cookies.push(Cookie {
                name: fields[5].to_string(),
                value: fields[6].to_string(),
                domain,
                path,
                expires,
                secure,
                host_only,
                http_only,
                creation: now,
            });
            n += 1;
        }
        n
    }

    /// Render the jar as a Netscape file (curl `-c` compatible):
    /// `domain\tflag\tpath\tsecure\texpiry\tname\tvalue`, session
    /// cookies at expiry 0, `#HttpOnly_` prefixes where set. Sorted
    /// (domain, path, name) for stable output.
    pub fn to_netscape(&self) -> String {
        let mut out = String::new();
        out.push_str("# Netscape HTTP Cookie File\n");
        out.push_str("# https://curl.se/docs/http-cookies.html\n");
        let mut cookies: Vec<&Cookie> = self.cookies.iter().collect();
        cookies.sort_by(|a, b| {
            (&a.domain, &a.path, &a.name, &a.value).cmp(&(&b.domain, &b.path, &b.name, &b.value))
        });
        for c in cookies {
            let expiry = c
                .expires
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs().to_string())
                .unwrap_or_else(|| "0".to_string());
            let prefix = if c.http_only { "#HttpOnly_" } else { "" };
            let flag = if c.host_only { "FALSE" } else { "TRUE" };
            out.push_str(&format!(
                "{prefix}{}\t{flag}\t{}\t{}\t{expiry}\t{}\t{}\n",
                c.domain,
                c.path,
                if c.secure { "TRUE" } else { "FALSE" },
                c.name,
                c.value
            ));
        }
        out
    }
}

/// RFC 6265 §5.1.3 domain-match (host is already lowercase).
fn domain_match(host: &str, domain: &str) -> bool {
    if host == domain {
        return true;
    }
    // IP strings never substring-match — on either side (§5.1.3's
    // last bullet covers the domain being an address literal).
    if host.parse::<std::net::IpAddr>().is_ok() || domain.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    host.ends_with(domain)
        && host.as_bytes().get(host.len() - domain.len() - 1) == Some(&b'.')
        && !domain.is_empty()
}

/// RFC 6265 §5.1.4 path-match.
fn path_match(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    request_path.starts_with(cookie_path)
        && (cookie_path.ends_with('/')
            || request_path
                .as_bytes()
                .get(cookie_path.len())
                .is_some_and(|&b| b == b'/'))
}

/// RFC 6265 §5.1.4 default-path: the request path up to (not
/// including) the right-most `/`; `/` when there is at most the
/// leading slash.
fn default_path(request_path: &str) -> String {
    if !request_path.starts_with('/') {
        return "/".to_string();
    }
    match request_path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => request_path[..i].to_string(),
    }
}

/// RFC 6265 §5.1.1 cookie-date: the delimiter-token algorithm that
/// accepts the three HTTP date spellings (IMF-fixdate, RFC 850,
/// asctime) — time, day, month, year tokens in any order; 2-digit
/// years follow §5.1.1 step 8 (69-99 → 19xx, 0-68 → 20xx). The
/// delimiter set is §5.1.1's (%x09, %x20-2F, %x3B-40, %x5B-60,
/// %x7B-7E) — note `:` (0x3A) is NOT a delimiter, so the time token
/// `08:49:37` stays whole.
pub fn parse_http_date(raw: &str) -> Option<SystemTime> {
    let is_delim =
        |c: char| matches!(c as u32, 0x09 | 0x20..=0x2F | 0x3B..=0x40 | 0x5B..=0x60 | 0x7B..=0x7E);
    let mut time: Option<(u32, u32, u32)> = None;
    let mut day: Option<u32> = None;
    let mut month: Option<u32> = None;
    let mut year: Option<i64> = None;
    for token in raw.split(is_delim) {
        if token.is_empty() {
            continue;
        }
        if time.is_none()
            && let Some(hm) = token.split_once(':')
            && let (Ok(h), rest) = (hm.0.parse::<u32>(), hm.1)
            && let Some((m, s)) = rest.split_once(':')
            && let (Ok(m), Ok(s)) = (m.parse::<u32>(), s.parse::<u32>())
            && (h, m, s) <= (23, 59, 60)
        {
            time = Some((h, m, s));
            continue;
        }
        if let Ok(n) = token.parse::<u32>() {
            if (1..=31).contains(&n) && day.is_none() {
                day = Some(n);
                continue;
            }
            // 2-digit years per §5.1.1 step 8; ≥100 is a full year.
            let spelled = match n {
                70..=99 => Some(1900 + n as i64),
                0..=68 => Some(2000 + n as i64),
                n if n >= 100 => Some(n as i64),
                _ => None,
            };
            if let Some(y) = spelled {
                year = year.or(Some(y));
                continue;
            }
        }
        if let Some(m) = match token.to_ascii_lowercase().as_str() {
            "jan" => Some(1),
            "feb" => Some(2),
            "mar" => Some(3),
            "apr" => Some(4),
            "may" => Some(5),
            "jun" => Some(6),
            "jul" => Some(7),
            "aug" => Some(8),
            "sep" => Some(9),
            "oct" => Some(10),
            "nov" => Some(11),
            "dec" => Some(12),
            _ => None,
        } {
            month = month.or(Some(m));
        }
    }
    let (h, m, s) = time?;
    let day = day?;
    let month = month?;
    let year = year?;
    days_from_civil(year, month, day)
        .checked_mul(86_400)
        .and_then(|days| {
            let secs = days + h as i64 * 3600 + m as i64 * 60 + s as i64;
            UNIX_EPOCH.checked_add(std::time::Duration::from_secs(secs.unsigned_abs()))
        })
}

/// Days since 1970-01-01 (Howard Hinnant's civil-from-days inverse).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_000_000_000)
    }

    fn jar_after(header: &str, host: &str, path: &str) -> CookieJar {
        let mut jar = CookieJar::new();
        jar.store_set_cookie(header, host, path, now());
        jar
    }

    #[test]
    fn simple_pair_and_attributes() {
        // RFC 6265 §5.2's shape: pair first, attributes after.
        let jar = jar_after(
            "SID=31d4d96e407aad42; Path=/; Domain=example.com",
            "www.example.com",
            "/a/b",
        );
        assert_eq!(jar.len(), 1);
        let c = &jar.cookies[0];
        assert_eq!(
            (c.name.as_str(), c.value.as_str()),
            ("SID", "31d4d96e407aad42")
        );
        assert_eq!(c.domain, "example.com");
        assert!(!c.host_only, "Domain attribute ⇒ subdomain matching");
        assert_eq!(c.path, "/");
        assert_eq!(
            jar.cookie_header("www.example.com", "/x", false, now()),
            Some("SID=31d4d96e407aad42".to_string())
        );
        // host-only without Domain: exact host only
        let jar = jar_after("SID=1", "example.com", "/");
        assert!(
            jar.cookie_header("www.example.com", "/", false, now())
                .is_none()
        );
        assert_eq!(
            jar.cookie_header("example.com", "/", false, now()),
            Some("SID=1".to_string())
        );
    }

    #[test]
    fn malformed_pairs_ignored_never_fatal() {
        for header in ["novalue", "=noname", "  ", "a=1;;b=2"] {
            let jar = jar_after(header, "example.com", "/");
            assert!(jar.len() <= 2, "{header:?}");
        }
        // A control-char name/value stays out (trim + empty rules)
        let jar = jar_after("\u{0}=1", "example.com", "/");
        assert_eq!(jar.len(), 0);
    }

    #[test]
    fn domain_match_rules() {
        // exact / suffix-with-dot / rejected cross-host
        let jar = jar_after("A=1; Domain=example.com", "www.example.com", "/");
        assert!(
            jar.cookie_header("a.example.com", "/", false, now())
                .is_some()
        );
        assert!(
            jar.cookie_header("example.com", "/", false, now())
                .is_some()
        );
        assert!(
            jar.cookie_header("notexample.com", "/", false, now())
                .is_none()
        );
        assert!(
            jar.cookie_header("example.com.evil.com", "/", false, now())
                .is_none()
        );
        // a set from a host the domain does not match is rejected
        let jar = jar_after("A=1; Domain=example.com", "evil.org", "/");
        assert!(jar.is_empty());
        // leading dot strips (old-style Domain=.example.com)
        let jar = jar_after("A=1; Domain=.example.com", "www.example.com", "/");
        assert_eq!(jar.cookies[0].domain, "example.com");
        // IP hosts never suffix-match
        let jar = jar_after("A=1; Domain=1.2.3.4", "www.1.2.3.4", "/");
        assert!(
            jar.is_empty(),
            "a Domain attr an IP host cannot match is rejected"
        );
        let jar = jar_after("A=1", "1.2.3.4", "/");
        assert!(jar.cookie_header("1.2.3.4", "/", false, now()).is_some());
        assert!(jar.cookie_header("5.1.2.3.4", "/", false, now()).is_none());
    }

    #[test]
    fn path_rules_and_default_path() {
        // explicit Path wins; relative (non-/) attr ignored → default
        let jar = jar_after("A=1; Path=relative", "example.com", "/dir/page");
        assert_eq!(
            jar.cookies[0].path, "/dir",
            "default-path cuts at the last /"
        );
        let jar = jar_after("A=1; Path=/shop", "example.com", "/");
        assert_eq!(
            jar.cookie_header("example.com", "/shop/cart", false, now())
                .as_deref(),
            Some("A=1")
        );
        assert!(
            jar.cookie_header("example.com", "/shopping", false, now())
                .is_none()
        );
        assert!(
            jar.cookie_header("example.com", "/", false, now())
                .is_none()
        );
        // default-path edge: root-only path
        let jar = jar_after("A=1", "example.com", "/page");
        assert_eq!(jar.cookies[0].path, "/");
    }

    #[test]
    fn expiry_max_age_wins_and_deletes() {
        // Max-Age precedence (§4.1.2.2) + a past Max-Age deletes
        let mut jar = CookieJar::new();
        jar.store_set_cookie(
            "A=1; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
            "example.com",
            "/",
            now(),
        );
        assert_eq!(jar.len(), 1);
        assert!(jar.cookies[0].expires.unwrap() > now());
        jar.store_set_cookie("A=1; Max-Age=-1", "example.com", "/", now());
        assert!(jar.is_empty(), "a past Max-Age deletes the stored cookie");
        // Expires in the past: same effect
        jar.store_set_cookie(
            "B=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
            "example.com",
            "/",
            now(),
        );
        assert!(jar.is_empty());
        // expired cookies are not sent
        jar.store_set_cookie("C=1; Max-Age=1", "example.com", "/", now());
        let later = now() + Duration::from_secs(2);
        assert!(
            jar.cookie_header("example.com", "/", false, later)
                .is_none()
        );
    }

    #[test]
    fn http_date_formats() {
        for date in [
            "Sun, 06 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Nov-94 08:49:37 GMT",
            "Sun Nov  6 08:49:37 1994",
        ] {
            let t = parse_http_date(date).unwrap_or_else(|| panic!("{date}"));
            assert_eq!(
                t.duration_since(UNIX_EPOCH).unwrap().as_secs(),
                784_111_777,
                "{date}"
            );
        }
        // 2-digit years: 69-99 → 19xx, 0-68 → 20xx
        assert_eq!(
            parse_http_date("Thu, 01 Jan 2038 03:14:07 GMT")
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs()),
            Some(2_145_928_447)
        );
        assert_eq!(
            parse_http_date("Mon, 06 Nov 94 08:49:37 GMT"),
            parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT")
        );
        assert_eq!(
            parse_http_date("Sun, 06 Nov 68 08:49:37 GMT"),
            parse_http_date("Wed, 06 Nov 2068 08:49:37 GMT")
        );
        // junk
        assert!(parse_http_date("not a date").is_none());
        assert!(parse_http_date("").is_none());
    }

    #[test]
    fn replace_keeps_creation_and_send_order() {
        let mut jar = CookieJar::new();
        let t = now();
        jar.store_set_cookie("A=1; Path=/", "example.com", "/", t);
        let t2 = t + Duration::from_secs(10);
        jar.store_set_cookie("A=2; Path=/", "example.com", "/", t2);
        assert_eq!(jar.len(), 1, "same (name,domain,path) replaces");
        assert_eq!(jar.cookies[0].value, "2");
        assert_eq!(
            jar.cookies[0].creation, t,
            "creation time survives replacement (§5.3.11)"
        );
        // different path ⇒ a second cookie
        jar.store_set_cookie("A=3; Path=/sub", "example.com", "/", t2);
        assert_eq!(jar.len(), 2);
        // longer path first (§5.4)
        assert_eq!(
            jar.cookie_header("example.com", "/sub/x", false, t2)
                .unwrap(),
            "A=3; A=2"
        );
        // same path length ⇒ older first
        jar.store_set_cookie("B=9; Path=/", "example.com", "/", t2);
        assert_eq!(
            jar.cookie_header("example.com", "/", false, t2).unwrap(),
            "A=2; B=9"
        );
    }

    #[test]
    fn secure_cookies_stay_home_over_http() {
        let jar = jar_after("A=1; Secure", "example.com", "/");
        assert!(jar.cookie_header("example.com", "/", true, now()).is_some());
        assert!(
            jar.cookie_header("example.com", "/", false, now())
                .is_none()
        );
    }

    #[test]
    fn netscape_roundtrip() {
        let mut jar = CookieJar::new();
        let t = now();
        jar.store_set_cookie(
            "SID=abc; Path=/; Domain=example.com; HttpOnly",
            "www.example.com",
            "/",
            t,
        );
        jar.store_set_cookie("short=lived", "example.com", "/dir", t);
        jar.store_set_cookie(
            "locked=1; Path=/; Secure; Expires=Sun, 06 Nov 2100 08:49:37 GMT",
            "example.com",
            "/",
            t,
        );
        let text = jar.to_netscape();
        assert!(
            text.contains("#HttpOnly_example.com\tTRUE\t/\tFALSE\t"),
            "{text}"
        );
        // The `short` cookie's request path was `/dir` — its default
        // path per §5.1.4 is `/` (only the leading slash).
        assert!(
            text.contains("example.com\tFALSE\t/\tFALSE\t0\tshort\tlived"),
            "{text}"
        );
        // reload
        let mut jar2 = CookieJar::new();
        let n = jar2.load_netscape(&text, t);
        assert_eq!(n, 3);
        assert_eq!(
            jar2.cookie_header("www.example.com", "/", true, t),
            jar.cookie_header("www.example.com", "/", true, t)
        );
        // comments, HttpOnly prefix, expiry 0 = session
        assert!(text.starts_with("# "));
        assert!(jar2.cookies.iter().any(|c| c.http_only));
        assert!(
            jar2.cookies
                .iter()
                .any(|c| c.expires.is_none() && c.name == "short")
        );
        // curl's own file shape parses
        let curl_file = "# Netscape HTTP Cookie File\n\
            #This file was generated by curl\n\
            \n\
            127.0.0.1\tFALSE\t/\tFALSE\t0\tname\tvalue\n\
            #HttpOnly_127.0.0.1\tFALSE\t/\tFALSE\t0\ts\tt\n";
        let mut jar3 = CookieJar::new();
        assert_eq!(jar3.load_netscape(curl_file, t), 2);
        assert_eq!(
            jar3.cookie_header("127.0.0.1", "/", false, t).unwrap(),
            "name=value; s=t"
        );
    }
}
