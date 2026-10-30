//! Service/version probe engine (T21c): a committed, data-driven
//! probe table + a regex-anchored match DSL (the nmap-service-probes
//! subset as the model — probes are *data*, matching is not wire
//! control, so the engine reuses `regex` per ADR-2).
//!
//! Flow per open TCP port (the `--service` post-pass over a completed
//! scan): each probe in table order opens one fresh kernel connection
//! ([`wrex_io::TcpDriver`], the T9b per-probe pattern), sends its
//! payload (banner-grab probes send nothing), collects reply bytes
//! until orderly EOF or the wait deadline, and runs its match rules in
//! order — first hit wins and renders
//! [`ServiceMatch { service, version }`] (capture groups substitute
//! `$1..$9` into the version template). A port where every probe
//! comes back silent stays `None` (data, never an error — the scan
//! precedent).

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use wrex_io::{Driver, TcpDriver};

/// Reply bytes a single probe collects before matching.
const MAX_BANNER: usize = 4096;

/// One matched service rule result.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ServiceMatch {
    /// The probe that matched (`NULL` / `HTTPGet`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe: Option<&'static str>,
    pub service: &'static str,
    pub version: Option<String>,
}

/// One match rule: an anchored regex over the collected reply, a
/// service name, and an optional version template (`$1..$9` capture
/// substitution).
#[derive(Clone, Debug)]
pub struct MatchRule {
    pub pattern: &'static str,
    pub service: &'static str,
    pub version: Option<&'static str>,
}

/// One probe: a payload (or nothing — the banner grab), and ordered
/// match rules.
#[derive(Clone, Debug)]
pub struct ServiceProbe {
    pub name: &'static str,
    /// Probe payload (`None` = the null probe: connect and listen).
    pub payload: Option<&'static [u8]>,
    /// How long to collect reply bytes.
    pub wait: Duration,
    pub matches: &'static [MatchRule],
}

macro_rules! rule {
    ($p:expr, $s:expr) => {
        MatchRule {
            pattern: $p,
            service: $s,
            version: None,
        }
    };
    ($p:expr, $s:expr, $v:expr) => {
        MatchRule {
            pattern: $p,
            service: $s,
            version: Some($v),
        }
    };
}

/// The committed probe table (a curated subset — recorded deferrals:
/// UDP service probes, RPC, TLS-inside-probe (the T32 door),
/// full nmap `softmatch`/`fallback` chaining).
pub const PROBE_TABLE: &[ServiceProbe] = &[
    ServiceProbe {
        name: "NULL",
        payload: None,
        wait: Duration::from_millis(500),
        matches: &[
            rule!(r"^SSH-[\d.]+-([^\r\n]+)", "ssh", "$1"),
            rule!(r"(?i)^220[- ][^\r\n]*\bftp\b", "ftp"),
            rule!(r"(?i)^220[- ]([^\r\n]*\besmtp\b[^\r\n]*)", "smtp", "$1"),
            rule!(r"(?i)^220[- ]([^\r\n]*\bsmtp\b[^\r\n]*)", "smtp", "$1"),
            rule!(r"(?i)^220[- ]([^\r\n]*)", "smtp", "$1"),
            rule!(r"(?i)^[+-](?:ERR|PONG)", "redis"),
        ],
    },
    ServiceProbe {
        name: "HTTPGet",
        payload: Some(b"GET / HTTP/1.0\r\n\r\n"),
        wait: Duration::from_millis(500),
        matches: &[
            rule!(r"(?im)^Server: ([^\r\n]+)", "http", "$1"),
            rule!(r"^HTTP/1\.[01] \d{3}", "http"),
        ],
    },
];

/// A probe with its rules compiled (built once per process).
struct CompiledProbe {
    name: &'static str,
    payload: Option<&'static [u8]>,
    wait: Duration,
    matches: Vec<(regex::Regex, &'static str, Option<&'static str>)>,
}

fn compiled_table() -> &'static Vec<CompiledProbe> {
    static TABLE: OnceLock<Vec<CompiledProbe>> = OnceLock::new();
    TABLE.get_or_init(|| {
        PROBE_TABLE
            .iter()
            .map(|p| CompiledProbe {
                name: p.name,
                payload: p.payload,
                wait: p.wait,
                matches: p
                    .matches
                    .iter()
                    .map(|r| {
                        (
                            regex::Regex::new(r.pattern)
                                .unwrap_or_else(|e| panic!("probe table: `{}`: {e}", r.pattern)),
                            r.service,
                            r.version,
                        )
                    })
                    .collect(),
            })
            .collect()
    })
}

/// Substitute `$1..$9` capture references in a version template.
fn render_version(template: &str, caps: &regex::Captures<'_>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(dollar) = rest.find('$') {
        out.push_str(&rest[..dollar]);
        let after = &rest[dollar + 1..];
        let Some(first) = after.chars().next() else {
            out.push('$');
            rest = after;
            continue;
        };
        if let Some(n) = first.to_digit(10) {
            if let Some(group) = caps.get(n as usize) {
                out.push_str(group.as_str());
            }
            // a missing group renders empty (consumed with the `$`)
            rest = &after[first.len_utf8()..];
        } else {
            out.push('$');
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Run one probe's rules over collected reply bytes. First hit wins.
pub fn match_reply(probe: usize, reply: &[u8]) -> Option<ServiceMatch> {
    let table = compiled_table();
    let probe = table.get(probe)?;
    let text = String::from_utf8_lossy(reply);
    for (re, service, template) in &probe.matches {
        if let Some(caps) = re.captures(&text) {
            return Some(ServiceMatch {
                probe: Some(probe.name),
                service,
                version: template.map(|t| render_version(t, &caps)),
            });
        }
    }
    None
}

/// Run the whole table against a collected reply stream (probe order).
pub fn match_table(reply: &[u8]) -> Option<ServiceMatch> {
    (0..PROBE_TABLE.len()).find_map(|i| match_reply(i, reply))
}

/// Collect reply bytes for one probe over an established driver:
/// until orderly EOF (the empty frame), the deadline, or the budget.
fn collect_banner(
    driver: &mut TcpDriver,
    payload: Option<&[u8]>,
    wait: Duration,
) -> io::Result<Vec<u8>> {
    if let Some(p) = payload {
        driver.send(p)?;
    }
    let deadline = Instant::now() + wait;
    let mut buf = BytesMut::new();
    while buf.len() < MAX_BANNER {
        let Some(frame) = driver.recv(deadline)? else {
            break; // wait elapsed
        };
        if frame.bytes.is_empty() {
            break; // orderly EOF
        }
        let remaining = MAX_BANNER - buf.len();
        buf.extend_from_slice(&frame.bytes[..frame.bytes.len().min(remaining)]);
    }
    Ok(buf.to_vec())
}

/// Probe one open TCP port with the whole committed table: one fresh
/// connection per probe (the T9b rule). `Ok(None)` = every probe came
/// back without a match (data, never an error); a connect *failure*
/// after the scan said the port was open is `Ok(None)` too — the
/// port may have closed since (racing reality), silence is honest.
pub fn probe_service(
    target: IpAddr,
    port: u16,
    connect_timeout: Duration,
) -> io::Result<Option<ServiceMatch>> {
    let addr = SocketAddr::new(target, port);
    let table = compiled_table();
    for probe in table {
        let Ok(mut driver) = TcpDriver::connect(addr, None, connect_timeout) else {
            return Ok(None); // port closed/refused since the scan — silence
        };
        let banner = collect_banner(&mut driver, probe.payload, probe.wait)?;
        let text = String::from_utf8_lossy(&banner);
        for (re, service, template) in &probe.matches {
            if let Some(caps) = re.captures(&text) {
                return Ok(Some(ServiceMatch {
                    probe: Some(probe.name),
                    service,
                    version: template.map(|t| render_version(t, &caps)),
                }));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_invariants() {
        // every pattern compiles (the table is committed data)
        let table = compiled_table();
        assert_eq!(table.len(), PROBE_TABLE.len());
        assert_eq!(table[0].name, "NULL");
        assert!(table[0].payload.is_none());
        assert_eq!(table[1].name, "HTTPGet");
        assert_eq!(table[1].payload, Some(&b"GET / HTTP/1.0\r\n\r\n"[..]));
        // every rule has a service name
        for p in table {
            assert!(!p.matches.is_empty(), "{} carries rules", p.name);
        }
    }

    #[test]
    fn ssh_banner_matches_null_probe() {
        let m = match_reply(0, b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n").unwrap();
        assert_eq!(m.service, "ssh");
        assert_eq!(
            m.version.as_deref(),
            Some("OpenSSH_9.6p1 Debian-3"),
            "{m:?}"
        );
    }

    #[test]
    fn ftp_and_smtp_banners() {
        let m = match_reply(0, b"220 (vsFTPd 3.0.3)\r\n").unwrap();
        // no literal "ftp" word in the banner → the smtp rule catches it
        assert_eq!(m.service, "smtp");
        assert_eq!(m.version.as_deref(), Some("(vsFTPd 3.0.3)"));
        let m2 = match_reply(0, b"220 mail.example.com ESMTP Postfix\r\n").unwrap();
        assert_eq!(m2.service, "smtp");
        assert_eq!(
            m2.version.as_deref(),
            Some("mail.example.com ESMTP Postfix")
        );
        // ftp rule ordered before smtp: an FTP banner naming ftp wins
        let m3 = match_reply(0, b"220 FTP Server (vsftpd)\r\n").unwrap();
        assert_eq!(m3.service, "ftp");
        // redis
        let m4 = match_reply(0, b"-ERR unknown command\r\n").unwrap();
        assert_eq!(m4.service, "redis");
    }

    #[test]
    fn http_server_header_and_status() {
        let reply = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx/1.24.0\r\n\r\nhi";
        let m = match_reply(1, reply).unwrap();
        assert_eq!(m.service, "http");
        assert_eq!(m.version.as_deref(), Some("nginx/1.24.0"));
        // no Server header → status line still identifies http
        let m2 = match_reply(1, b"HTTP/1.0 404 Not Found\r\n\r\n").unwrap();
        assert_eq!(m2.service, "http");
        assert_eq!(m2.version, None);
        // nothing http-shaped → no match
        assert!(match_reply(1, b"garbage\r\n").is_none());
        assert!(match_reply(0, b"garbage\r\n").is_none());
    }

    #[test]
    fn match_table_runs_probes_in_order() {
        let m = match_table(b"SSH-2.0-dropbear\r\n").unwrap();
        assert_eq!(m.service, "ssh");
        let m2 = match_table(b"HTTP/1.1 200 OK\r\n\r\n").unwrap();
        assert_eq!(m2.service, "http");
        assert!(match_table(b"\x00\x01\x02nothing").is_none());
    }

    #[test]
    fn version_template_substitution() {
        let re = regex::Regex::new(r"^v(\d+)\.(\d+) build (\w+)$").unwrap();
        let caps = re.captures("v1.2 build abc").unwrap();
        assert_eq!(render_version("$3-$1.$2", &caps), "abc-1.2");
        assert_eq!(render_version("no groups", &caps), "no groups");
        assert_eq!(render_version("$9", &caps), ""); // missing group → empty
        assert_eq!(render_version("$x", &caps), "$x"); // non-digit passes through
        assert_eq!(render_version("trailing$", &caps), "trailing$");
    }

    #[test]
    fn service_match_serde() {
        let m = ServiceMatch {
            probe: Some("NULL"),
            service: "ssh",
            version: Some("OpenSSH_9.6".into()),
        };
        let j = serde_json::to_value(&m).unwrap();
        assert_eq!(j["service"], "ssh");
        assert_eq!(j["probe"], "NULL");
        assert_eq!(j["version"], "OpenSSH_9.6");
        let bare = ServiceMatch {
            probe: None,
            service: "ftp",
            version: None,
        };
        let j2 = serde_json::to_value(&bare).unwrap();
        assert_eq!(j2["version"], serde_json::Value::Null);
    }
}
