//! Duration parsing for `--interval` / `--timeout` (units `ms|s|m`).

use std::time::Duration;

/// Parse a duration: `500ms`, `2s`, `5m`; a bare number is seconds.
pub fn parse_duration(raw: &str) -> Result<Duration, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty duration".to_string());
    }
    let (num, unit) = if let Some(n) = raw.strip_suffix("ms").or_else(|| raw.strip_suffix("MS")) {
        (n.trim(), "ms")
    } else if let Some(n) = raw.strip_suffix('s').or_else(|| raw.strip_suffix('S')) {
        (n.trim(), "s")
    } else if let Some(n) = raw.strip_suffix('m').or_else(|| raw.strip_suffix('M')) {
        (n.trim(), "m")
    } else {
        (raw, "s")
    };
    let n: u64 = num.parse().map_err(|_| format!("bad duration `{raw}`"))?;
    match unit {
        "ms" => Ok(Duration::from_millis(n)),
        "s" => Ok(Duration::from_secs(n)),
        "m" => Ok(Duration::from_secs(n * 60)),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units() {
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("3").unwrap(), Duration::from_secs(3));
        assert_eq!(parse_duration(" 1s ").unwrap(), Duration::from_secs(1));
    }

    #[test]
    fn errors() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("1.5s").is_err()); // fractional unsupported
        assert!(parse_duration("-1s").is_err());
        assert!(parse_duration("99999999999999999999999s").is_err());
    }
}
