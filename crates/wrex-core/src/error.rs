use thiserror::Error;

/// Malformed user request: unknown layer/field, bad value, invalid stack.
/// CLI maps this to exit code 2.
#[derive(Debug, Error)]
pub enum SpecError {
    #[error("unknown layer `{wanted}` (known: {known})")]
    UnknownLayer { wanted: String, known: String },
    #[error("unknown field `{layer}.{path}`")]
    UnknownField { layer: &'static str, path: String },
    #[error("bad value for `{path}`: `{raw}`: {reason}")]
    BadValue {
        path: String,
        raw: String,
        reason: String,
    },
    #[error("invalid stack: {detail}")]
    InvalidStack { detail: String },
}

/// A spec that cannot be encoded: missing required field or a layer order
/// that no codec can write. CLI maps this to exit code 2.
#[derive(Debug, Error)]
pub enum EncodeError {
    #[error("unfillable field `{field}`: required and not set")]
    Unfillable { field: String },
    #[error("incompatible stack: {detail}")]
    IncompatibleStack { detail: String },
}

/// Internal decode failure. Never returned to callers; surfaced as an
/// [`crate::dissect::Anomaly`] instead.
#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("truncated {kind}: need {need} bytes, have {have}")]
    Truncated {
        kind: &'static str,
        need: usize,
        have: usize,
    },
    #[error("bad field `{path}`: {reason}")]
    BadField { path: String, reason: String },
    #[error("unsupported {kind}")]
    Unsupported { kind: &'static str },
}

/// Bad filter term on `wrex recv --filter` / `--wait-reply --filter`.
/// CLI maps this to exit code 2.
#[derive(Debug, Error)]
pub enum FilterError {
    #[error("bad filter term `{term}`: {reason}")]
    BadTerm { term: String, reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderings() {
        let e = SpecError::UnknownLayer {
            wanted: "ipx".into(),
            known: "eth, ipv4".into(),
        };
        assert_eq!(e.to_string(), "unknown layer `ipx` (known: eth, ipv4)");
        let e = SpecError::BadValue {
            path: "tcp.flags".into(),
            raw: "sny".into(),
            reason: "x".into(),
        };
        assert!(
            e.to_string()
                .starts_with("bad value for `tcp.flags`: `sny`")
        );
        let e = EncodeError::Unfillable {
            field: "arp.tpa".into(),
        };
        assert_eq!(
            e.to_string(),
            "unfillable field `arp.tpa`: required and not set"
        );
        let e = DecodeError::Truncated {
            kind: "ipv4",
            need: 20,
            have: 13,
        };
        assert_eq!(e.to_string(), "truncated ipv4: need 20 bytes, have 13");
        let e = FilterError::BadTerm {
            term: "tcp.port".into(),
            reason: "no operator".into(),
        };
        assert!(e.to_string().contains("bad filter term `tcp.port`"));
    }
}
