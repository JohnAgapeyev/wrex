//! CLI test harness: assert_cmd wrappers over the `wrex` binary.

use assert_cmd::Command;

/// Path to the built `wrex` binary (`CARGO_BIN_EXE_wrex` in integration
/// tests; plain `wrex` via PATH fallback for other callers).
pub fn wrex_bin() -> Command {
    Command::new(option_env!("CARGO_BIN_EXE_wrex").unwrap_or("wrex"))
}

/// Run `wrex <args>` and return stdout bytes (panics on failure).
pub fn craft_bytes<I, S>(args: I) -> Vec<u8>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut cmd = wrex_bin();
    let out = cmd.args(args).assert().success();
    out.get_output().stdout.clone()
}

/// `craft --format hex` → hex string (no trailing newline trimmed).
pub fn craft_hex<I, S>(args: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let mut all: Vec<std::ffi::OsString> = vec!["craft".into(), "--format".into(), "hex".into()];
    all.extend(args.into_iter().map(|s| s.as_ref().to_owned()));
    String::from_utf8(craft_bytes(all)).expect("utf8")
}

/// `dissect` with stdin bytes → text stdout (panics on failure).
pub fn dissect(bytes: &[u8], args: &[&str]) -> String {
    let mut all: Vec<std::ffi::OsString> = vec!["dissect".into()];
    for a in args {
        all.push((*a).into());
    }
    let mut cmd = wrex_bin();
    let out = cmd
        .args(&all)
        .write_stdin(bytes.to_vec())
        .assert()
        .success();
    String::from_utf8(out.get_output().stdout.clone()).expect("utf8")
}

/// Capability probe for the env-gated driver suites: `lo` must exist
/// and (with `v6`) the IPv6 loopback `::1` must be bindable. A runner
/// without loopback or IPv6 is an environment problem, not a
/// regression — callers skip with a notice instead of failing.
pub fn loopback_ready(v6: bool) -> bool {
    if !std::path::Path::new("/sys/class/net/lo").exists() {
        eprintln!("driver tests: skipping (no lo interface on this runner)");
        return false;
    }
    if v6 && std::net::UdpSocket::bind("[::1]:0").is_err() {
        eprintln!("driver tests: skipping (IPv6 loopback unavailable)");
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    #[test]
    fn harness_paths_resolve() {
        assert!(!crate::harness::wrex_bin().get_program().is_empty());
    }
}
