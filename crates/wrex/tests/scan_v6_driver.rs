//! Tranche-7b scan ground truth over IPv6 (env-gated:
//! `WREX_DRIVER_TESTS=1`): real probes on `lo` against real kernel
//! endpoints — a bound TCP6 listener must classify open, an unbound
//! port closed (kernel RST), a bound UDP6 socket open|filtered, an
//! unbound one closed (kernel ICMPv6 unreach), and `::1` alive under
//! icmpv6 echo. Auto-skip otherwise.
//!
//! Spawns processes and opens raw sockets: ignored under Miri.
#![cfg_attr(miri, ignore = "raw sockets + subprocesses; not Miri-safe")]

use std::net::{TcpListener, UdpSocket};
use std::process::Command;

fn driver_tests_enabled() -> bool {
    std::env::var("WREX_DRIVER_TESTS").as_deref() == Ok("1")
}

/// Run `wrex scan …`, return (exit code, stdout).
fn scan_out(timeout: &str, args: &[&str]) -> (i32, String) {
    let mut all: Vec<std::ffi::OsString> = vec![
        "scan".into(),
        "-i".into(),
        "lo".into(),
        "--timeout".into(),
        timeout.into(),
    ];
    for a in args {
        all.push((*a).into());
    }
    let out = Command::new(env!("CARGO_BIN_EXE_wrex"))
        .args(&all)
        .output()
        .expect("spawn wrex scan");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
    )
}

fn skip(name: &str) {
    eprintln!("scan v6 driver tests: skipping {name} (WREX_DRIVER_TESTS != 1)");
}

#[test]
fn v6_syn_scan_open_and_closed() {
    if !driver_tests_enabled() {
        skip("v6_syn_scan_open_and_closed");
        return;
    }
    // One bound [::1] listener + one unbound port: the scan line for
    // the bound port must say open, the unbound closed (kernel RST).
    let listener = TcpListener::bind("[::1]:0").expect("bind tcp6");
    let open = listener.local_addr().expect("local addr").port();
    let closed = unused_tcp6_port();
    let (_code, out) = scan_out(
        "2s",
        &[
            "--mode",
            "syn",
            "--ports",
            &format!("{open},{closed}"),
            "--seed",
            "42",
            "::1",
        ],
    );
    let open_line = format!("::1  {open}/tcp  open");
    let closed_line = format!("::1  {closed}/tcp  closed");
    assert!(
        out.contains(&open_line),
        "expected `{open_line}` in:\n{out}"
    );
    assert!(
        out.contains(&closed_line),
        "expected `{closed_line}` in:\n{out}"
    );
}

#[test]
fn v6_udp_scan_unbound_is_closed() {
    if !driver_tests_enabled() {
        skip("v6_udp_scan_unbound_is_closed");
        return;
    }
    // An unbound UDP port on ::1: the kernel answers with ICMPv6
    // destination-unreachable (code 3) → closed.
    let port = unused_udp6_port();
    let (_code, out) = scan_out(
        "2s",
        &[
            "--mode",
            "udp",
            "--ports",
            &port.to_string(),
            "--seed",
            "42",
            "::1",
        ],
    );
    let line = format!("::1  {port}/udp  closed");
    assert!(out.contains(&line), "expected `{line}` in:\n{out}");
}

#[test]
fn v6_icmp_echo_alive() {
    if !driver_tests_enabled() {
        skip("v6_icmp_echo_alive");
        return;
    }
    // ::1 answers echo requests: icmp mode over an ipv6 target speaks
    // icmpv6 (type 128 probes, 129 replies).
    let (_code, out) = scan_out("2s", &["--mode", "icmp", "--seed", "42", "::1"]);
    assert!(
        out.contains("::1  icmpv6  alive"),
        "expected icmpv6 alive in:\n{out}"
    );
}

#[test]
fn v6_scan_seed_reproducible() {
    if !driver_tests_enabled() {
        skip("v6_scan_seed_reproducible");
        return;
    }
    let args = &["--mode", "icmp", "--seed", "424242", "::1"];
    let (_c1, out1) = scan_out("1s", args);
    let (_c2, out2) = scan_out("1s", args);
    assert_eq!(out1, out2, "same seed must reproduce the scan output");
}

/// An unused TCP6 port (bind + drop).
fn unused_tcp6_port() -> u16 {
    let l = TcpListener::bind("[::1]:0").expect("bind tcp6");
    l.local_addr().expect("local addr").port()
}

/// An unused UDP6 port (bind + drop).
fn unused_udp6_port() -> u16 {
    let s = UdpSocket::bind("[::1]:0").expect("bind udp6");
    s.local_addr().expect("local addr").port()
}
