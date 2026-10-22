#![no_main]
//! libFuzzer target: arbitrary bytes drive a prober session's event
//! stream (frames + timeouts under a moving clock). Invariants: no
//! panics, every probe resolves to exactly one finding, the send
//! count stays bounded, and the session goes idle.

use std::time::{Duration, Instant};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wrex::standard;
use wrex_fuzz::{FuzzConfig, ProbeMode, ProberSession};
use wrex_mut::Strategy;
use wrex_session::{Session, SessionAction};

/// One scripted event: a frame (raw bytes) or a timeout tick.
#[derive(Arbitrary, Debug)]
enum FuzzEvent {
    Frame(Vec<u8>),
    Timeout(u32),
}

#[derive(Arbitrary, Debug)]
struct FuzzDrive {
    events: Vec<FuzzEvent>,
    retries: bool,
    baseline: bool,
}

fn cfg(retries: u32, baseline: bool) -> FuzzConfig {
    FuzzConfig::build(
        ProbeMode::Udp,
        &["127.0.0.1".to_string()],
        Some("53"),
        2, // mutated rounds
        baseline,
        Strategy::All,
        Duration::ZERO, // burst
        Duration::ZERO,
        0xC0FFEE,
        retries,
        Duration::from_secs(1),
        256,
        false,
    )
    .expect("static config")
}

const SRC: wrex_scan::ScanAddr = wrex_scan::ScanAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

fuzz_target!(|drive: FuzzDrive| {
    let registry = standard();
    let retries = u32::from(drive.retries);
    let baseline = drive.baseline;
    let mut session =
        ProberSession::new(&registry, cfg(retries, baseline), SRC, Instant::now()).unwrap();
    // baseline(when asked) + 2 mutated rounds per slot.
    let probe_count = 2 + usize::from(baseline);

    let mut sends = 0usize;
    while session.poll_action().is_some() {
        sends += 1;
        assert!(sends <= probe_count, "burst send bound exceeded");
    }

    let mut t = Instant::now();
    for event in &drive.events {
        match event {
            FuzzEvent::Frame(bytes) => {
                let frame = wrex_io::Frame {
                    bytes: bytes::Bytes::copy_from_slice(bytes),
                    iface: "fuzz".into(),
                    ts: std::time::SystemTime::UNIX_EPOCH,
                };
                session.on_frame(frame, t);
            }
            FuzzEvent::Timeout(units) => {
                t += Duration::from_millis(u64::from(*units));
                session.on_timeout(t);
            }
        }
        while let Some(SessionAction::Send(_)) = session.poll_action() {
            sends += 1;
            assert!(
                sends <= probe_count * (retries as usize + 1),
                "send bound exceeded"
            );
        }
    }
    // Exhaust remaining deadlines deterministically.
    for i in 0..(retries + 4) {
        session.on_timeout(t + Duration::from_secs(u64::from(i)));
        while let Some(SessionAction::Send(_)) = session.poll_action() {
            sends += 1;
            assert!(sends <= probe_count * (retries as usize + 1));
        }
    }
    let mut findings = 0usize;
    while session.poll_result().is_some() {
        findings += 1;
    }
    assert_eq!(findings, probe_count, "every probe resolves exactly once");
    assert!(session.next_timeout().is_none(), "session must go idle");
});