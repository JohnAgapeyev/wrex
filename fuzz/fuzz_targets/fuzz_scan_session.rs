#![no_main]
//! libFuzzer target: arbitrary bytes drive a scan session's event stream
//! (frames + timeouts under a fake clock). Invariants: no panics,
//! every probe resolves exactly once, the send count stays bounded,
//! and the session goes idle.

use std::time::{Duration, Instant};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wrex::standard;
use wrex_scan::{ScanConfig, ScanMode, ScanSession};
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
}

fn cfg(seed: u64, retries: u32) -> ScanConfig {
    ScanConfig::build(
        ScanMode::Syn,
        &["127.0.0.1".to_string()],
        Some("1,2,3"),
        Duration::ZERO, // burst
        Duration::ZERO,
        seed,
        retries,
        Duration::from_secs(1),
        256,
    )
    .expect("static config")
}

fuzz_target!(|drive: FuzzDrive| {
    let registry = standard();
    let retries = u32::from(drive.retries);
    let mut session = ScanSession::new(&registry, cfg(0xC0FFEE, retries), SRC, Instant::now())
        .unwrap();
    let probe_count = 3usize;

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
            // probes × (retries+1) + follow-up RSTs (one per open probe)
            assert!(
                sends <= probe_count * (retries as usize + 2),
                "send bound exceeded"
            );
        }
    }
    // Exhaust remaining deadlines deterministically.
    for i in 0..(retries + 4) {
        session.on_timeout(t + Duration::from_secs(u64::from(i)));
        while session.poll_action().is_some() {
            sends += 1;
            assert!(sends <= probe_count * (retries as usize + 2) + 1);
        }
    }
    let mut results = 0usize;
    while session.poll_result().is_some() {
        results += 1;
    }
    assert_eq!(results, probe_count, "every probe resolves exactly once");
    assert!(session.next_timeout().is_none(), "session must go idle");
});

const SRC: wrex_scan::ScanAddr = wrex_scan::ScanAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));