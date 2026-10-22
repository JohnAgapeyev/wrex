#![no_main]
//! libFuzzer target: arbitrary received byte chunks + timeouts drive
//! one h2 client session (wrex-h2) over a two-request queue. Never
//! panics, sends a bounded number of frames, resolves at most one
//! outcome per stream, and always terminates once every deadline
//! fires (the fuzz_http_session lineage, transposed to h2).

use std::time::{Duration, Instant};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wrex_h2::H2Session;
use wrex_http::{HttpConfig, HttpRequestSpec};
use wrex_session::{Session, SessionAction};

/// One scripted event: a "wire" chunk, a timeout tick, or an orderly
/// EOF (the stream convention).
#[derive(Arbitrary, Debug)]
enum FuzzEvent {
    Chunk(Vec<u8>),
    Timeout(u32),
    Eof,
}

#[derive(Arbitrary, Debug)]
struct FuzzDrive {
    events: Vec<FuzzEvent>,
}

/// Small budget so the bounded-buffer invariant is observable.
const MAX_BYTES: usize = 512;

fuzz_target!(|drive: FuzzDrive| {
    let spec =
        HttpRequestSpec::build("GET", "https://fuzz.invalid/", &[], bytes::Bytes::new())
            .expect("static spec");
    let cfg = HttpConfig { timeout: Duration::from_secs(1), max_bytes: MAX_BYTES };
    let specs =
        [spec.clone(), spec];
    let t0 = Instant::now();
    let mut session =
        H2Session::new(&specs, &[cfg, cfg], t0).expect("static session");

    let mut sends = 0usize;
    let mut results = 0usize;
    while session.poll_action().is_some() {
        sends += 1;
        assert!(sends <= 16, "the preface + 2 HEADERS + bounded DATA");
    }

    let mut eof_seen = false;
    for event in &drive.events {
        if eof_seen {
            continue; // bytes after EOF are legal but ignored (late)
        }
        match event {
            FuzzEvent::Chunk(bytes) => {
                let frame = wrex_io::Frame {
                    bytes: bytes::Bytes::copy_from_slice(bytes),
                    iface: "fuzz".into(),
                    ts: std::time::SystemTime::UNIX_EPOCH,
                };
                session.on_frame(frame, t0 + Duration::from_millis(1));
            }
            FuzzEvent::Eof => {
                eof_seen = true;
                session.on_frame(
                    wrex_io::Frame {
                        bytes: bytes::Bytes::new(),
                        iface: "fuzz".into(),
                        ts: std::time::SystemTime::UNIX_EPOCH,
                    },
                    t0 + Duration::from_millis(2),
                );
            }
            FuzzEvent::Timeout(units) => {
                session.on_timeout(t0 + Duration::from_millis(u64::from(*units)));
            }
        }
        while let Some(action) = session.poll_action() {
            match action {
                SessionAction::Send(_) => {
                    sends += 1;
                    assert!(sends <= 4096, "bounded send queue");
                }
                _ => {} // non-exhaustive enum: future action kinds no-op
            }
        }
        while session.poll_result().is_some() {
            results += 1;
            assert!(results <= 2, "at most one outcome per stream");
        }
    }

    // Force every deadline so the state machine must terminate.
    for i in 0..32 {
        session.on_timeout(t0 + Duration::from_secs(i as u64 + 60));
        while session.poll_action().is_some() {}
    }
    let drained = std::iter::from_fn(|| session.poll_result()).count();
    assert!(results + drained <= 2, "at most one outcome per stream");
    assert!(session.next_timeout().is_none(), "session must reach Done");
});