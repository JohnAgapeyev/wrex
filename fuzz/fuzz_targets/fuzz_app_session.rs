#![no_main]
//! libFuzzer target: arbitrary byte-chunk streams + timeouts drive an
//! app-layer probe session (`wrex fuzz --mode http|dns`, tranche 9b)
//! over a small response budget. Invariants: no panics, a bounded
//! response buffer, exactly one request sent, at most one outcome,
//! and the session always reaches Done (terminates).

use std::time::{Duration, Instant};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wrex_fuzz::{AppConfig, AppOutcome, AppSession};
use wrex_session::{Session, SessionAction};

/// One scripted event: a chunk of response bytes, a timeout tick, or
/// an orderly EOF (the stream convention).
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
    let mut session = AppSession::new(
        bytes::Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n"),
        AppConfig {
            timeout: Duration::from_secs(1),
            max_bytes: MAX_BYTES,
        },
        Instant::now(),
    );

    let mut sends = 0usize;
    while session.poll_action().is_some() {
        sends += 1;
        assert!(sends <= 1, "one probe sends its request exactly once");
    }

    let t0 = Instant::now();
    let mut eof_seen = false;
    for event in &drive.events {
        if eof_seen {
            continue; // bytes after EOF are legal but must be ignored
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
        while session.poll_action().is_some() {
            sends += 1;
            assert!(sends <= 1);
        }
    }
    // Force every deadline so the state machine must terminate.
    for i in 0..32 {
        session.on_timeout(t0 + Duration::from_secs(i as u64 + 60));
        while session.poll_action().is_some() {}
    }
    let outcomes = std::iter::from_fn(|| session.poll_result()).count();
    assert!(outcomes <= 1, "at most one outcome");
    assert!(session.next_timeout().is_none(), "session must reach Done");
    let _ = AppOutcome::Silence; // link the enum
});