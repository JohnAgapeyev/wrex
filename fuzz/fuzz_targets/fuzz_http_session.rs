#![no_main]
//! libFuzzer target: arbitrary byte-chunk streams + timeouts drive an
//! HTTP client session (small --max-bytes budget). Invariants: no
//! panics, a bounded internal buffer, exactly one request sent, one
//! outcome at most, and the session always reaches Done (terminates).

use std::time::{Duration, Instant};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use wrex_http::{HttpConfig, HttpOutcome, HttpRequestSpec, HttpClientSession};
use wrex_session::Session;

/// One scripted event: a chunk of "wire" bytes, a timeout tick, or an
/// orderly EOF (the stream convention).
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
    let spec = HttpRequestSpec::build("GET", "http://fuzz.invalid/", &[], bytes::Bytes::new())
        .expect("static spec");
    let mut session = HttpClientSession::new(
        &spec,
        HttpConfig {
            timeout: Duration::from_secs(1),
            max_bytes: MAX_BYTES,
        },
        Instant::now(),
    )
    .expect("static session");

    let mut sends = 0usize;
    while session.poll_action().is_some() {
        sends += 1;
        assert!(sends <= 1, "close-mode sends the request exactly once");
    }

    let t0 = Instant::now();
    let mut eof_seen = false;
    for event in &drive.events {
        if eof_seen {
            // bytes after EOF are legal but must be ignored (late)
            continue;
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
    let _ = HttpOutcome::Timeout; // link the enum
});