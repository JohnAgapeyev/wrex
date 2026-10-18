//! Integration suite: craft→dissect pipeline, byte transparency, strict
//! exit codes, spec-grammar equivalence, fields output, empty/zero-layer
//! errors, corpus goldens. Driver (socket) tests live in `driver.rs`.
//!
//! Every test here spawns the `wrex` binary: not Miri-safe as a unit, so
//! the file is ignored under Miri (the deterministic engine/codec unit
//! tests in the lib targets run under Miri instead).
#![cfg_attr(miri, ignore = "spawns the wrex binary; engine units cover Miri")]
use assert_cmd::Command;
use predicates::str::contains;

fn wrex() -> assert_cmd::Command {
    Command::new(env!("CARGO_BIN_EXE_wrex"))
}

const GOLDEN_HEX: &str =
    "ffffffffffff0000000000000800450000200000000040117ccb7f0000017f000001115c15b3000c3d27deadbeef";

const GOLDEN_ARGS: &[&str] = &[
    "--layer",
    "eth",
    "--layer",
    "ipv4",
    "--layer",
    "udp",
    "--eth-dst=ff:ff:ff:ff:ff:ff",
    "--ipv4-src=127.0.0.1",
    "--ipv4-dst=127.0.0.1",
    "--udp-sport=4444",
    "--udp-dport=5555",
    "--payload=hex:deadbeef",
];

const GOLDEN_ARGS_IMPLIED: &[&str] = &[
    "--eth-dst=ff:ff:ff:ff:ff:ff",
    "--ipv4-src=127.0.0.1",
    "--ipv4-dst=127.0.0.1",
    "--udp-sport=4444",
    "--udp-dport=5555",
    "--payload=hex:deadbeef",
];

/// §Verification 2: the golden craft (explicit + implied --layer modes).
#[test]
fn golden_craft_explicit_and_implied() {
    let mut explicit = vec!["craft".to_string(), "--format".into(), "hex".into()];
    explicit.extend(GOLDEN_ARGS.iter().map(|s| s.to_string()));
    let out = wrex().args(&explicit).assert().success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert_eq!(stdout.trim(), GOLDEN_HEX);

    let mut implied = vec!["craft".to_string(), "--format".into(), "hex".into()];
    implied.extend(GOLDEN_ARGS_IMPLIED.iter().map(|s| s.to_string()));
    let out2 = wrex().args(&implied).assert().success();
    let stdout2 = String::from_utf8(out2.get_output().stdout.clone()).unwrap();
    assert_eq!(stdout2.trim(), GOLDEN_HEX);
}

/// §Verification 3: round-trip through dissect; --strict exit codes.
#[test]
fn dissect_roundtrip_and_strict() {
    let mut craft_args = vec!["craft".to_string()];
    craft_args.extend(GOLDEN_ARGS.iter().map(|s| s.to_string()));
    let bytes = wrex()
        .args(&craft_args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    // dissect --format json
    let json_out = wrex()
        .args(["dissect", "--format", "json"])
        .write_stdin(bytes.clone())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&json_out).unwrap();
    assert_eq!(json["start"], "eth");
    let kinds: Vec<&str> = json["layers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, vec!["eth", "ipv4", "udp"]);
    assert_eq!(json["payload_hex"], "deadbeef");
    assert_eq!(json["anomalies"].as_array().unwrap().len(), 0);

    // --strict on the valid packet → exit 0
    wrex()
        .args(["dissect", "--strict"])
        .write_stdin(bytes.clone())
        .assert()
        .success();

    // Corrupt the UDP checksum byte → anomaly present.
    let mut corrupt = bytes.clone();
    corrupt[40] ^= 0xff; // udp checksum high byte
    let plain = wrex()
        .args(["dissect", "--format", "text"])
        .write_stdin(corrupt.clone())
        .assert()
        .success();
    let stdout = String::from_utf8(plain.get_output().stdout.clone()).unwrap();
    assert!(stdout.contains("udp.checksum"), "{stdout}");

    // exit 0 without --strict, exit 1 with it
    wrex()
        .args(["dissect"])
        .write_stdin(corrupt.clone())
        .assert()
        .code(0);
    wrex()
        .args(["dissect", "--strict"])
        .write_stdin(corrupt)
        .assert()
        .code(1);
}

/// §Verification 4: raw pipeline byte-transparency + truncated start.
#[test]
fn byte_transparency() {
    let mut raw_args = vec!["craft".to_string(), "--format".into(), "raw".into()];
    raw_args.extend(GOLDEN_ARGS.iter().map(|s| s.to_string()));
    let raw = wrex()
        .args(&raw_args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let piped = wrex()
        .args(["dissect", "--format", "hex"])
        .write_stdin(raw)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let craft_hex_out = wrex()
        .args(["craft", "--format", "hex"])
        .args(GOLDEN_ARGS)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    // Both sides are ASCII hex lines (with trailing newline): compare
    // directly — hex-encoding the already-hex string would double-encode.
    let hex_line = String::from_utf8(craft_hex_out).unwrap();
    assert_eq!(String::from_utf8(piped).unwrap().trim(), hex_line.trim());

    // truncated 14-byte eth frame: no panic, exit 0
    let trunc: Vec<u8> = vec![0xff; 6]
        .into_iter()
        .chain([0; 6])
        .chain([0x08, 0x00])
        .collect();
    wrex()
        .args(["dissect", "--format", "text"])
        .write_stdin(trunc)
        .assert()
        .code(0);
}

#[test]
fn strict_craft_invalid_packet_exits_2() {
    // ihl=4 (invalid) + bogus checksum: exit 2 under --strict, exit 0 without
    let bad = [
        "craft",
        "--strict",
        "--layer",
        "ipv4",
        "--ipv4-ihl=4",
        "--ipv4-checksum=0xdead",
        "--ipv4-total_len=999",
        "--ipv4-src=1.2.3.4",
        "--ipv4-dst=5.6.7.8",
    ];
    let out = wrex().args(bad).assert().code(2);
    let stderr = String::from_utf8(out.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("ipv4.ihl"), "{stderr}");
    assert!(stderr.contains("ipv4.checksum"), "{stderr}");
    assert!(stderr.contains("ipv4.total_len"), "{stderr}");

    // Same without --strict: encodes fine (deliberate invalid packets).
    let mut lax = bad.to_vec();
    lax.remove(1); // drop --strict
    wrex().args(&lax).assert().code(0);
}

#[test]
fn zero_layers_and_empty_stdin_exit_2() {
    // payload-only → zero layers → exit 2
    wrex()
        .args(["craft", "--payload=hex:00"])
        .assert()
        .failure()
        .code(2);
    // empty stdin dissect → exit 2
    wrex()
        .args(["dissect"])
        .write_stdin(vec![])
        .assert()
        .failure()
        .code(2);
}

#[test]
fn unknown_layer_and_bad_chain_exit_2() {
    wrex()
        .args(["craft", "--layer", "ipx"])
        .assert()
        .failure()
        .code(2);
    wrex()
        .args(["craft", "--layer", "eth", "--layer", "tcp", "--tcp-sport=1"])
        .assert()
        .failure()
        .code(2)
        .stderr(contains("tcp requires parent ipv4"));
}

#[test]
fn fields_verb_lists_registry() {
    let out = wrex()
        .args(["fields", "tcp"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("tcp"), "{text}");
    assert!(text.contains("flags"), "{text}");
    // per-bit flags are settable through the CLI grammar
    let all = wrex().args(["fields"]).assert().success();
    let text_all = String::from_utf8(all.get_output().stdout.clone()).unwrap();
    for k in ["eth", "arp", "ipv4", "icmp", "udp", "tcp"] {
        assert!(text_all.contains(k), "missing {k} in fields output");
    }
    // unknown kind → exit 2
    wrex().args(["fields", "ipx"]).assert().failure().code(2);
}

#[test]
fn iface_verb() {
    let out = wrex()
        .args(["iface"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("lo"), "{text}");
    // unknown iface name → exit 1
    wrex()
        .args(["iface", "definitely-not-here999"])
        .assert()
        .failure()
        .code(1);
}

/// Corpus golden tests: every imported frame dissects byte-equal to its
/// committed expected JSON, and both oracles agree (differential).
#[test]
fn corpus_goldens() {
    let corpora = wrex_test::corpus::Corpus::load_all();
    assert!(
        corpora.len() >= 4,
        "expected at least 4 corpora, found {}",
        corpora.len()
    );
    let mut checked = 0;
    for corpus in &corpora {
        for frame in &corpus.frames {
            let registry = wrex::standard();
            let packet =
                wrex_core::dissect::dissect(&registry, &frame.bytes, &corpus.manifest.start);
            wrex_test::corpus::matches_expected(frame, &packet)
                .unwrap_or_else(|e| panic!("corpus {}/{}: {e}", corpus.name, frame.name));
            let failures = wrex_test::oracle::check_all_oracles(&frame.bytes, &packet);
            assert!(
                failures.is_empty(),
                "corpus {}/{} oracle diffs: {failures:?}",
                corpus.name,
                frame.name
            );
            checked += 1;
        }
    }
    assert!(checked >= 16, "only {checked} corpus frames checked");
}

/// Discoverability: the field flags are not clap args, so their grammar
/// must be documented in --help; `completions` must emit a script.
#[test]
fn help_documents_field_flags_and_completions_emit() {
    let craft_help = String::from_utf8(
        wrex()
            .args(["craft", "--help"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    for needle in [
        "FIELD FLAGS",
        "--layer",
        "--payload",
        "wrex fields",
        "EXAMPLES",
    ] {
        assert!(
            craft_help.contains(needle),
            "craft --help must mention {needle:?}"
        );
    }

    let root_help = String::from_utf8(
        wrex()
            .args(["--help"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    for needle in ["EXIT CODES", "VALUE GRAMMAR", "completions"] {
        assert!(root_help.contains(needle), "--help must mention {needle:?}");
    }

    let completions = String::from_utf8(
        wrex()
            .args(["completions", "bash"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(!completions.is_empty() && completions.contains("wrex"));
}
