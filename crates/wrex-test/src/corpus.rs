//! Corpus: `wrex-test/corpus/<capture>/{manifest.toml, frames/NN.bin,
//! NN.expected.json}` — multi-frame golden dissections.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use wrex_core::dissect::DissectedPacket;
use wrex_core::render::dissect_to_json;

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub source_url: String,
    pub imported: String,
    pub start: String,
    pub frames: Vec<String>,
}

#[derive(Debug)]
pub struct CorpusFrame {
    pub name: String,
    pub bytes: Vec<u8>,
    pub expected: serde_json::Value,
}

#[derive(Debug)]
pub struct Corpus {
    pub name: String,
    pub manifest: Manifest,
    pub root: PathBuf,
    pub frames: Vec<CorpusFrame>,
}

impl Corpus {
    /// Load a corpus directory by name (`wrex-test/corpus/<name>`).
    pub fn load(name: &str) -> Option<Corpus> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("corpus")
            .join(name);
        let manifest_raw = std::fs::read_to_string(root.join("manifest.toml")).ok()?;
        let manifest: Manifest = toml::from_str(&manifest_raw).ok()?;
        let mut frames = Vec::new();
        for fname in &manifest.frames {
            let bytes = std::fs::read(root.join("frames").join(format!("{fname}.bin"))).ok()?;
            let expected_raw =
                std::fs::read_to_string(root.join("frames").join(format!("{fname}.expected.json")))
                    .ok()?;
            let expected: serde_json::Value = serde_json::from_str(&expected_raw).ok()?;
            frames.push(CorpusFrame {
                name: fname.clone(),
                bytes,
                expected,
            });
        }
        Some(Corpus {
            name: name.to_string(),
            manifest,
            root,
            frames,
        })
    }

    /// List every corpus directory.
    pub fn load_all() -> Vec<Corpus> {
        let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&corpus_root) {
            for dent in rd.flatten() {
                if dent.path().join("manifest.toml").is_file()
                    && let Some(c) =
                        Corpus::load(dent.file_name().to_string_lossy().to_string().as_str())
                {
                    out.push(c);
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

/// Compare our dissection of a corpus frame with the expected JSON.
pub fn matches_expected(frame: &CorpusFrame, actual: &DissectedPacket) -> Result<(), String> {
    let got = dissect_to_json(actual);
    let got_raw = serde_json::to_string(&got).map_err(|e| e.to_string())?;
    let want_raw = serde_json::to_string(&frame.expected).map_err(|e| e.to_string())?;
    // Canonicalize key order by parsing into serde_json::Value.
    let got_v: serde_json::Value = serde_json::from_str(&got_raw).map_err(|e| e.to_string())?;
    let got_canon = serde_json::to_string(&got_v).map_err(|e| e.to_string())?;
    let want_canon = {
        let w: serde_json::Value = serde_json::from_str(&want_raw).map_err(|e| e.to_string())?;
        serde_json::to_string(&w).map_err(|e| e.to_string())?
    };
    if got_canon == want_canon {
        Ok(())
    } else {
        Err(format!(
            "corpus frame {}: dissection differs\n got: {got_canon}\nwant: {want_canon}",
            frame.name
        ))
    }
}

/// Import a classic pcap into a corpus dir (dev-time). Frames are split by
/// the in-house classic-pcap reader below (no tshark needed); the first
/// 16 frames are committed (the corpus is a seed set, not an archive).
pub fn import(pcap: &Path, name: &str) -> Result<PathBuf, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("corpus")
        .join(name);
    let frames_dir = root.join("frames");
    std::fs::create_dir_all(&frames_dir).map_err(|e| e.to_string())?;
    let pcap_bytes = std::fs::read(pcap).map_err(|e| format!("read {}: {e}", pcap.display()))?;
    let frames = read_classic_pcap(&pcap_bytes)?;
    let mut frame_names = Vec::new();
    for (i, bytes) in frames.iter().take(MAX_FRAMES).enumerate() {
        let fname = format!("{:02}", i + 1);
        std::fs::write(frames_dir.join(format!("{fname}.bin")), bytes)
            .map_err(|e| e.to_string())?;
        // Golden expected dissection via our own engine.
        let registry = wrex::standard();
        let packet = wrex_core::dissect::dissect(&registry, bytes, "auto");
        let expected = serde_json::to_string_pretty(&wrex_core::render::dissect_to_json(&packet))
            .map_err(|e| e.to_string())?;
        std::fs::write(
            frames_dir.join(format!("{fname}.expected.json")),
            expected + "\n",
        )
        .map_err(|e| e.to_string())?;
        frame_names.push(fname);
    }
    let manifest = format!(
        "source_url = {pcap:?}\nimported = {today:?}\nstart = \"auto\"\nframes = {frames:?}\n",
        pcap = pcap.display().to_string(),
        today = chrono_today(),
        frames = frame_names,
    );
    std::fs::write(root.join("manifest.toml"), manifest).map_err(|e| e.to_string())?;
    Ok(root)
}

/// Committed frames per corpus capture.
pub const MAX_FRAMES: usize = 16;

/// Parse a classic pcap file into raw frames (all endianness/nanosecond
/// magic variants). Delegates to `wrex-pcap` (the tranche-5 shared
/// reader); timestamps are kept there — the corpus only needs bytes.
pub fn read_classic_pcap(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let file = wrex_pcap::read(bytes).map_err(|e| e.to_string())?;
    Ok(file.records.into_iter().map(|r| r.bytes).collect())
}

fn chrono_today() -> String {
    // No chrono dep: read the date from the environment `date` command.
    let out = std::process::Command::new("date").arg("+%Y-%m-%d").output();
    match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => "1970-01-01".to_string(),
    }
}
