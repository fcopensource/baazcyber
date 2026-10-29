//! Quarantine: move a threat somewhere it can't run and other antivirus software won't trip over it.
//!
//! The file's bytes are XOR-encoded (so it is no longer an executable, and scanners skip it) and stored with a
//! small JSON record of where it came from. Restoring reverses the encoding and puts it back.

use crate::{hex, Threat};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The byte used to encode quarantined files. It only has to stop the file being a runnable program and keep
/// other scanners away; it is not secret and not security.
const XOR_KEY: u8 = 0x6b;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    /// Where the file was before it was quarantined.
    pub original_path: PathBuf,
    pub original_name: String,
    pub size: u64,
    pub sha256: String,
    pub threat_name: String,
    pub quarantined_at: u64,
    pub reasons: Vec<String>,
}

pub struct Quarantine {
    dir: PathBuf,
}

impl Quarantine {
    /// Open or create the quarantine folder (for example %LOCALAPPDATA%\BaazCyber\Quarantine).
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(dir.join("files"))?;
        fs::create_dir_all(dir.join("meta"))?;
        Ok(Self { dir })
    }

    fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }

    /// Move a file into quarantine. The original is removed only after the encoded copy is safely written.
    pub fn add(&self, path: &Path, sha256: &str, threat: &Threat) -> io::Result<QuarantineEntry> {
        let meta = fs::metadata(path)?;
        let id = format!("{}-{}", Self::now(), &sha256_or_random(sha256)[..16.min(sha256_or_random(sha256).len())]);
        let original_name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: path.to_path_buf(),
            original_name,
            size: meta.len(),
            sha256: sha256.to_string(),
            threat_name: threat.name.clone(),
            quarantined_at: Self::now(),
            reasons: threat.reasons.clone(),
        };
        // Write the encoded bytes first, then the record, then delete the original.
        let encoded = self.dir.join("files").join(format!("{id}.quarantine"));
        encode_file(path, &encoded)?;
        let meta_path = self.dir.join("meta").join(format!("{id}.json"));
        fs::write(&meta_path, serde_json::to_vec_pretty(&entry)?)?;
        if let Err(e) = fs::remove_file(path) {
            // Couldn't remove the original: undo so we don't keep two copies.
            let _ = fs::remove_file(&encoded);
            let _ = fs::remove_file(&meta_path);
            return Err(e);
        }
        Ok(entry)
    }

    pub fn list(&self) -> io::Result<Vec<QuarantineEntry>> {
        let mut entries = Vec::new();
        for item in fs::read_dir(self.dir.join("meta"))? {
            let path = item?.path();
            if path.extension().is_some_and(|e| e == "json") {
                if let Ok(entry) = serde_json::from_slice::<QuarantineEntry>(&fs::read(&path)?) { entries.push(entry); }
            }
        }
        entries.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at));
        Ok(entries)
    }

    fn entry(&self, id: &str) -> io::Result<QuarantineEntry> {
        let data = fs::read(self.dir.join("meta").join(format!("{id}.json")))?;
        serde_json::from_slice(&data).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Put a quarantined file back where it came from. Fails if something is already at that path.
    pub fn restore(&self, id: &str) -> io::Result<PathBuf> {
        let entry = self.entry(id)?;
        if entry.original_path.exists() {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "a file already exists at the original location"));
        }
        if let Some(parent) = entry.original_path.parent() { fs::create_dir_all(parent)?; }
        decode_file(&self.dir.join("files").join(format!("{id}.quarantine")), &entry.original_path)?;
        self.forget(id)?;
        Ok(entry.original_path)
    }

    /// Delete a quarantined file for good.
    pub fn delete(&self, id: &str) -> io::Result<()> {
        let _ = fs::remove_file(self.dir.join("files").join(format!("{id}.quarantine")));
        self.forget(id)
    }

    fn forget(&self, id: &str) -> io::Result<()> {
        fs::remove_file(self.dir.join("meta").join(format!("{id}.json")))?;
        let _ = fs::remove_file(self.dir.join("files").join(format!("{id}.quarantine")));
        Ok(())
    }
}

fn sha256_or_random(sha: &str) -> String {
    if sha.len() == 64 { sha.to_string() } else { hex(&Quarantine::now().to_le_bytes()) }
}

fn encode_file(src: &Path, dst: &Path) -> io::Result<()> {
    let mut input = fs::File::open(src)?;
    let mut output = fs::File::create(dst)?;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 { break; }
        for b in &mut buf[..n] { *b ^= XOR_KEY; }
        output.write_all(&buf[..n])?;
    }
    Ok(())
}

fn decode_file(src: &Path, dst: &Path) -> io::Result<()> { encode_file(src, dst) }
