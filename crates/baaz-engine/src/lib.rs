//! The BaazCyber Antivirus scanning engine.
//!
//! A file is checked, in order, against:
//! 1. known malware fingerprints (SHA-256) from the signature database,
//! 2. byte signatures (including the EICAR and Baaz test files),
//! 3. heuristics for files that aren't known yet: executables, scripts and file names.
//!
//! The first two give exact matches; heuristics give a score and the reasons behind it.

pub mod heuristics;
pub mod quarantine;
pub mod signatures;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use walkdir::WalkDir;

pub use signatures::SignatureDb;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity { Low, Medium, High, Critical }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Known malware (exact fingerprint or signature).
    Malware,
    /// Not known, but behaves like malware.
    Suspicious,
    /// Potentially unwanted: miners, adware, hacking tools.
    Pua,
    /// An industry test file (EICAR) or the Baaz test file. Harmless.
    Test,
}

/// How the threat was recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Method { Hash, Signature, Heuristic }

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Threat {
    /// A detection name, for example "Script.Downloader.PowerShell".
    pub name: String,
    pub kind: Kind,
    pub severity: Severity,
    pub method: Method,
    /// Why it was flagged, in plain words.
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileResult {
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
    pub threat: Option<Threat>,
}

#[derive(Debug, Clone)]
pub struct Options {
    /// Files larger than this are fingerprinted but not read in full for heuristics.
    pub max_heuristic_bytes: u64,
    /// Skip files larger than this entirely.
    pub max_file_bytes: u64,
    /// Heuristic score (0-100) at or above which a file is reported as suspicious.
    pub heuristic_threshold: u32,
}

impl Default for Options {
    fn default() -> Self { Self { max_heuristic_bytes: 64 * 1024 * 1024, max_file_bytes: 1024 * 1024 * 1024, heuristic_threshold: 60 } }
}

pub struct Scanner {
    pub db: SignatureDb,
    pub options: Options,
}

/// Progress of a folder scan, readable while it runs.
#[derive(Default)]
pub struct Progress {
    pub files: AtomicU64,
    pub bytes: AtomicU64,
    pub threats: AtomicU64,
    pub cancelled: AtomicBool,
}

pub fn sha256_hex(data: &[u8]) -> String { hex(&Sha256::digest(data)) }
pub fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

impl Scanner {
    pub fn new(db: SignatureDb) -> Self { Self { db, options: Options::default() } }

    /// Check a file's contents (already in memory) under the given name.
    pub fn scan_bytes(&self, name: &str, data: &[u8]) -> Option<Threat> {
        let digest: [u8; 32] = Sha256::digest(data).into();
        self.check(name, data, &digest)
    }

    fn check(&self, name: &str, data: &[u8], digest: &[u8; 32]) -> Option<Threat> {
        if let Some(family) = self.db.lookup_hash(digest) {
            return Some(Threat { name: family.to_string(), kind: Kind::Malware, severity: Severity::Critical, method: Method::Hash, reasons: vec!["Its fingerprint (SHA-256) matches known malware in the signature database.".into()] });
        }
        if let Some(t) = self.db.match_signature(data) { return Some(t); }
        heuristics::evaluate(name, data, self.options.heuristic_threshold)
    }

    /// Check one file on disk.
    pub fn scan_file(&self, path: &Path) -> std::io::Result<FileResult> {
        let meta = std::fs::metadata(path)?;
        let size = meta.len();
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if size > self.options.max_file_bytes {
            return Ok(FileResult { path: path.to_path_buf(), size, sha256: String::new(), threat: heuristics::name::check(&name) });
        }
        // Hash the whole file while keeping the first part in memory for signatures and heuristics.
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let keep = size.min(self.options.max_heuristic_bytes) as usize;
        let mut head = Vec::with_capacity(keep);
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = file.read(&mut buf)?;
            if n == 0 { break; }
            hasher.update(&buf[..n]);
            if head.len() < keep { head.extend_from_slice(&buf[..n.min(keep - head.len())]); }
        }
        let digest: [u8; 32] = hasher.finalize().into();
        let threat = self.check(&name, &head, &digest);
        Ok(FileResult { path: path.to_path_buf(), size, sha256: hex(&digest), threat })
    }

    /// Check every file under `root` in parallel. `on_result` is called for each file (from worker threads).
    pub fn scan_path(&self, root: &Path, progress: &Progress, on_result: impl Fn(FileResult) + Sync) {
        let files = WalkDir::new(root).follow_links(false).into_iter().filter_map(Result::ok).filter(|e| e.file_type().is_file());
        files.par_bridge().for_each(|entry| {
            if progress.cancelled.load(Ordering::Relaxed) { return; }
            if let Ok(result) = self.scan_file(entry.path()) {
                progress.files.fetch_add(1, Ordering::Relaxed);
                progress.bytes.fetch_add(result.size, Ordering::Relaxed);
                if result.threat.is_some() { progress.threats.fetch_add(1, Ordering::Relaxed); }
                on_result(result);
            }
        });
    }
}

/// The folders a quick scan checks: where malware usually arrives or hides.
pub fn quick_scan_locations() -> Vec<PathBuf> {
    let env = |k: &str| std::env::var_os(k).map(PathBuf::from);
    let mut out = Vec::new();
    if let Some(home) = env("USERPROFILE").or_else(|| env("HOME")) {
        for sub in ["Downloads", "Desktop", "Documents"] { out.push(home.join(sub)); }
    }
    if let Some(temp) = env("TEMP") { out.push(temp); }
    if let Some(appdata) = env("APPDATA") { out.push(appdata.join(r"Microsoft\Windows\Start Menu\Programs\Startup")); }
    if let Some(pd) = env("ProgramData") { out.push(pd.join(r"Microsoft\Windows\Start Menu\Programs\StartUp")); }
    out.into_iter().filter(|p| p.exists()).collect()
}
