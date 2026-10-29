//! Known threats: SHA-256 fingerprints and byte signatures.
//!
//! The fingerprint database is a text file with one entry per line, `<sha256> <name>` (the name is optional),
//! so it can be built from public threat feeds such as MalwareBazaar's hash exports.

use crate::{Kind, Method, Severity, Threat};
use std::collections::HashMap;
use std::path::Path;

pub struct ByteSignature {
    pub name: &'static str,
    pub kind: Kind,
    pub severity: Severity,
    pub reason: &'static str,
    /// How the bytes must appear.
    pub rule: Rule,
}

pub enum Rule {
    /// The file starts with these bytes, optionally followed by whitespace, and is at most `max_len` long.
    StartsWithThenWhitespace { bytes: Vec<u8>, max_len: usize },
    /// The bytes appear anywhere in the first part of the file.
    Contains(Vec<u8>),
}

pub struct SignatureDb {
    hashes: HashMap<[u8; 32], String>,
    signatures: Vec<ByteSignature>,
}

/// The EICAR test string. It is assembled here at run time: antivirus software (including Windows Defender)
/// deletes any file that contains it in one piece, including this source file.
pub fn eicar() -> Vec<u8> {
    let parts = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}", "$EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!", "$H+H*"];
    parts.concat().into_bytes()
}

/// The Baaz test file: harmless, only recognised by BaazCyber, so it can be used in tests without other
/// antivirus software interfering.
pub const BAAZ_TEST: &[u8] = b"BAAZCYBER-ANTIVIRUS-TEST-FILE";

impl Default for SignatureDb {
    fn default() -> Self { Self::builtin() }
}

impl SignatureDb {
    /// The signatures that ship with the engine.
    pub fn builtin() -> Self {
        let signatures = vec![
            ByteSignature { name: "Test.EICAR", kind: Kind::Test, severity: Severity::Low, reason: "The EICAR antivirus test file. It is harmless and used to check that antivirus software works.", rule: Rule::StartsWithThenWhitespace { bytes: eicar(), max_len: 128 } },
            ByteSignature { name: "Test.BaazCyber", kind: Kind::Test, severity: Severity::Low, reason: "The BaazCyber test file. It is harmless and used to check that BaazCyber Antivirus works.", rule: Rule::Contains(BAAZ_TEST.to_vec()) },
        ];
        Self { hashes: HashMap::new(), signatures }
    }

    pub fn hash_count(&self) -> usize { self.hashes.len() }

    /// Add fingerprints from text: `<sha256> [name]` per line; blank lines and lines starting with # are ignored.
    /// Returns how many were added.
    pub fn load_hashes_text(&mut self, text: &str, default_name: &str) -> usize {
        let mut added = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            let mut parts = line.splitn(2, |c: char| c == ' ' || c == '\t' || c == ',');
            let Some(hash) = parts.next().map(|h| h.trim_matches('"')) else { continue };
            let Some(bytes) = parse_sha256(hash) else { continue };
            let name = parts.next().map(|n| n.trim().trim_matches('"')).filter(|n| !n.is_empty()).unwrap_or(default_name);
            self.hashes.insert(bytes, name.to_string());
            added += 1;
        }
        added
    }

    pub fn load_hashes_file(&mut self, path: &Path, default_name: &str) -> std::io::Result<usize> {
        Ok(self.load_hashes_text(&std::fs::read_to_string(path)?, default_name))
    }

    pub fn lookup_hash(&self, digest: &[u8; 32]) -> Option<&str> { self.hashes.get(digest).map(String::as_str) }

    pub fn match_signature(&self, data: &[u8]) -> Option<Threat> {
        self.signatures.iter().find(|s| matches(&s.rule, data)).map(|s| Threat {
            name: s.name.to_string(), kind: s.kind, severity: s.severity, method: Method::Signature, reasons: vec![s.reason.to_string()],
        })
    }
}

fn matches(rule: &Rule, data: &[u8]) -> bool {
    match rule {
        Rule::StartsWithThenWhitespace { bytes, max_len } => {
            data.len() <= *max_len && data.starts_with(bytes) && data[bytes.len()..].iter().all(|b| b.is_ascii_whitespace() || *b == 0x1a)
        }
        Rule::Contains(needle) => data.windows(needle.len()).any(|w| w == needle.as_slice()),
    }
}

pub fn parse_sha256(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 { return None; }
    let mut out = [0u8; 32];
    for (i, chunk) in text.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}
