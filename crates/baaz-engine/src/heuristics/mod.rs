//! Heuristics: recognising threats that aren't in the signature database yet.
//!
//! Each check returns evidence with a score. Evidence is combined, and a file is reported when the total
//! reaches the threshold, with the strongest piece of evidence naming it.

pub mod name;
pub mod pe;
pub mod script;

use crate::{Kind, Method, Severity, Threat};

/// One piece of evidence: a detection name, a score (0-100) and the reason in plain words.
#[derive(Debug, Clone)]
pub struct Evidence {
    pub name: &'static str,
    pub score: u32,
    pub reason: String,
    pub kind: Kind,
}

impl Evidence {
    pub fn new(name: &'static str, score: u32, reason: impl Into<String>) -> Self { Self { name, score, reason: reason.into(), kind: Kind::Suspicious } }
    pub fn pua(mut self) -> Self { self.kind = Kind::Pua; self }
}

/// Combine the evidence for a file into a threat, if it is strong enough.
pub fn verdict(mut evidence: Vec<Evidence>, threshold: u32) -> Option<Threat> {
    if evidence.is_empty() { return None; }
    evidence.sort_by(|a, b| b.score.cmp(&a.score));
    // The strongest evidence counts in full; each further piece adds half its score, so many weak hints
    // don't add up to a false alarm as easily as one strong one.
    let total = evidence.iter().enumerate().map(|(i, e)| if i == 0 { e.score } else { e.score / 2 }).sum::<u32>().min(100);
    if total < threshold { return None; }
    let top = &evidence[0];
    let severity = match total { 90.. => Severity::Critical, 75..=89 => Severity::High, _ => Severity::Medium };
    Some(Threat {
        name: top.name.to_string(),
        kind: top.kind,
        severity: if top.kind == Kind::Pua { Severity::Medium.min(severity) } else { severity },
        method: Method::Heuristic,
        reasons: evidence.iter().map(|e| e.reason.clone()).collect(),
    })
}

/// Run every heuristic that applies to this file.
pub fn evaluate(file_name: &str, data: &[u8], threshold: u32) -> Option<Threat> {
    let mut evidence = name::evidence(file_name);
    if pe::is_pe(data) { evidence.extend(pe::evidence(data)); }
    else if let Some(lang) = script::language(file_name, data) { evidence.extend(script::evidence(lang, data)); }
    verdict(evidence, threshold)
}
