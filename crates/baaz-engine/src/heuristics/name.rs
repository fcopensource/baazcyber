//! File-name tricks: a program dressed up as a document.

use super::Evidence;
use crate::Threat;

const EXECUTABLE: &[&str] = &["exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "ps1", "msi", "lnk", "cpl", "jar", "dll"];
const DOCUMENT: &[&str] = &["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif", "mp3", "mp4", "avi", "mov", "zip", "rar", "csv", "html", "htm"];

pub fn evidence(name: &str) -> Vec<Evidence> {
    let mut out = Vec::new();
    // A right-to-left override makes "invoice_\u{202E}fdp.exe" display as "invoice_exe.pdf".
    if name.chars().any(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')) {
        out.push(Evidence::new("Trojan.FileName.RightToLeft", 95, "The file name contains a hidden text-direction character, which makes a program's real extension appear backwards (for example \"invoice_exe.pdf\"). This is only used to trick people into running malware."));
    }
    let lower = name.to_lowercase();
    let parts: Vec<&str> = lower.rsplitn(3, '.').collect();
    if parts.len() == 3 {
        let (last, middle) = (parts[0], parts[1]);
        if EXECUTABLE.contains(&last) && DOCUMENT.contains(&middle) {
            out.push(Evidence::new("Trojan.FileName.DoubleExtension", 80, format!("It is a program (.{last}) disguised as a .{middle} file with a double extension. Windows hides the last extension by default, so it looks like a harmless document.")));
        }
    }
    // Lots of spaces before the real extension push it out of view in file listings.
    if let Some(dot) = lower.rfind('.') {
        let before = &lower[..dot];
        if EXECUTABLE.contains(&&lower[dot + 1..]) && before.ends_with("     ") {
            out.push(Evidence::new("Trojan.FileName.HiddenExtension", 80, "Many spaces before the extension push \".exe\" out of view, so the program looks like a different kind of file."));
        }
    }
    out
}

/// For files too large to read: only the name can be checked.
pub fn check(name: &str) -> Option<Threat> { super::verdict(evidence(name), 60) }
