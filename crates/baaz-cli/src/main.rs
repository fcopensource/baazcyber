//! BaazCyber Antivirus command-line scanner.
//!
//!   baaz scan <path>...        check files or folders
//!   baaz quick                 check the usual places malware arrives
//!   baaz scan <path> --json    machine-readable output
//!   baaz list                  show quarantined files
//!   baaz restore <id>          put a quarantined file back
//!   baaz delete <id>           delete a quarantined file for good
//!
//! --quarantine moves every threat found during a scan into quarantine.

use baaz_engine::quarantine::Quarantine;
use baaz_engine::{quick_scan_locations, FileResult, Kind, Progress, Scanner, Severity, SignatureDb};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::time::Instant;

fn quarantine_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| std::env::temp_dir());
    base.join("BaazCyber").join("Quarantine")
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().any(|a| a == name);
    let command = args.first().map(String::as_str).unwrap_or("help");
    let paths: Vec<PathBuf> = args.iter().skip(1).filter(|a| !a.starts_with("--")).map(PathBuf::from).collect();

    match command {
        "scan" | "quick" => scan(command, &paths, flag("--json"), flag("--quarantine")),
        "list" => list(flag("--json")),
        "restore" => manage(&paths, true),
        "delete" => manage(&paths, false),
        "version" | "--version" | "-v" => { println!("BaazCyber Antivirus engine {}", env!("CARGO_PKG_VERSION")); ExitCode::SUCCESS }
        _ => { help(); ExitCode::SUCCESS }
    }
}

fn load_scanner() -> Scanner {
    let mut db = SignatureDb::builtin();
    // Load extra fingerprints from the signatures folder next to the quarantine, if any have been downloaded.
    let sig_dir = quarantine_dir().parent().map(|p| p.join("Signatures")).unwrap_or_default();
    if let Ok(entries) = std::fs::read_dir(&sig_dir) {
        for entry in entries.flatten() {
            if entry.path().extension().is_some_and(|e| e == "txt" || e == "hsh") {
                let _ = db.load_hashes_file(&entry.path(), "Malware");
            }
        }
    }
    Scanner::new(db)
}

fn scan(command: &str, paths: &[PathBuf], json: bool, do_quarantine: bool) -> ExitCode {
    let roots: Vec<PathBuf> = if command == "quick" { quick_scan_locations() } else { paths.to_vec() };
    if roots.is_empty() { eprintln!("Nothing to scan. Try: baaz scan <path>, or baaz quick"); return ExitCode::from(2); }

    let scanner = load_scanner();
    let progress = Progress::default();
    let found: Mutex<Vec<FileResult>> = Mutex::new(Vec::new());
    let start = Instant::now();

    if !json { println!("BaazCyber Antivirus  \u{2014}  scanning\n"); }
    for root in &roots {
        if !root.exists() { if !json { eprintln!("  skipped (not found): {}", root.display()); } continue; }
        if root.is_file() {
            if let Ok(result) = scanner.scan_file(root) {
                progress.files.fetch_add(1, Ordering::Relaxed);
                report_one(&result, json);
                if result.threat.is_some() { found.lock().unwrap().push(result); }
            }
        } else {
            scanner.scan_path(root, &progress, |result| {
                if result.threat.is_some() { report_one(&result, json); found.lock().unwrap().push(result); }
            });
        }
    }

    let mut threats = found.into_inner().unwrap();
    threats.sort_by(|a, b| b.threat.as_ref().map(|t| t.severity).cmp(&a.threat.as_ref().map(|t| t.severity)));

    let mut quarantined = 0usize;
    if do_quarantine && !threats.is_empty() {
        if let Ok(q) = Quarantine::open(quarantine_dir()) {
            for result in &threats {
                // Test files aren't a real threat, so they aren't quarantined unless asked for directly.
                if result.threat.as_ref().map(|t| t.kind) == Some(Kind::Test) { continue; }
                if q.add(&result.path, &result.sha256, result.threat.as_ref().unwrap()).is_ok() { quarantined += 1; }
            }
        }
    }

    if json {
        let summary = serde_json::json!({
            "files_scanned": progress.files.load(Ordering::Relaxed),
            "bytes_scanned": progress.bytes.load(Ordering::Relaxed),
            "threats": threats.len(),
            "quarantined": quarantined,
            "seconds": start.elapsed().as_secs_f64(),
            "detections": threats,
        });
        println!("{}", serde_json::to_string_pretty(&summary).unwrap());
    } else {
        let files = progress.files.load(Ordering::Relaxed);
        println!("\n  Scanned {files} files in {:.1}s.", start.elapsed().as_secs_f64());
        if threats.is_empty() {
            println!("  \u{2713} No threats found.");
        } else {
            println!("  {} threat(s) found{}.", threats.len(), if quarantined > 0 { format!(", {quarantined} quarantined") } else { String::new() });
            if !do_quarantine { println!("  Run again with --quarantine to move them somewhere safe."); }
        }
    }
    if threats.iter().any(|r| r.threat.as_ref().map(|t| t.kind) != Some(Kind::Test)) { ExitCode::from(1) } else { ExitCode::SUCCESS }
}

fn report_one(result: &FileResult, json: bool) {
    if json { return; }
    let Some(threat) = &result.threat else { return };
    let (icon, label) = badge(threat.severity);
    println!("  {icon} {label}  {}", threat.name);
    println!("      {}", result.path.display());
    for reason in &threat.reasons { println!("      \u{2022} {reason}"); }
    println!();
}

fn badge(severity: Severity) -> (&'static str, &'static str) {
    match severity {
        Severity::Critical => ("\u{1f6d1}", "CRITICAL"),
        Severity::High => ("\u{1f534}", "HIGH    "),
        Severity::Medium => ("\u{1f7e0}", "MEDIUM  "),
        Severity::Low => ("\u{1f535}", "LOW     "),
    }
}

fn list(json: bool) -> ExitCode {
    let Ok(q) = Quarantine::open(quarantine_dir()) else { eprintln!("No quarantine folder yet."); return ExitCode::SUCCESS };
    let entries = q.list().unwrap_or_default();
    if json { println!("{}", serde_json::to_string_pretty(&entries).unwrap()); return ExitCode::SUCCESS; }
    if entries.is_empty() { println!("Quarantine is empty."); return ExitCode::SUCCESS; }
    println!("Quarantined files:\n");
    for e in &entries {
        println!("  {}  {}", e.id, e.threat_name);
        println!("      was: {}", e.original_path.display());
    }
    println!("\nRestore one with: baaz restore <id>   \u{2022}   delete with: baaz delete <id>");
    ExitCode::SUCCESS
}

fn manage(paths: &[PathBuf], restore: bool) -> ExitCode {
    let Ok(q) = Quarantine::open(quarantine_dir()) else { eprintln!("No quarantine folder yet."); return ExitCode::from(2) };
    let Some(id) = paths.first().and_then(|p| p.to_str()) else { eprintln!("Which one? Use: baaz {} <id>  (see 'baaz list')", if restore { "restore" } else { "delete" }); return ExitCode::from(2) };
    let result = if restore { q.restore(id).map(|p| format!("Restored to {}", p.display())) } else { q.delete(id).map(|_| "Deleted.".to_string()) };
    match result {
        Ok(message) => { println!("{message}"); ExitCode::SUCCESS }
        Err(e) => { eprintln!("Couldn't do that: {e}"); ExitCode::from(2) }
    }
}

fn help() {
    println!("BaazCyber Antivirus\n");
    println!("  baaz scan <path>...     Check files or folders for threats");
    println!("  baaz quick              Check the usual places malware arrives");
    println!("  baaz list               Show quarantined files");
    println!("  baaz restore <id>       Put a quarantined file back");
    println!("  baaz delete <id>        Delete a quarantined file for good");
    println!("\nAdd --quarantine to a scan to move threats somewhere safe, or --json for machine-readable output.");
}

#[allow(dead_code)]
fn is_path(_: &Path) {}
