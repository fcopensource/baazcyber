//! The BaazCyber Antivirus desktop app: a thin Tauri layer over baaz-engine.
//! The window calls these commands; the engine does the scanning.

use baaz_engine::quarantine::{Quarantine, QuarantineEntry};
use baaz_engine::{quick_scan_locations, FileResult, Kind, Progress, Scanner, SignatureDb};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tauri::{Emitter, Manager, State};

/// Everything the app keeps while running.
struct App {
    scanner: Scanner,
    /// The scan currently running, so it can report progress and be cancelled.
    current: Mutex<Option<Arc<Progress>>>,
}

fn data_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
        .or_else(|| dirs_local())
        .unwrap_or_else(std::env::temp_dir);
    base.join("BaazCyber")
}
fn dirs_local() -> Option<PathBuf> { std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")) }
fn quarantine() -> std::io::Result<Quarantine> { Quarantine::open(data_dir().join("Quarantine")) }

fn load_scanner() -> Scanner {
    let mut db = SignatureDb::builtin();
    if let Ok(entries) = std::fs::read_dir(data_dir().join("Signatures")) {
        for entry in entries.flatten() {
            if entry.path().extension().is_some_and(|e| e == "txt" || e == "hsh") {
                let _ = db.load_hashes_file(&entry.path(), "Malware");
            }
        }
    }
    Scanner::new(db)
}

#[derive(Serialize, Clone)]
struct ScanProgress { files: u64, bytes: u64, threats: u64, current: String }

#[derive(Serialize, Clone)]
struct ScanSummary { files: u64, bytes: u64, seconds: f64, cancelled: bool, detections: Vec<FileResult> }

#[derive(Serialize)]
struct Target { label: String, path: String }

/// The folders a quick scan will check, for showing before it runs.
#[tauri::command]
fn quick_targets() -> Vec<Target> {
    quick_scan_locations().into_iter().map(|p| Target {
        label: p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.display().to_string()),
        path: p.display().to_string(),
    }).collect()
}

#[tauri::command]
fn signature_count(state: State<App>) -> usize { state.scanner.db.hash_count() }

/// Scan the given paths (or the quick-scan locations when `paths` is empty). Emits "scan:progress" events and
/// returns a summary. Run on a background thread so the window stays responsive.
#[tauri::command]
async fn start_scan(app: tauri::AppHandle, paths: Vec<String>) -> Result<ScanSummary, String> {
    let state = app.state::<App>();
    let roots: Vec<PathBuf> = if paths.is_empty() { quick_scan_locations() } else { paths.into_iter().map(PathBuf::from).collect() };

    let progress = Arc::new(Progress::default());
    *state.current.lock().unwrap() = Some(progress.clone());

    let detections: Arc<Mutex<Vec<FileResult>>> = Arc::new(Mutex::new(Vec::new()));
    let start = Instant::now();
    let app_for_events = app.clone();
    let progress_for_scan = progress.clone();
    let detections_for_scan = detections.clone();

    // Throttle progress events to a few per second.
    let last_emit = Arc::new(Mutex::new(Instant::now()));

    tauri::async_runtime::spawn_blocking(move || {
        let state = app_for_events.state::<App>();
        for root in &roots {
            if progress_for_scan.cancelled.load(Ordering::Relaxed) { break; }
            if !root.exists() { continue; }
            if root.is_file() {
                if let Ok(result) = state.scanner.scan_file(root) {
                    progress_for_scan.files.fetch_add(1, Ordering::Relaxed);
                    progress_for_scan.bytes.fetch_add(result.size, Ordering::Relaxed);
                    if result.threat.is_some() { progress_for_scan.threats.fetch_add(1, Ordering::Relaxed); detections_for_scan.lock().unwrap().push(result); }
                }
            } else {
                let detections = detections_for_scan.clone();
                let app_evt = app_for_events.clone();
                let last = last_emit.clone();
                let prog = progress_for_scan.clone();
                state.scanner.scan_path(root, &progress_for_scan, move |result| {
                    if result.threat.is_some() { detections.lock().unwrap().push(result.clone()); }
                    let mut guard = last.lock().unwrap();
                    if guard.elapsed().as_millis() > 120 {
                        *guard = Instant::now();
                        let _ = app_evt.emit("scan:progress", ScanProgress {
                            files: prog.files.load(Ordering::Relaxed),
                            bytes: prog.bytes.load(Ordering::Relaxed),
                            threats: prog.threats.load(Ordering::Relaxed),
                            current: result.path.display().to_string(),
                        });
                    }
                });
            }
        }
    }).await.map_err(|e| e.to_string())?;

    let cancelled = progress.cancelled.load(Ordering::Relaxed);
    *state.current.lock().unwrap() = None;
    let mut found = detections.lock().unwrap().clone();
    found.sort_by(|a, b| b.threat.as_ref().map(|t| t.severity).cmp(&a.threat.as_ref().map(|t| t.severity)));
    Ok(ScanSummary { files: progress.files.load(Ordering::Relaxed), bytes: progress.bytes.load(Ordering::Relaxed), seconds: start.elapsed().as_secs_f64(), cancelled, detections: found })
}

#[tauri::command]
fn cancel_scan(state: State<App>) {
    if let Some(p) = state.current.lock().unwrap().as_ref() { p.cancelled.store(true, Ordering::Relaxed); }
}

/// Move a detected file into quarantine. Returns the new quarantine entry.
#[tauri::command]
fn quarantine_file(path: String, sha256: String, name: String, reasons: Vec<String>) -> Result<QuarantineEntry, String> {
    let threat = baaz_engine::Threat { name, kind: Kind::Malware, severity: baaz_engine::Severity::High, method: baaz_engine::Method::Heuristic, reasons };
    quarantine().map_err(|e| e.to_string())?.add(std::path::Path::new(&path), &sha256, &threat).map_err(|e| e.to_string())
}

#[tauri::command]
fn list_quarantine() -> Result<Vec<QuarantineEntry>, String> { quarantine().map_err(|e| e.to_string())?.list().map_err(|e| e.to_string()) }

#[tauri::command]
fn restore_quarantine(id: String) -> Result<String, String> { quarantine().map_err(|e| e.to_string())?.restore(&id).map(|p| p.display().to_string()).map_err(|e| e.to_string()) }

#[tauri::command]
fn delete_quarantine(id: String) -> Result<(), String> { quarantine().map_err(|e| e.to_string())?.delete(&id).map_err(|e| e.to_string()) }

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(App { scanner: load_scanner(), current: Mutex::new(None) })
        .invoke_handler(tauri::generate_handler![
            quick_targets, signature_count, start_scan, cancel_scan,
            quarantine_file, list_quarantine, restore_quarantine, delete_quarantine
        ])
        .run(tauri::generate_context!())
        .expect("error while running BaazCyber Antivirus");
}
