# BaazCyber Antivirus

Fast, private malware scanning for Windows. A **BaazCyber** product, by **FlightCoders**.

BaazCyber scans your files for malware, trojans, backdoors and malicious scripts, and quarantines what it
finds. Everything runs on your computer: nothing is uploaded. It runs alongside Windows Defender as an extra
layer; it does not replace it.

```
crates/baaz-engine   the scanning engine (Rust, no network): signatures, heuristics, quarantine
crates/baaz-cli      the command-line scanner (baaz)
app/                 the desktop app (Tauri 2: Rust + a dark glass UI)
```

## How it detects threats

A file is checked, in order, against:

1. **Known-malware fingerprints** (SHA-256), loaded from public threat feeds.
2. **Byte signatures**, including the industry-standard **EICAR** test file.
3. **Heuristics** for threats not yet in the database:
   - **File names:** a program dressed as a document (`invoice.pdf.exe`), hidden direction characters, hidden extensions.
   - **Windows programs:** packers, process injection and hollowing, keyloggers, ransomware patterns, crypto miners, anti-debugging.
   - **Scripts** (PowerShell, batch, VBScript, JavaScript, HTA, Python, shell): download-and-run, hidden/encoded PowerShell, reverse shells, disabling Defender or deleting backups, persistence, credential theft, miners.

Each heuristic gives a score and the reason in plain words; a file is reported when the evidence is strong enough.

## Testing it safely

BaazCyber is tested with **EICAR** (the standard harmless antivirus test file) and its own harmless
`BAAZCYBER-ANTIVIRUS-TEST-FILE` marker. No real malware is used anywhere in this project. Note that writing a
real EICAR file to disk makes Windows Defender delete it immediately, so the automated tests use the Baaz marker.

## The command line

```
baaz scan <path>...     Check files or folders
baaz quick              Check the usual places malware arrives
baaz scan <p> --json    Machine-readable output
baaz list               Show quarantined files
baaz restore <id>       Put a quarantined file back
baaz delete <id>        Delete a quarantined file for good
```

Add `--quarantine` to a scan to move every threat somewhere safe.

## The app

A Tauri 2 desktop app with a dark glass interface: a protection dashboard, quick/full/custom scans with a live
sweep animation, a results list, and a quarantine manager.

```
cd app && npm run tauri dev      # run it
cd app && npm run tauri build    # build an installer
```

## Quarantine

A detected file is XOR-encoded (so it can no longer run and other scanners skip it) and stored with a record of
where it came from, under `%LOCALAPPDATA%\BaazCyber\Quarantine`. It can be restored to its original place or
deleted for good.

## What needs more before release

- **Real-time blocking** (stopping a file the instant it runs) needs a Microsoft-signed kernel driver, which
  requires an EV code-signing certificate and Microsoft driver attestation. Until then, BaazCyber scans on
  demand and on a schedule, alongside Defender.
- **Appearing in Windows Security** needs membership of Microsoft's antivirus partner programme.

## Status

Phase 1: engine, CLI and quarantine complete and tested. The desktop app and Microsoft Store packaging are in
progress. Not a replacement for a full security suite yet.

---

© 2026 BaazCyber, a FlightCoders company.
