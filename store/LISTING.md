# Microsoft Store listing: BaazCyber Antivirus

Everything to paste into Partner Center (**Apps and games → BaazCyber Antivirus**). Submitted as an
**EXE or MSI app**, the same way as Veyra Studio.

## Packages

| Field | Value |
| --- | --- |
| Package URL | `https://downloads.veyraeditor.com/baazcyber/v0.2.3/BaazCyber.Antivirus_0.2.3_x64_en-US.msi` |
| Architecture | x64 |
| Installer type | MSI (installs silently, no parameters needed) |
| Language | English (United States) |

Never replace or delete a submitted installer. Each new version goes in a new folder, for example
`downloads.veyraeditor.com/baazcyber/v0.2.4/`.

## Properties

| Field | Value |
| --- | --- |
| Category | Utilities & tools → Security |
| Privacy policy URL | `https://veyraeditor.com/baazcyber/privacy` |
| Website | `https://veyraeditor.com/baazcyber` |
| Support contact | `hire@flightcoders.com` |
| Price | Free |
| Age rating | Fill in the questionnaire: no violence, no user-generated content, no purchases |

## Store listing (English)

**Product name:** BaazCyber Antivirus

**Short description** (shown first):

> Private malware protection for Windows. Scan your PC for trojans, backdoors, web shells and password stealers. Every scan runs on your computer, and nothing is uploaded.

**Description:**

> BaazCyber Antivirus checks your files for malware and explains every finding in plain words.
>
> Run a Smart Scan of the places malware usually hides (Downloads, Desktop, Documents, Temp and the programs that start with Windows) or a Full Scan of your whole system drive. You can also scan any folder, USB stick, external drive or single file before you open it.
>
> BaazCyber looks for known malware by its fingerprint, and uses heuristics to catch threats that are not in any database yet: programs disguised as documents, packed or injecting programs, keyloggers and ransomware patterns, and malicious PowerShell, batch, VBScript and JavaScript files that download and run code, disable security tools or steal passwords.
>
> When something is found, move it to quarantine. The file is encoded so it can no longer run, and you can restore or delete it at any time. Save a PDF security report of any scan.
>
> Private by design: every scan runs on your computer. BaazCyber has no account, no ads, no analytics and no telemetry, and never uploads your files.
>
> BaazCyber scans on demand and works alongside Windows Security (Microsoft Defender).

**What's new in this version:**

> First Microsoft Store release: Smart, Full, Folder, File, Downloads and Startup scans, quarantine, scan history, PDF security reports and signed automatic updates.

**Product features** (one per line, up to 20):

- Smart Scan of Downloads, Desktop, Documents, Temp and Startup
- Full Scan of your system drive
- Scan any folder, USB stick, external drive or single file
- Detects known malware by SHA-256 fingerprint
- Heuristics for disguised programs, packers, injection, keyloggers and ransomware patterns
- Detects malicious PowerShell, batch, VBScript, JavaScript and HTA scripts
- Every finding explained in plain words
- Quarantine that stops threats from running, with restore and delete
- PDF security reports
- Scan history and a security score
- Everything runs on your PC: no uploads, no account, no telemetry
- Signed automatic updates

**Search terms** (up to 7): `antivirus`, `malware scanner`, `virus scan`, `security`, `trojan`, `quarantine`, `privacy`

**Copyright:** © 2026 BaazCyber, a FlightCoders company

## Images

| Partner Center field | File | Size |
| --- | --- | --- |
| Screenshots (desktop) | [`screenshots/01-dashboard.png`](screenshots/01-dashboard.png) | 1920×1080 |
| | [`screenshots/02-scan-in-progress.png`](screenshots/02-scan-in-progress.png) | 1920×1080 |
| | [`screenshots/03-scan-results.png`](screenshots/03-scan-results.png) | 1920×1080 |
| | [`screenshots/04-quarantine.png`](screenshots/04-quarantine.png) | 1920×1080 |
| | [`screenshots/05-history.png`](screenshots/05-history.png) | 1920×1080 |
| | [`screenshots/06-settings.png`](screenshots/06-settings.png) | 1920×1080 |
| | [`screenshots/07-dashboard-after-scan.png`](screenshots/07-dashboard-after-scan.png) | 1920×1080 |
| Store logo | [`logos/store-logo-300.png`](logos/store-logo-300.png) | 300×300 |
| 1:1 box art | [`logos/box-art-1080.png`](logos/box-art-1080.png) (or [`box-art-2160.png`](logos/box-art-2160.png)) | 1080×1080 / 2160×2160 |
| 2:3 poster art | [`logos/poster-art-720x1080.png`](logos/poster-art-720x1080.png) (or [`1440x2160`](logos/poster-art-1440x2160.png)) | 720×1080 / 1440×2160 |
| 16:9 hero art | [`logos/hero-art-1920x1080.png`](logos/hero-art-1920x1080.png) | 1920×1080 |

Suggested screenshot captions:

1. Your security score and every scan in one place
2. Scans about 1,000 files a second
3. Every finding explained in plain words
4. Quarantine stops threats from running
5. A history of every scan
6. Signed automatic updates

### How the screenshots were made

They show BaazCyber 0.2.3's real interface at 1920×1080, with the real results of the BaazCyber engine scanning
a demo drive (X:, 19,201 ordinary files plus the harmless BaazCyber test file, which is why the detection is
`Test.BaazCyber`). A demo drive keeps personal file names out of the images. No real malware was used.

## Reviewer notes (Notes for certification)

> BaazCyber Antivirus is an on-demand malware scanner. It does not install drivers or services and does not provide real-time protection; it runs alongside Microsoft Defender. To test detection safely, create a text file containing exactly BAAZCYBER-ANTIVIRUS-TEST-FILE (or the standard EICAR test string) and run a File Scan on it. The app's only network request is a signed update check to veyraeditor.com.
