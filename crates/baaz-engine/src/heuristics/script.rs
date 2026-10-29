//! Scripts: PowerShell, batch files, VBScript, JavaScript, HTA, Python and shell scripts.
//! These are the most common first stage of an attack, because they run with a double click.

use super::Evidence;
use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang { PowerShell, Batch, VbScript, JavaScript, Hta, Python, Shell }

pub fn language(name: &str, data: &[u8]) -> Option<Lang> {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    let lang = match ext.as_str() {
        "ps1" | "psm1" | "psd1" => Lang::PowerShell,
        "bat" | "cmd" => Lang::Batch,
        "vbs" | "vbe" | "wsf" => Lang::VbScript,
        "js" | "jse" | "mjs" | "cjs" => Lang::JavaScript,
        "hta" => Lang::Hta,
        "py" | "pyw" => Lang::Python,
        "sh" | "bash" => Lang::Shell,
        _ if data.starts_with(b"#!") => if data.starts_with(b"#!/usr/bin/env python") || data.starts_with(b"#!/usr/bin/python") { Lang::Python } else { Lang::Shell },
        _ => return None,
    };
    Some(lang)
}

struct Pattern { name: &'static str, score: u32, re: Regex, reason: &'static str, pua: bool }

fn p(name: &'static str, score: u32, re: &str, reason: &'static str) -> Pattern { Pattern { name, score, re: Regex::new(re).expect("valid pattern"), reason, pua: false } }

static PATTERNS: LazyLock<Vec<Pattern>> = LazyLock::new(|| {
    let mut v = vec![
        p("Trojan.Downloader.Script", 85, r"(?i)\b(?:iex|invoke-expression)\b[^\n]{0,80}\b(?:net\.webclient|downloadstring|downloaddata|iwr|irm|invoke-webrequest|invoke-restmethod)\b|\b(?:downloadstring|downloaddata)\b[^\n]{0,120}\b(?:iex|invoke-expression)\b", "It downloads code from the internet and runs it straight away, without saving or checking it."),
        p("Trojan.Downloader.Script", 80, r"(?i)\b(?:curl|wget)\b[^|\n;]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b", "It downloads a script and pipes it straight into a shell."),
        p("Trojan.Downloader.Script", 70, r"(?i)\bcertutil(?:\.exe)?\s+[-/]urlcache\b|\bbitsadmin(?:\.exe)?\s+/transfer\b|\bmshta(?:\.exe)?\s+[\x22']?https?:|\bregsvr32(?:\.exe)?\s+[^\n]*/i:https?:", "It uses a built-in Windows tool to download and run a file (a \"living off the land\" technique that avoids security tools)."),
        p("Trojan.PowerShell.Encoded", 80, r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,80}\s-(?:e|en|enc|enco|encod|encode|encoded|encodedc\w*)\s+[A-Za-z0-9+/=]{40,}", "It runs a PowerShell command hidden in base64 so it can't be read."),
        p("Trojan.PowerShell.Hidden", 45, r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,120}-(?:w|win|window|windowstyle)\s+h(?:idden)?\b", "It starts PowerShell in a hidden window so you don't see it running."),
        // Base64-decode-and-run is the classic dropper; strong enough to flag on its own.
        p("Trojan.Script.DecodeExecute", 78, r"(?i)\b(?:eval|execute|executeglobal|iex|invoke-expression|exec)\s*\(?[^\n]{0,60}\b(?:frombase64string|atob|b64decode|base64\.(?:b64)?decode|convert\]::frombase64)", "It decodes base64-hidden text and runs it as code, the classic way malware hides its real behaviour."),
        // fromCharCode/unescape building code is weaker: legitimate polyfills do this, so it needs a second signal.
        p("Suspicious.Script.CharCodeExecute", 45, r"(?i)\b(?:eval|execute|executeglobal|iex|invoke-expression)\s*\(?[^\n]{0,60}\b(?:unescape|fromcharcode|chrw?\s*\()", "It assembles code from character codes or escapes and runs it, a way of hiding what the code does."),
        p("Backdoor.ReverseShell", 95, r"(?i)/dev/(?:tcp|udp)/[\w.-]+/\d+|\bnc(?:at)?\b[^\n]{0,60}\s-[ec]\s|\b(?:ba)?sh\s+-i\s*>&|\bpty\.spawn\s*\(\s*['\x22]/bin/|New-Object\s+(?:System\.)?Net\.Sockets\.TCPClient", "It opens a remote command line for an attacker (a reverse shell): full control of the computer."),
        p("Trojan.DisableDefender", 95, r"(?i)\bSet-MpPreference\b[^\n]*-Disable\w*\s+\$?true|\bAdd-MpPreference\b[^\n]*-Exclusion(?:Path|Process|Extension)\b|\bnetsh\s+(?:adv)?firewall\s+set\s+[^\n]*state\s+off|\bvssadmin(?:\.exe)?\s+delete\s+shadows\b|\bwmic\s+shadowcopy\s+delete\b|\bwbadmin\s+delete\s+catalog\b|\bbcdedit\b[^\n]*recoveryenabled\s+no", "It turns off Windows Defender or the firewall, or deletes backup copies of your files. Ransomware does exactly this before encrypting."),
        p("Trojan.Persistence", 50, r"(?i)\bschtasks(?:\.exe)?\s+/create\b|\\CurrentVersion\\Run(?:Once)?\b|\bRegister-ScheduledTask\b|\bStartup\\[^\n]*\.(?:lnk|bat|vbs|exe)\b|\(\s*crontab\s+-l", "It sets itself up to start automatically every time the computer starts or you sign in."),
        p("Spyware.CredentialTheft", 70, r"(?i)\\Login Data\b|\\Local State\b|\bwallet\.dat\b|\\Exodus\\exodus\.wallet|Local Extension Settings\\nkbihfbeogaeaoehlefnkodbefgpgknn|\.ssh[\\/]id_(?:rsa|ed25519)|discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot", "It reads saved browser passwords, crypto wallets or keys, or sends data to a Discord or Telegram bot, which is how stolen data is collected."),
    ];
    v.push(Pattern { name: "PUA.CoinMiner", score: 70, re: Regex::new(r"(?i)stratum\+(?:tcp|ssl|tls)://|\bxmrig\b|\b(?:minexmr|nanopool|supportxmr|moneroocean|nicehash)\.(?:com|org|net)\b").unwrap(), reason: "It runs a cryptocurrency miner, which uses your computer's power to earn money for someone else.", pua: true });
    v
});

pub fn evidence(_lang: Lang, data: &[u8]) -> Vec<Evidence> {
    // Scripts are text; very large ones are usually generated and are checked in their first 4 MB.
    let text = String::from_utf8_lossy(&data[..data.len().min(4 * 1024 * 1024)]);
    let mut out: Vec<Evidence> = Vec::new();
    for pat in PATTERNS.iter() {
        if pat.re.is_match(&text) && !out.iter().any(|e| e.name == pat.name) {
            let e = Evidence::new(pat.name, pat.score, pat.reason);
            out.push(if pat.pua { e.pua() } else { e });
        }
    }
    out
}
