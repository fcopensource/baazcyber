//! Windows programs (PE files): packing, injection, keylogging and other behaviour visible in the file itself.

use super::Evidence;
use goblin::pe::PE;
use std::collections::HashSet;

pub fn is_pe(data: &[u8]) -> bool { data.len() > 0x40 && data.starts_with(b"MZ") }

/// Shannon entropy in bits per byte: 8 is random (encrypted or compressed), normal code is about 5-6.5.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0usize; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| { let p = c as f64 / len; -p * p.log2() }).sum()
}

const PACKER_SECTIONS: &[(&str, &str)] = &[
    ("upx0", "UPX"), ("upx1", "UPX"), (".aspack", "ASPack"), (".adata", "ASPack"), ("mpress1", "MPRESS"), ("mpress2", "MPRESS"),
    (".themida", "Themida"), (".winlice", "WinLicense"), (".vmp0", "VMProtect"), (".vmp1", "VMProtect"), (".enigma1", "Enigma"), (".petite", "Petite"), (".nsp0", "NsPack"),
];

/// Groups of imported functions that together mean a specific capability.
const BEHAVIOURS: &[(&str, u32, &[&str], &str)] = &[
    ("Trojan.Injector", 70, &["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"], "It can write code into other running programs and start it there (process injection), a technique malware uses to hide inside trusted programs."),
    ("Trojan.Injector.Hollowing", 75, &["CreateProcess", "NtUnmapViewOfSection", "WriteProcessMemory", "SetThreadContext"], "It can replace a legitimate program's code with its own while it runs (process hollowing), a technique used to disguise malware as a trusted program."),
    ("Spyware.Keylogger", 65, &["SetWindowsHookEx", "GetAsyncKeyState"], "It can watch every key you press, the core of a keylogger."),
    ("Spyware.Keylogger", 55, &["GetAsyncKeyState", "GetForegroundWindow", "GetWindowText"], "It repeatedly reads key presses along with the title of the window you're typing in, as keyloggers do."),
    ("Trojan.Downloader", 35, &["URLDownloadToFile", "ShellExecute"], "It downloads a file from the internet and runs it."),
    ("Ransom.Behaviour", 40, &["CryptEncrypt", "FindFirstFile", "FindNextFile", "MoveFileEx"], "It walks through folders and encrypts files, the pattern of ransomware."),
    ("Trojan.AntiDebug", 20, &["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"], "It checks whether it is being analysed in a debugger, which malware does to hide its behaviour from researchers."),
];

fn imports(pe: &PE) -> HashSet<String> {
    // Names without the A/W suffix, so "CreateProcessA" and "CreateProcessW" both match "CreateProcess".
    pe.imports.iter().map(|i| i.name.trim_end_matches(['A', 'W']).to_string()).collect()
}

pub fn evidence(data: &[u8]) -> Vec<Evidence> {
    let mut out = Vec::new();
    let Ok(pe) = PE::parse(data) else {
        return vec![Evidence::new("Suspicious.Malformed", 25, "It looks like a Windows program but its structure is damaged or deliberately malformed, which can be done to confuse security tools.")];
    };
    let signed = pe.header.optional_header.map(|o| o.data_directories.get_certificate_table().map(|d| d.size > 0).unwrap_or(false)).unwrap_or(false);
    let names = imports(&pe);

    // Packers and protectors compress or encrypt the real program so it can't be inspected.
    let mut packer: Option<&str> = None;
    let mut packed_sections = 0;
    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name).trim_end_matches('\0').to_lowercase();
        if let Some((_, p)) = PACKER_SECTIONS.iter().find(|(n, _)| *n == name) { packer = Some(p); }
        let start = section.pointer_to_raw_data as usize;
        let end = start.saturating_add(section.size_of_raw_data as usize).min(data.len());
        let executable = section.characteristics & goblin::pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0;
        if executable && end > start + 4096 && entropy(&data[start..end]) > 7.3 { packed_sections += 1; }
    }
    if let Some(p) = packer {
        out.push(Evidence::new("Suspicious.Packed", if signed { 10 } else { 35 }, format!("It is packed with {p}, which hides the real program inside a compressed or encrypted shell. Legitimate software uses this too, but most malware does.")));
    } else if packed_sections > 0 {
        out.push(Evidence::new("Suspicious.Packed", if signed { 10 } else { 40 }, "Its program code is encrypted or compressed (very high entropy), so its real behaviour is hidden until it runs."));
    }
    // A program that imports almost nothing loads everything at run time, usually to hide what it does.
    if !pe.is_lib && pe.imports.len() <= 3 && packer.is_none() && packed_sections > 0 {
        out.push(Evidence::new("Suspicious.HiddenImports", 25, "It imports almost no system functions and loads them while running instead, which hides its capabilities from inspection."));
    }
    for (name, score, needed, reason) in BEHAVIOURS {
        if needed.iter().all(|n| names.contains(*n)) {
            // A valid digital signature from a publisher makes these capabilities far more likely to be legitimate.
            out.push(Evidence::new(name, if signed { score / 4 } else { *score }, *reason));
        }
    }
    // Mining software, recognisable by its own strings.
    let text = String::from_utf8_lossy(&data[..data.len().min(8 * 1024 * 1024)]);
    // Stored reversed and turned around at run time, so BaazCyber's own program file doesn't match.
    let tool_strings = ["sdrowssapnogol::aslrukes", "mas::pmudasl", "cnycsd::pmudasl", "nedlog::soreberk", "iwkilitneg"]
        .map(|s| s.chars().rev().collect::<String>());
    if tool_strings.iter().any(|s| text.contains(s.as_str())) {
        out.push(Evidence::new("HackTool.Mimikatz", if signed { 40 } else { 95 }, "It contains Mimikatz, a tool that steals Windows passwords and login tickets from memory."));
    }
    if text.contains("stratum+tcp://") || text.contains("stratum+ssl://") || text.contains("xmrig") || text.contains("cryptonight") {
        out.push(Evidence::new("PUA.CoinMiner", 70, "It contains cryptocurrency mining code, which uses your computer's power to earn money for someone else.").pua());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn entropy_of_uniform_and_random_data() {
        assert_eq!(entropy(&[0u8; 1000]), 0.0);
        let all: Vec<u8> = (0..=255u8).cycle().take(256 * 40).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
    }
}
