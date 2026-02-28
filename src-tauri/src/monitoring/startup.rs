use std::collections::HashSet;
use std::fs;
use std::path::Path;

use crate::models::StartupProcess;
use crate::monitoring::trust;

#[cfg(target_os = "windows")]
use winreg::{enums::*, HKEY, RegKey};

#[cfg(target_os = "windows")]
pub fn get_startup_processes() -> Vec<StartupProcess> {
    let mut items = Vec::new();
    let mut seen = HashSet::new();

    collect_run_key(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM Run",
        &mut items,
        &mut seen,
    );
    collect_run_key(
        HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU Run",
        &mut items,
        &mut seen,
    );
    collect_startup_folder(
        Path::new("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        "Startup Folder (All Users)",
        &mut items,
        &mut seen,
    );

    if let Ok(roaming) = std::env::var("APPDATA") {
        let user_startup = Path::new(&roaming).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup");
        collect_startup_folder(
            &user_startup,
            "Startup Folder (Current User)",
            &mut items,
            &mut seen,
        );
    }

    items.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    items
}

#[cfg(target_os = "windows")]
fn collect_run_key(
    hive: HKEY,
    path: &str,
    source: &str,
    out: &mut Vec<StartupProcess>,
    seen: &mut HashSet<String>,
) {
    let root = RegKey::predef(hive);
    let Ok(run_key) = root.open_subkey(path) else {
        return;
    };

    for value in run_key.enum_values().flatten() {
        let name = value.0;
        let Ok(command) = run_key.get_value::<String, _>(&name) else {
            continue;
        };
        let executable = trust::extract_executable_from_command(&command);
        let trust_level = trust::classify_process_trust(executable.as_deref(), None);
        let dedupe_key = format!("{}|{}", name.to_lowercase(), command.to_lowercase());
        if !seen.insert(dedupe_key) {
            continue;
        }
        out.push(StartupProcess {
            name,
            command,
            location: executable.unwrap_or_default(),
            source: source.to_string(),
            trust_level,
        });
    }
}

#[cfg(target_os = "windows")]
fn collect_startup_folder(
    dir: &Path,
    source: &str,
    out: &mut Vec<StartupProcess>,
    seen: &mut HashSet<String>,
) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let name = path
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_string();
        if name.is_empty() {
            continue;
        }

        let location = path.to_string_lossy().to_string();
        let dedupe_key = format!("{}|{}", name.to_lowercase(), location.to_lowercase());
        if !seen.insert(dedupe_key) {
            continue;
        }

        out.push(StartupProcess {
            name,
            command: location.clone(),
            location: location.clone(),
            source: source.to_string(),
            trust_level: trust::classify_process_trust(Some(&location), None),
        });
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_startup_processes() -> Vec<StartupProcess> {
    Vec::new()
}
