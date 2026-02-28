use std::collections::HashSet;

use crate::models::InstalledProgram;
use crate::monitoring::trust;

#[cfg(target_os = "windows")]
use winreg::{enums::*, HKEY, RegKey};

#[cfg(target_os = "windows")]
pub fn get_installed_programs() -> Vec<InstalledProgram> {
    let mut programs = Vec::new();
    let mut seen = HashSet::new();

    collect_from_hive(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "HKLM", &mut programs, &mut seen);
    collect_from_hive(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "HKLM-WOW6432", &mut programs, &mut seen);
    collect_from_hive(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "HKCU", &mut programs, &mut seen);

    programs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    programs
}

#[cfg(target_os = "windows")]
fn collect_from_hive(
    hive: HKEY,
    path: &str,
    source: &str,
    out: &mut Vec<InstalledProgram>,
    seen: &mut HashSet<String>,
) {
    let root = RegKey::predef(hive);
    let Ok(uninstall) = root.open_subkey(path) else {
        return;
    };

    for key_name in uninstall.enum_keys().flatten() {
        let Ok(app_key) = uninstall.open_subkey(&key_name) else {
            continue;
        };

        let Ok(name) = app_key.get_value::<String, _>("DisplayName") else {
            continue;
        };

        if name.trim().is_empty() {
            continue;
        }

        let version = app_key.get_value::<String, _>("DisplayVersion").ok();
        let publisher = app_key.get_value::<String, _>("Publisher").ok();
        let install_date = app_key.get_value::<String, _>("InstallDate").ok();
        let install_location = app_key.get_value::<String, _>("InstallLocation").ok();
        let display_icon = app_key.get_value::<String, _>("DisplayIcon").ok();
        let uninstall_string = app_key.get_value::<String, _>("UninstallString").ok();

        let executable_path = display_icon
            .as_deref()
            .and_then(trust::extract_executable_from_command)
            .or_else(|| {
                uninstall_string
                    .as_deref()
                    .and_then(trust::extract_executable_from_command)
            });
        let trust_level = trust::classify_program_trust(
            &name,
            publisher.as_deref(),
            install_location.as_deref(),
            executable_path.as_deref(),
        );

        let dedupe_key = format!(
            "{}|{}|{}",
            name.to_lowercase(),
            version.clone().unwrap_or_default().to_lowercase(),
            publisher.clone().unwrap_or_default().to_lowercase()
        );
        if !seen.insert(dedupe_key) {
            continue;
        }

        out.push(InstalledProgram {
            name,
            version,
            publisher,
            install_date,
            install_location,
            executable_path,
            trust_level,
            trust_label: None,
            source: source.to_string(),
        });
    }
}

#[cfg(not(target_os = "windows"))]
pub fn get_installed_programs() -> Vec<InstalledProgram> {
    Vec::new()
}
