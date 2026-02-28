use std::collections::HashMap;

#[cfg(target_os = "windows")]
use winreg::{enums::*, HKEY, RegKey};

#[cfg(target_os = "windows")]
const RUN_KEYS: &[(HKEY, &str, &str)] = &[
    (
        HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU",
    ),
    (
        HKEY_CURRENT_USER,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKCU",
    ),
    (
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM",
    ),
    (
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKLM",
    ),
    (
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "HKLM",
    ),
];

#[cfg(target_os = "windows")]
pub fn snapshot_critical_values() -> Result<HashMap<String, String>, String> {
    let mut snapshot = HashMap::new();

    for (hive, path, hive_label) in RUN_KEYS {
        collect_string_values(*hive, hive_label, path, &mut snapshot);
    }
    collect_ifeo_debugger_values(&mut snapshot);

    Ok(snapshot)
}

#[cfg(target_os = "windows")]
fn collect_string_values(
    hive: HKEY,
    hive_label: &str,
    path: &str,
    snapshot: &mut HashMap<String, String>,
) {
    let root = RegKey::predef(hive);
    let Ok(key) = root.open_subkey(path) else {
        return;
    };

    for value in key.enum_values().flatten() {
        let value_name = value.0;
        let Ok(value_data) = key.get_value::<String, _>(&value_name) else {
            continue;
        };
        let composite_key = format!("{}\\{}\\{}", hive_label, path, value_name);
        snapshot.insert(composite_key, value_data);
    }
}

#[cfg(target_os = "windows")]
fn collect_ifeo_debugger_values(snapshot: &mut HashMap<String, String>) {
    let root = RegKey::predef(HKEY_LOCAL_MACHINE);
    let ifeo_path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    let Ok(ifeo_root) = root.open_subkey(ifeo_path) else {
        return;
    };

    for subkey_name in ifeo_root.enum_keys().flatten() {
        let Ok(subkey) = ifeo_root.open_subkey(&subkey_name) else {
            continue;
        };
        let Ok(debugger) = subkey.get_value::<String, _>("Debugger") else {
            continue;
        };
        let composite_key = format!(
            "HKLM\\{}\\{}\\Debugger",
            ifeo_path,
            subkey_name
        );
        snapshot.insert(composite_key, debugger);
    }
}

#[cfg(not(target_os = "windows"))]
pub fn snapshot_critical_values() -> Result<HashMap<String, String>, String> {
    Ok(HashMap::new())
}
