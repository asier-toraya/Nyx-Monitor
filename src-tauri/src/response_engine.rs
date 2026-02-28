use std::process::Command;

use crate::models::ResponseActionType;

const CRITICAL_PROCESS_NAMES: &[&str] = &[
    "system",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "explorer.exe",
    "dwm.exe",
];

pub fn is_critical_process(name: &str, path: Option<&str>) -> bool {
    let lower_name = name.to_lowercase();
    if CRITICAL_PROCESS_NAMES.iter().any(|item| *item == lower_name) {
        return true;
    }
    path.map(|value| {
        let lower = value.to_lowercase();
        lower.starts_with("c:\\windows\\system32\\")
            && (lower.contains("\\csrss.exe")
                || lower.contains("\\wininit.exe")
                || lower.contains("\\services.exe")
                || lower.contains("\\lsass.exe")
                || lower.contains("\\winlogon.exe"))
    })
    .unwrap_or(false)
}

pub fn execute_action(
    action: &ResponseActionType,
    pid: u32,
    process_path: Option<&str>,
) -> Result<String, String> {
    match action {
        ResponseActionType::SuspendProcess => suspend_process(pid),
        ResponseActionType::TerminateProcess => terminate_process(pid),
        ResponseActionType::BlockProcessNetwork => block_process_network(pid, process_path),
    }
}

#[cfg(target_os = "windows")]
fn suspend_process(pid: u32) -> Result<String, String> {
    let script = format!(
        "$ErrorActionPreference='Stop'; Suspend-Process -Id {} -ErrorAction Stop; 'ok'",
        pid
    );
    let mut command = Command::new("powershell.exe");
    command.args(["-NoProfile", "-Command", &script]);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let output = command
        .output()
        .map_err(|err| format!("failed executing suspend process command: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "suspend process failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(format!("process {} suspended", pid))
}

#[cfg(target_os = "windows")]
fn terminate_process(pid: u32) -> Result<String, String> {
    let mut command = Command::new("taskkill");
    command.args(["/PID", &pid.to_string(), "/T", "/F"]);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let output = command
        .output()
        .map_err(|err| format!("failed executing terminate process command: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "terminate process failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(format!("process {} terminated", pid))
}

#[cfg(target_os = "windows")]
fn block_process_network(pid: u32, process_path: Option<&str>) -> Result<String, String> {
    let path = process_path
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "process path unavailable for firewall block action".to_string())?;

    let rule_name = format!(
        "NyxMonitor_Block_PID_{}_{}",
        pid,
        chrono::Utc::now().timestamp()
    );

    let mut command = Command::new("netsh");
    command.args([
        "advfirewall",
        "firewall",
        "add",
        "rule",
        &format!("name={}", rule_name),
        "dir=out",
        "action=block",
        &format!("program={}", path),
        "enable=yes",
        "profile=any",
    ]);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let output = command
        .output()
        .map_err(|err| format!("failed executing firewall command: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "block network failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(format!("outbound network blocked by firewall rule {}", rule_name))
}

#[cfg(not(target_os = "windows"))]
fn suspend_process(_pid: u32) -> Result<String, String> {
    Err("unsupported platform".to_string())
}

#[cfg(not(target_os = "windows"))]
fn terminate_process(_pid: u32) -> Result<String, String> {
    Err("unsupported platform".to_string())
}

#[cfg(not(target_os = "windows"))]
fn block_process_network(_pid: u32, _process_path: Option<&str>) -> Result<String, String> {
    Err("unsupported platform".to_string())
}
