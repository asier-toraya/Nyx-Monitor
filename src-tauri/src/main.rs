#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app_state;
mod detection;
mod models;
mod monitoring;
mod storage;

use anyhow::Context;
use app_state::RuntimeState;
use models::{CpuSpikeConfig, DetectionProfile, TrustLevel};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::process::Command;
use tauri::{Manager, State};

#[tauri::command]
fn get_process_tree(state: State<'_, RuntimeState>) -> Vec<models::ProcessNode> {
    state.get_process_tree()
}

#[tauri::command]
fn get_process_metrics(state: State<'_, RuntimeState>) -> Vec<models::ProcessMetric> {
    state.get_process_metrics()
}

#[tauri::command]
fn get_installed_programs(state: State<'_, RuntimeState>) -> Vec<models::InstalledProgram> {
    state.get_installed_programs()
}

#[tauri::command]
fn get_startup_processes(state: State<'_, RuntimeState>) -> Vec<models::StartupProcess> {
    state.get_startup_processes()
}

#[tauri::command]
fn get_app_usage_history(state: State<'_, RuntimeState>) -> Vec<models::AppUsageEntry> {
    state.get_app_usage_history()
}

#[tauri::command]
fn get_active_alerts(state: State<'_, RuntimeState>) -> Vec<models::Alert> {
    state.active_alerts()
}

#[tauri::command]
fn get_alert_history(state: State<'_, RuntimeState>) -> Vec<models::Alert> {
    state.alert_history()
}

#[tauri::command]
fn ack_alert(alert_id: String, state: State<'_, RuntimeState>) -> Result<bool, String> {
    state
        .acknowledge_alert(&alert_id)
        .map_err(|err| format!("failed acknowledging alert: {err}"))
}

#[tauri::command]
fn delete_alert(alert_id: String, state: State<'_, RuntimeState>) -> Result<bool, String> {
    state
        .delete_alert(&alert_id)
        .map_err(|err| format!("failed deleting alert: {err}"))
}

#[tauri::command]
fn delete_all_alerts(state: State<'_, RuntimeState>) -> Result<usize, String> {
    state
        .delete_all_active_alerts()
        .map_err(|err| format!("failed deleting all alerts: {err}"))
}

#[tauri::command]
fn set_detection_profile(profile: DetectionProfile, state: State<'_, RuntimeState>) {
    state.set_profile(profile);
}

#[tauri::command]
fn set_cpu_spike_threshold(config: CpuSpikeConfig, state: State<'_, RuntimeState>) {
    state.set_cpu_spike_config(config);
}

#[tauri::command]
fn add_known_process(
    path: Option<String>,
    name: String,
    label: String,
    state: State<'_, RuntimeState>,
) -> Result<bool, String> {
    state
        .add_known_process(path.as_deref(), &name, &label)
        .map_err(|err| format!("failed adding known process: {err}"))
}

#[tauri::command]
fn add_known_program(
    executable_path: Option<String>,
    install_location: Option<String>,
    name: String,
    label: String,
    state: State<'_, RuntimeState>,
) -> Result<bool, String> {
    state
        .add_known_program(
            executable_path.as_deref(),
            install_location.as_deref(),
            &name,
            &label,
        )
        .map_err(|err| format!("failed adding known program: {err}"))
}

#[tauri::command]
fn open_path_in_explorer(path: String) -> Result<bool, String> {
    let normalized = path.trim();
    if normalized.is_empty() {
        return Ok(false);
    }

    open_path_with_explorer(normalized)
}

#[tauri::command]
fn open_process_folder_by_pid(pid: u32, state: State<'_, RuntimeState>) -> Result<bool, String> {
    let metrics = state.get_process_metrics();
    let maybe_path = metrics
        .into_iter()
        .find(|metric| metric.pid == pid)
        .and_then(|metric| metric.exe_path);

    match maybe_path {
        Some(path) => open_path_with_explorer(&path),
        None => Ok(false),
    }
}

fn open_path_with_explorer(path: &str) -> Result<bool, String> {
    let normalized = path.trim();
    if normalized.is_empty() {
        return Ok(false);
    }

    let candidate = Path::new(normalized);
    let status = if candidate.is_file() {
        Command::new("explorer.exe")
            .arg(format!("/select,{}", normalized))
            .status()
    } else {
        Command::new("explorer.exe").arg(normalized).status()
    };

    match status {
        Ok(exit) => Ok(exit.success()),
        Err(err) => Err(format!("failed to open explorer: {err}")),
    }
}

#[tauri::command]
fn set_process_trust_override(
    path: Option<String>,
    name: String,
    trust_level: TrustLevel,
    label: Option<String>,
    state: State<'_, RuntimeState>,
) -> Result<bool, String> {
    state
        .set_process_trust_override(path.as_deref(), &name, trust_level, label.as_deref())
        .map_err(|err| format!("failed setting process override: {err}"))
}

#[tauri::command]
fn open_url_in_browser(url: String) -> Result<bool, String> {
    let normalized = url.trim();
    if normalized.is_empty() {
        return Ok(false);
    }

    let mut command = Command::new("cmd.exe");
    command.args(["/C", "start", "", normalized]);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let status = command.status();
    match status {
        Ok(exit) => Ok(exit.success()),
        Err(err) => Err(format!("failed opening browser url: {err}")),
    }
}

#[tauri::command]
fn get_file_sha256(path: String) -> Result<Option<String>, String> {
    let normalized = path.trim();
    if normalized.is_empty() {
        return Ok(None);
    }

    let candidate = Path::new(normalized);
    if !candidate.is_file() {
        return Ok(None);
    }

    let hash = compute_sha256(candidate)?;
    Ok(Some(hash))
}

fn compute_sha256(path: &Path) -> Result<String, String> {
    let file = File::open(path)
        .map_err(|err| format!("failed opening file for hashing {}: {err}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|err| format!("failed reading file for hashing {}: {err}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let digest = hasher.finalize();
    Ok(format!("{:x}", digest))
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .context("failed to resolve app data directory")?;
            std::fs::create_dir_all(&data_dir)
                .with_context(|| format!("failed creating app data dir {}", data_dir.display()))?;

            let state =
                RuntimeState::new(data_dir.join("alerts.json"), data_dir.join("known_entities.json"))?;
            monitoring::start_background_tasks(app.handle().clone(), state.clone());
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_process_tree,
            get_process_metrics,
            get_installed_programs,
            get_startup_processes,
            get_app_usage_history,
            get_active_alerts,
            get_alert_history,
            ack_alert,
            delete_alert,
            delete_all_alerts,
            set_detection_profile,
            set_cpu_spike_threshold,
            add_known_process,
            add_known_program,
            set_process_trust_override,
            open_path_in_explorer,
            open_process_folder_by_pid,
            open_url_in_browser,
            get_file_sha256
        ])
        .run(tauri::generate_context!())
        .expect("error while running nyx-monitor");
}
