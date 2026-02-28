pub mod gpu_collector;
pub mod process_collector;
pub mod programs;
pub mod startup;
pub mod trust;

use std::collections::HashMap;
use std::time::Duration;

use tauri::{AppHandle, Emitter};

use crate::app_state::RuntimeState;
use crate::detection;

const GPU_REFRESH_TICKS: u64 = 3;
const INVENTORY_REFRESH_TICKS: u64 = 300;
const SIGNATURE_PROBE_BUDGET: usize = 8;

pub fn start_background_tasks(app: AppHandle, state: RuntimeState) {
    refresh_installed_programs(&state);
    refresh_startup_processes(&state);

    tauri::async_runtime::spawn(async move {
        let mut gpu_cache: HashMap<u32, f32> = HashMap::new();
        let mut tick: u64 = 0;

        loop {
            let mut metrics = process_collector::collect_process_metrics();
            if tick % GPU_REFRESH_TICKS == 0 {
                gpu_cache = gpu_collector::collect_gpu_usage_by_pid();
            }

            let profile = state.profile();
            let parent_names: HashMap<u32, String> =
                metrics.iter().map(|m| (m.pid, m.name.to_lowercase())).collect();
            let mut live_pids = Vec::with_capacity(metrics.len());
            let mut signature_probes = 0usize;

            for metric in &mut metrics {
                live_pids.push(metric.pid);
                metric.gpu_pct = *gpu_cache.get(&metric.pid).unwrap_or(&0.0);

                let signed = if let Some(path) = metric.exe_path.as_ref() {
                    if let Some(cached) = state.get_cached_signature(path) {
                        Some(cached)
                    } else if signature_probes < SIGNATURE_PROBE_BUDGET
                        && should_probe_signature(path, metric.pid, tick)
                    {
                        signature_probes = signature_probes.saturating_add(1);
                        let discovered = process_collector::is_binary_signed(path);
                        state.put_cached_signature(path.clone(), discovered);
                        Some(discovered)
                    } else {
                        None
                    }
                } else {
                    None
                };

                let cpu_spike = state.update_cpu_and_check_spike(metric.pid, metric.cpu_pct);
                let parent_name = metric
                    .ppid
                    .and_then(|ppid| parent_names.get(&ppid))
                    .map(String::as_str);
                let assessment = detection::assess_process(
                    metric,
                    parent_name,
                    signed,
                    cpu_spike,
                    &profile,
                );
                metric.trust_level =
                    trust::classify_process_trust(metric.exe_path.as_deref(), signed);
                metric.trust_label = None;
                if let Some((level, label)) = state.known_process_override(metric) {
                    metric.trust_level = level;
                    metric.trust_label = label;
                }
                metric.suspicion = assessment.clone();

                if !is_internal_process(metric) {
                    if let Some(alert) = detection::build_alert(metric, &assessment, cpu_spike) {
                        if state.add_alert_if_new(alert.clone()).unwrap_or(false) {
                            let _ = app.emit("alert_created", &alert);
                        }
                    }
                }
            }

            state.prune_cpu_history(&live_pids);
            let tree = process_collector::build_process_tree(&metrics);
            state.update_snapshot(tree, metrics.clone());
            let _ = app.emit("process_snapshot_updated", &metrics);

            if tick % INVENTORY_REFRESH_TICKS == 0 {
                refresh_installed_programs(&state);
                refresh_startup_processes(&state);
            }

            tick = tick.saturating_add(1);
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

fn should_probe_signature(path: &str, pid: u32, tick: u64) -> bool {
    let rolling = path.bytes().fold(pid as u64, |acc, byte| {
        acc.wrapping_mul(16777619).wrapping_add(byte as u64)
    });
    (rolling.wrapping_add(tick)) % 5 == 0
}

fn refresh_installed_programs(state: &RuntimeState) {
    let mut programs = programs::get_installed_programs();
    for program in &mut programs {
        if let Some((level, label)) = state.known_program_override(program) {
            program.trust_level = level;
            program.trust_label = label;
        } else {
            program.trust_label = None;
        }
    }
    state.update_installed_programs(programs);
}

fn refresh_startup_processes(state: &RuntimeState) {
    let startup_items = startup::get_startup_processes();
    state.update_startup_processes(startup_items);
}

fn is_internal_process(metric: &crate::models::ProcessMetric) -> bool {
    let name = metric.name.to_lowercase();
    if name.contains("p-control") || name.contains("nyx monitor") || name.contains("nyx-monitor") {
        return true;
    }
    metric
        .exe_path
        .as_ref()
        .map(|path| {
            let lower = path.to_lowercase();
            lower.contains("\\p-control\\") || lower.contains("\\nyx monitor\\") || lower.contains("\\nyx-monitor\\")
        })
        .unwrap_or(false)
}
