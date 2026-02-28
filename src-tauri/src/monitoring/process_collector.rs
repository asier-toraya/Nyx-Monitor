use std::collections::HashMap;
use std::process::Command;
use std::sync::{Mutex, OnceLock};

use chrono::{TimeZone, Utc};
use sysinfo::System;

use crate::models::{ProcessMetric, ProcessNode, RiskLevel, ThreatVerdict, TrustLevel};

pub fn collect_process_metrics() -> Vec<ProcessMetric> {
    static COLLECTOR: OnceLock<Mutex<ProcessCollector>> = OnceLock::new();
    let collector = COLLECTOR.get_or_init(|| Mutex::new(ProcessCollector::new()));
    let mut guard = collector.lock().expect("poisoned process collector lock");
    guard.collect()
}

struct ProcessCollector {
    system: System,
}

impl ProcessCollector {
    fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();
        Self { system }
    }

    fn collect(&mut self) -> Vec<ProcessMetric> {
        self.system.refresh_all();
        let mut metrics = Vec::with_capacity(self.system.processes().len());

        for (pid, process) in self.system.processes() {
            let started = Utc
                .timestamp_opt(process.start_time() as i64, 0)
                .single()
                .map(|value| value.to_rfc3339());

            metrics.push(ProcessMetric {
                pid: pid.as_u32(),
                ppid: process.parent().map(|value| value.as_u32()),
                name: process.name().to_string_lossy().to_string(),
                exe_path: process.exe().map(|value| value.to_string_lossy().to_string()),
                user: None,
                cpu_pct: process.cpu_usage().max(0.0),
                gpu_pct: 0.0,
                memory_mb: (process.memory() as f32 / 1024.0 / 1024.0).max(0.0),
                status: format!("{:?}", process.status()),
                started_at: started,
                trust_level: TrustLevel::Unknown,
                trust_label: None,
                suspicion: Default::default(),
                risk_factors: Vec::new(),
                risk_score: 0,
                verdict: ThreatVerdict::Benign,
            });
        }

        metrics.sort_by(|a, b| b.cpu_pct.total_cmp(&a.cpu_pct));
        metrics
    }
}

pub fn build_process_tree(metrics: &[ProcessMetric]) -> Vec<ProcessNode> {
    let mut by_pid: HashMap<u32, &ProcessMetric> = HashMap::new();
    let mut children_by_parent: HashMap<Option<u32>, Vec<u32>> = HashMap::new();

    for metric in metrics {
        by_pid.insert(metric.pid, metric);
        children_by_parent
            .entry(metric.ppid)
            .or_default()
            .push(metric.pid);
    }

    let mut roots = Vec::new();
    for metric in metrics {
        if metric.ppid.is_none() || !by_pid.contains_key(&metric.ppid.unwrap_or_default()) {
            roots.push(metric.pid);
        }
    }

    roots.sort_unstable();
    roots.dedup();

    let mut nodes: Vec<ProcessNode> = roots
        .into_iter()
        .filter_map(|pid| build_node(pid, &by_pid, &children_by_parent))
        .collect();
    nodes.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    nodes
}

pub fn is_binary_signed(path: &str) -> bool {
    let escaped = path.replace('\'', "''");
    let script = format!(
        "$ErrorActionPreference='SilentlyContinue'; (Get-AuthenticodeSignature -LiteralPath '{}').Status",
        escaped
    );
    let mut command = Command::new("powershell.exe");
    command.args(["-NoProfile", "-Command", &script]);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let output = command.output();

    match output {
        Ok(out) if out.status.success() => {
            let status = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
            status == "valid"
        }
        _ => false,
    }
}

fn build_node(
    pid: u32,
    by_pid: &HashMap<u32, &ProcessMetric>,
    children_by_parent: &HashMap<Option<u32>, Vec<u32>>,
) -> Option<ProcessNode> {
    let metric = by_pid.get(&pid)?;
    let children_pids = children_by_parent.get(&Some(pid)).cloned().unwrap_or_default();
    let mut children: Vec<ProcessNode> = children_pids
        .into_iter()
        .filter_map(|child_pid| build_node(child_pid, by_pid, children_by_parent))
        .collect();
    children.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    Some(ProcessNode {
        pid: metric.pid,
        ppid: metric.ppid,
        name: metric.name.clone(),
        exe_path: metric.exe_path.clone(),
        user: metric.user.clone(),
        risk: match metric.suspicion.level {
            RiskLevel::Legitimate => RiskLevel::Legitimate,
            RiskLevel::Unknown => RiskLevel::Unknown,
            RiskLevel::Suspicious => RiskLevel::Suspicious,
        },
        trust_level: metric.trust_level.clone(),
        trust_label: metric.trust_label.clone(),
        children,
    })
}
