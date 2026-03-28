use std::collections::HashSet;

use chrono::Utc;

use crate::models::{
    AppUsageEntry, CpuSpikeConfig, DetectionProfile, InstalledProgram, StartupProcess,
};

use super::RuntimeState;

impl RuntimeState {
    pub fn update_snapshot(
        &self,
        tree: Vec<crate::models::ProcessNode>,
        metrics: Vec<crate::models::ProcessMetric>,
    ) {
        {
            let mut lock = self
                .inner
                .process_tree
                .write()
                .expect("poisoned process tree lock");
            *lock = tree;
        }
        {
            let mut lock = self
                .inner
                .process_metrics
                .write()
                .expect("poisoned process metrics lock");
            *lock = metrics;
        }

        self.update_usage_history();
    }

    pub fn update_installed_programs(&self, programs: Vec<InstalledProgram>) {
        let mut lock = self
            .inner
            .installed_programs
            .write()
            .expect("poisoned installed programs lock");
        *lock = programs;
    }

    pub fn update_startup_processes(&self, startup_processes: Vec<StartupProcess>) {
        let mut lock = self
            .inner
            .startup_processes
            .write()
            .expect("poisoned startup processes lock");
        *lock = startup_processes;
    }

    pub fn profile(&self) -> DetectionProfile {
        self.inner
            .detection_profile
            .read()
            .expect("poisoned detection profile lock")
            .clone()
    }

    pub fn set_profile(&self, profile: DetectionProfile) {
        let mut lock = self
            .inner
            .detection_profile
            .write()
            .expect("poisoned detection profile lock");
        *lock = profile;
    }

    pub fn cpu_spike_config(&self) -> CpuSpikeConfig {
        self.inner
            .cpu_spike_config
            .read()
            .expect("poisoned cpu spike config lock")
            .clone()
    }

    pub fn update_cpu_and_check_spike(&self, pid: u32, sample: f32) -> bool {
        let config = self.cpu_spike_config();
        let mut history = self
            .inner
            .cpu_history
            .lock()
            .expect("poisoned cpu history lock");
        let samples = history.entry(pid).or_default();
        samples.push_back(sample);
        while samples.len() > 120 {
            samples.pop_front();
        }

        if samples.len() < config.min_consecutive_samples {
            return false;
        }

        let recent: Vec<f32> = samples
            .iter()
            .rev()
            .take(config.min_consecutive_samples)
            .copied()
            .collect();

        if !recent.iter().all(|value| *value >= config.threshold_pct) {
            return false;
        }

        let recent_avg = recent.iter().sum::<f32>() / recent.len() as f32;
        let prior_len = samples.len().saturating_sub(config.min_consecutive_samples);
        if prior_len < 5 {
            return recent_avg > config.threshold_pct + 5.0;
        }

        let prior_avg = samples.iter().take(prior_len).sum::<f32>() / prior_len as f32;
        recent_avg > prior_avg * config.deviation_ratio
    }

    pub fn prune_cpu_history(&self, live_pids: &[u32]) {
        let live: HashSet<u32> = live_pids.iter().copied().collect();
        let mut history = self
            .inner
            .cpu_history
            .lock()
            .expect("poisoned cpu history lock");
        history.retain(|pid, _| live.contains(pid));
    }

    pub fn get_cached_signature(&self, path: &str) -> Option<bool> {
        self.inner
            .signature_cache
            .lock()
            .expect("poisoned signature cache lock")
            .get(path)
            .copied()
    }

    pub fn put_cached_signature(&self, path: String, is_signed: bool) {
        self.inner
            .signature_cache
            .lock()
            .expect("poisoned signature cache lock")
            .insert(path, is_signed);
    }

    fn update_usage_history(&self) {
        let now = Utc::now().to_rfc3339();
        let metrics = self.get_process_metrics();

        let mut usage = self
            .inner
            .app_usage_history
            .lock()
            .expect("poisoned app usage history lock");
        let mut known_pids = self
            .inner
            .known_pids
            .lock()
            .expect("poisoned known pids lock");

        let live_pids: HashSet<u32> = metrics.iter().map(|metric| metric.pid).collect();

        for metric in metrics {
            let app_key = metric
                .exe_path
                .clone()
                .unwrap_or_else(|| metric.name.to_lowercase());
            let entry = usage.entry(app_key.clone()).or_insert_with(|| AppUsageEntry {
                app_key: app_key.clone(),
                name: metric.name.clone(),
                executable_path: metric.exe_path.clone(),
                launch_count: 0,
                max_cpu_pct: 0.0,
                last_pid: None,
                first_seen: now.clone(),
                last_seen: now.clone(),
            });

            if !known_pids.contains(&metric.pid) {
                entry.launch_count = entry.launch_count.saturating_add(1);
            }

            entry.name = metric.name.clone();
            entry.executable_path = metric.exe_path.clone();
            entry.max_cpu_pct = entry.max_cpu_pct.max(metric.cpu_pct);
            entry.last_pid = Some(metric.pid);
            entry.last_seen = now.clone();
        }

        *known_pids = live_pids;
    }
}
