use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use crate::models::{
    Alert, AppUsageEntry, CpuSpikeConfig, DetectionProfile, InstalledProgram, KnownEntity,
    KnownEntityKind, ProcessMetric, ProcessNode, StartupProcess, TrustLevel,
};
use crate::monitoring::trust;
use crate::storage::{AlertStore, KnownEntityStore};

#[derive(Clone)]
pub struct RuntimeState {
    inner: Arc<RuntimeStateInner>,
}

struct RuntimeStateInner {
    process_tree: RwLock<Vec<ProcessNode>>,
    process_metrics: RwLock<Vec<ProcessMetric>>,
    installed_programs: RwLock<Vec<InstalledProgram>>,
    startup_processes: RwLock<Vec<StartupProcess>>,
    detection_profile: RwLock<DetectionProfile>,
    cpu_spike_config: RwLock<CpuSpikeConfig>,
    cpu_history: Mutex<HashMap<u32, VecDeque<f32>>>,
    app_usage_history: Mutex<HashMap<String, AppUsageEntry>>,
    known_pids: Mutex<HashSet<u32>>,
    signature_cache: Mutex<HashMap<String, bool>>,
    store: Mutex<AlertStore>,
    known_store: Mutex<KnownEntityStore>,
}

impl RuntimeState {
    pub fn new(store_path: PathBuf, known_store_path: PathBuf) -> Result<Self> {
        let store = AlertStore::load(store_path).context("failed to initialize alert store")?;
        let known_store = KnownEntityStore::load(known_store_path)
            .context("failed to initialize known entity store")?;
        Ok(Self {
            inner: Arc::new(RuntimeStateInner {
                process_tree: RwLock::new(Vec::new()),
                process_metrics: RwLock::new(Vec::new()),
                installed_programs: RwLock::new(Vec::new()),
                startup_processes: RwLock::new(Vec::new()),
                detection_profile: RwLock::new(DetectionProfile::default()),
                cpu_spike_config: RwLock::new(CpuSpikeConfig::default()),
                cpu_history: Mutex::new(HashMap::new()),
                app_usage_history: Mutex::new(HashMap::new()),
                known_pids: Mutex::new(HashSet::new()),
                signature_cache: Mutex::new(HashMap::new()),
                store: Mutex::new(store),
                known_store: Mutex::new(known_store),
            }),
        })
    }

    pub fn get_process_tree(&self) -> Vec<ProcessNode> {
        self.inner
            .process_tree
            .read()
            .expect("poisoned process tree lock")
            .clone()
    }

    pub fn get_process_metrics(&self) -> Vec<ProcessMetric> {
        self.inner
            .process_metrics
            .read()
            .expect("poisoned process metrics lock")
            .clone()
    }

    pub fn get_installed_programs(&self) -> Vec<InstalledProgram> {
        self.inner
            .installed_programs
            .read()
            .expect("poisoned installed programs lock")
            .clone()
    }

    pub fn get_startup_processes(&self) -> Vec<StartupProcess> {
        self.inner
            .startup_processes
            .read()
            .expect("poisoned startup processes lock")
            .clone()
    }

    pub fn get_app_usage_history(&self) -> Vec<AppUsageEntry> {
        let mut list: Vec<AppUsageEntry> = self
            .inner
            .app_usage_history
            .lock()
            .expect("poisoned app usage history lock")
            .values()
            .cloned()
            .collect();
        list.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        list
    }

    pub fn update_snapshot(&self, tree: Vec<ProcessNode>, metrics: Vec<ProcessMetric>) {
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

    pub fn set_cpu_spike_config(&self, config: CpuSpikeConfig) {
        let mut lock = self
            .inner
            .cpu_spike_config
            .write()
            .expect("poisoned cpu spike config lock");
        *lock = config;
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

        let prior_avg = samples
            .iter()
            .take(prior_len)
            .sum::<f32>()
            / prior_len as f32;
        recent_avg > prior_avg * config.deviation_ratio
    }

    pub fn prune_cpu_history(&self, live_pids: &[u32]) {
        let live: std::collections::HashSet<u32> = live_pids.iter().copied().collect();
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

    pub fn add_alert_if_new(&self, alert: Alert) -> Result<bool> {
        let mut store = self.inner.store.lock().expect("poisoned alert store lock");
        let duplicate = store.history().into_iter().any(|existing| {
            existing.pid == alert.pid
                && existing.alert_type == alert.alert_type
                && existing.title == alert.title
                && is_recent(&existing.timestamp, 120)
        });
        if duplicate {
            return Ok(false);
        }
        store.push(alert)?;
        Ok(true)
    }

    pub fn acknowledge_alert(&self, alert_id: &str) -> Result<bool> {
        self.inner
            .store
            .lock()
            .expect("poisoned alert store lock")
            .acknowledge(alert_id)
    }

    pub fn delete_alert(&self, alert_id: &str) -> Result<bool> {
        self.inner
            .store
            .lock()
            .expect("poisoned alert store lock")
            .delete(alert_id)
    }

    pub fn delete_all_active_alerts(&self) -> Result<usize> {
        self.inner
            .store
            .lock()
            .expect("poisoned alert store lock")
            .delete_all_active()
    }

    pub fn add_known_process(&self, path: Option<&str>, name: &str, label: &str) -> Result<bool> {
        self.set_process_trust_override(path, name, TrustLevel::Trusted, Some(label))
    }

    pub fn set_process_trust_override(
        &self,
        path: Option<&str>,
        name: &str,
        trust_level: TrustLevel,
        label: Option<&str>,
    ) -> Result<bool> {
        let mut keys = trust::process_match_keys(path, name);
        keys.sort();
        keys.dedup();

        if keys.is_empty() {
            return Ok(false);
        }

        let normalized_label = label
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        let mut changed = false;
        let mut store = self
            .inner
            .known_store
            .lock()
            .expect("poisoned known store lock");
        for key in &keys {
            changed |= store.upsert(
                KnownEntityKind::Process,
                key.clone(),
                Some(trust_level.clone()),
                normalized_label.clone(),
            )?;
        }
        if let Some(name_key) = trust::normalize_key(name) {
            changed |= store.sync_process_aliases_by_name(
                &name_key,
                Some(trust_level.clone()),
                normalized_label.clone(),
            )?;
        }
        drop(store);

        if changed {
            self.apply_process_override_to_snapshot(&keys, &trust_level, normalized_label.as_deref());
        }

        Ok(changed)
    }

    pub fn add_known_program(
        &self,
        executable_path: Option<&str>,
        install_location: Option<&str>,
        name: &str,
        label: &str,
    ) -> Result<bool> {
        let key = trust::program_primary_key(executable_path, install_location, name);
        self.inner
            .known_store
            .lock()
            .expect("poisoned known store lock")
            .upsert(
                KnownEntityKind::Program,
                key,
                Some(TrustLevel::Trusted),
                Some(label.trim().to_string()),
            )
    }

    pub fn known_process_override(&self, metric: &ProcessMetric) -> Option<(TrustLevel, Option<String>)> {
        let keys = trust::process_match_keys(metric.exe_path.as_deref(), &metric.name);
        let store = self
            .inner
            .known_store
            .lock()
            .expect("poisoned known store lock");

        let mut selected: Option<KnownEntity> = None;
        for key in keys {
            if let Some(entity) = store.find(KnownEntityKind::Process, &key) {
                selected = pick_latest_entity(selected, entity);
            }
        }
        selected.map(|entity| (entity.trust_level.unwrap_or(TrustLevel::Trusted), entity.label))
    }

    pub fn known_program_override(
        &self,
        program: &InstalledProgram,
    ) -> Option<(TrustLevel, Option<String>)> {
        let keys = trust::program_match_keys(
            program.executable_path.as_deref(),
            program.install_location.as_deref(),
            &program.name,
        );
        let store = self
            .inner
            .known_store
            .lock()
            .expect("poisoned known store lock");

        let mut selected: Option<KnownEntity> = None;
        for key in keys {
            if let Some(entity) = store.find(KnownEntityKind::Program, &key) {
                selected = pick_latest_entity(selected, entity);
            }
        }
        selected.map(|entity| (entity.trust_level.unwrap_or(TrustLevel::Trusted), entity.label))
    }

    pub fn active_alerts(&self) -> Vec<Alert> {
        self.inner
            .store
            .lock()
            .expect("poisoned alert store lock")
            .active_alerts()
    }

    pub fn alert_history(&self) -> Vec<Alert> {
        self.inner
            .store
            .lock()
            .expect("poisoned alert store lock")
            .history()
    }
}

impl RuntimeState {
    fn apply_process_override_to_snapshot(
        &self,
        keys: &[String],
        trust_level: &TrustLevel,
        label: Option<&str>,
    ) {
        let key_set: std::collections::HashSet<String> = keys.iter().cloned().collect();
        let mut metrics_lock = self
            .inner
            .process_metrics
            .write()
            .expect("poisoned process metrics lock");

        for metric in metrics_lock.iter_mut() {
            let metric_keys = trust::process_match_keys(metric.exe_path.as_deref(), &metric.name);
            if metric_keys.iter().any(|key| key_set.contains(key)) {
                metric.trust_level = trust_level.clone();
                metric.trust_label = label.map(ToString::to_string);
            }
        }

        let refreshed_tree = crate::monitoring::process_collector::build_process_tree(&metrics_lock);
        drop(metrics_lock);

        let mut tree_lock = self
            .inner
            .process_tree
            .write()
            .expect("poisoned process tree lock");
        *tree_lock = refreshed_tree;
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

fn is_recent(timestamp: &str, window_seconds: i64) -> bool {
    let now = Utc::now();
    let parsed = DateTime::parse_from_rfc3339(timestamp)
        .ok()
        .map(|dt| dt.with_timezone(&Utc));
    match parsed {
        Some(ts) => now.signed_duration_since(ts).num_seconds().abs() <= window_seconds,
        None => false,
    }
}

fn pick_latest_entity(current: Option<KnownEntity>, candidate: KnownEntity) -> Option<KnownEntity> {
    match current {
        None => Some(candidate),
        Some(existing) => {
            if candidate.created_at >= existing.created_at {
                Some(candidate)
            } else {
                Some(existing)
            }
        }
    }
}
