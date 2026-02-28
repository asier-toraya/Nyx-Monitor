use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use crate::models::{
    Alert, AppUsageEntry, CpuSpikeConfig, DetectionProfile, EventEnvelope, InstalledProgram,
    KnownEntity, KnownEntityKind, PerformanceStats, ProcessMetric, ProcessNode, ResponseActionRecord,
    ResponseActionType, ResponseMode, ResponsePolicy, SensorHealth, StartupProcess, TrustLevel,
};
use crate::monitoring::trust;
use crate::response_engine;
use crate::storage::{AlertStore, EventStore, KnownEntityStore, ResponseActionStore};

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
    event_store: Mutex<EventStore>,
    known_store: Mutex<KnownEntityStore>,
    response_store: Mutex<ResponseActionStore>,
    sensor_health: Mutex<HashMap<String, SensorHealth>>,
    loop_samples: Mutex<VecDeque<f32>>,
    last_loop_ms: Mutex<f32>,
    response_policy: RwLock<ResponsePolicy>,
    action_cooldowns: Mutex<HashMap<String, DateTime<Utc>>>,
    dismissed_alerts: Mutex<HashMap<String, DateTime<Utc>>>,
    host_id: String,
}

impl RuntimeState {
    pub fn new(
        store_path: PathBuf,
        known_store_path: PathBuf,
        event_store_path: PathBuf,
        response_store_path: PathBuf,
    ) -> Result<Self> {
        let store = AlertStore::load(store_path).context("failed to initialize alert store")?;
        let known_store = KnownEntityStore::load(known_store_path)
            .context("failed to initialize known entity store")?;
        let event_store = EventStore::load(event_store_path)
            .context("failed to initialize event store")?;
        let response_store = ResponseActionStore::load(response_store_path)
            .context("failed to initialize response action store")?;
        let host_id = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown-host".to_string());
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
                event_store: Mutex::new(event_store),
                known_store: Mutex::new(known_store),
                response_store: Mutex::new(response_store),
                sensor_health: Mutex::new(HashMap::new()),
                loop_samples: Mutex::new(VecDeque::with_capacity(256)),
                last_loop_ms: Mutex::new(0.0),
                response_policy: RwLock::new(ResponsePolicy::default()),
                action_cooldowns: Mutex::new(HashMap::new()),
                dismissed_alerts: Mutex::new(HashMap::new()),
                host_id,
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

    pub fn host_id(&self) -> String {
        self.inner.host_id.clone()
    }

    pub fn push_event(&self, event: EventEnvelope) -> Result<()> {
        let sensor_name = event.sensor.clone();
        self.inner
            .event_store
            .lock()
            .expect("poisoned event store lock")
            .insert_event(&event)?;
        self.record_sensor_success(&sensor_name, None);
        if let Some(entry) = self
            .inner
            .sensor_health
            .lock()
            .expect("poisoned sensor health lock")
            .get_mut(&sensor_name)
        {
            entry.events_emitted = entry.events_emitted.saturating_add(1);
        }
        Ok(())
    }

    pub fn get_event_timeline(
        &self,
        limit: usize,
        event_type: Option<&str>,
        sensor: Option<&str>,
        search: Option<&str>,
    ) -> Vec<EventEnvelope> {
        self.inner
            .event_store
            .lock()
            .expect("poisoned event store lock")
            .list_events(limit, event_type, sensor, search)
            .unwrap_or_default()
    }

    pub fn record_sensor_success(&self, sensor: &str, latency_ms: Option<f32>) {
        let mut health = self
            .inner
            .sensor_health
            .lock()
            .expect("poisoned sensor health lock");
        let entry = health.entry(sensor.to_string()).or_insert_with(|| SensorHealth {
            sensor: sensor.to_string(),
            status: "ok".to_string(),
            last_success_utc: None,
            last_error: None,
            events_emitted: 0,
            last_latency_ms: None,
        });

        entry.status = "ok".to_string();
        entry.last_success_utc = Some(Utc::now().to_rfc3339());
        entry.last_error = None;
        if let Some(latency) = latency_ms {
            entry.last_latency_ms = Some(latency);
        }
    }

    pub fn record_sensor_error(&self, sensor: &str, error: &str) {
        let mut health = self
            .inner
            .sensor_health
            .lock()
            .expect("poisoned sensor health lock");
        let entry = health.entry(sensor.to_string()).or_insert_with(|| SensorHealth {
            sensor: sensor.to_string(),
            status: "degraded".to_string(),
            last_success_utc: None,
            last_error: None,
            events_emitted: 0,
            last_latency_ms: None,
        });

        entry.status = "degraded".to_string();
        entry.last_error = Some(error.to_string());
    }

    pub fn get_sensor_health(&self) -> Vec<SensorHealth> {
        let mut list: Vec<SensorHealth> = self
            .inner
            .sensor_health
            .lock()
            .expect("poisoned sensor health lock")
            .values()
            .cloned()
            .collect();
        list.sort_by(|a, b| a.sensor.cmp(&b.sensor));
        list
    }

    pub fn record_loop_timing(&self, duration_ms: f32) {
        {
            let mut last = self
                .inner
                .last_loop_ms
                .lock()
                .expect("poisoned last loop timing lock");
            *last = duration_ms;
        }
        let mut samples = self
            .inner
            .loop_samples
            .lock()
            .expect("poisoned loop samples lock");
        samples.push_back(duration_ms);
        while samples.len() > 240 {
            samples.pop_front();
        }
    }

    pub fn get_performance_stats(&self) -> PerformanceStats {
        let samples = self
            .inner
            .loop_samples
            .lock()
            .expect("poisoned loop samples lock");
        let mut sorted: Vec<f32> = samples.iter().copied().collect();
        sorted.sort_by(f32::total_cmp);
        let avg = if sorted.is_empty() {
            0.0
        } else {
            sorted.iter().sum::<f32>() / sorted.len() as f32
        };
        let p95 = percentile(&sorted, 95.0);
        drop(samples);

        let last = *self
            .inner
            .last_loop_ms
            .lock()
            .expect("poisoned last loop timing lock");
        let total_events = self
            .inner
            .event_store
            .lock()
            .expect("poisoned event store lock")
            .total_events()
            .unwrap_or(0);
        let tracked_processes = self
            .inner
            .process_metrics
            .read()
            .expect("poisoned process metrics lock")
            .len();

        PerformanceStats {
            loop_last_ms: last,
            loop_avg_ms: avg,
            loop_p95_ms: p95,
            total_events,
            event_store_size: total_events,
            tracked_processes,
        }
    }

    pub fn get_response_policy(&self) -> ResponsePolicy {
        self.inner
            .response_policy
            .read()
            .expect("poisoned response policy lock")
            .clone()
    }

    pub fn set_response_policy(&self, policy: ResponsePolicy) {
        let mut lock = self
            .inner
            .response_policy
            .write()
            .expect("poisoned response policy lock");
        *lock = policy;
    }

    pub fn get_response_actions(&self, limit: usize) -> Vec<ResponseActionRecord> {
        self.inner
            .response_store
            .lock()
            .expect("poisoned response store lock")
            .list_recent(limit.clamp(1, 1_000))
    }

    pub fn run_response_action(
        &self,
        pid: u32,
        action_type: ResponseActionType,
        reason: Option<&str>,
        automatic: bool,
    ) -> Result<ResponseActionRecord> {
        let metric = self
            .get_process_metrics()
            .into_iter()
            .find(|item| item.pid == pid)
            .ok_or_else(|| anyhow::anyhow!("process pid {} not found", pid))?;

        let policy = self.get_response_policy();
        let reason_text = reason
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("manual action");

        if automatic && policy.mode != ResponseMode::Constrain {
            return Err(anyhow::anyhow!(
                "automatic constrain blocked because policy mode is audit"
            ));
        }

        if policy.safe_mode
            && response_engine::is_critical_process(&metric.name, metric.exe_path.as_deref())
        {
            return Err(anyhow::anyhow!(
                "safe mode blocked action on critical process {} ({})",
                metric.name,
                metric.pid
            ));
        }

        if action_type == ResponseActionType::TerminateProcess && !policy.allow_terminate {
            return Err(anyhow::anyhow!(
                "terminate action blocked by policy (allow_terminate=false)"
            ));
        }

        if automatic && !self.is_action_allowed_by_cooldown(pid, &action_type, policy.cooldown_seconds) {
            return Err(anyhow::anyhow!("automatic action skipped by cooldown guardrail"));
        }

        let execution = response_engine::execute_action(&action_type, pid, metric.exe_path.as_deref());
        let (success, details) = match execution {
            Ok(msg) => (true, msg),
            Err(err) => (false, err),
        };

        let record = ResponseActionRecord {
            id: format!(
                "response-{}-{}-{}",
                pid,
                action_type_label(&action_type),
                Utc::now().timestamp_millis()
            ),
            timestamp_utc: Utc::now().to_rfc3339(),
            action_type: action_type.clone(),
            mode: policy.mode,
            pid,
            process_name: metric.name.clone(),
            success,
            automatic,
            score: metric.risk_score,
            verdict: metric.verdict.clone(),
            reason: reason_text.to_string(),
            details: details.clone(),
        };

        self.inner
            .response_store
            .lock()
            .expect("poisoned response store lock")
            .push(record.clone())?;

        if automatic {
            self.update_action_cooldown(pid, &action_type);
        }

        let event = EventEnvelope {
            event_id: format!(
                "response-action-{}-{}",
                pid,
                Utc::now().timestamp_millis()
            ),
            host_id: self.host_id(),
            timestamp_utc: Utc::now().to_rfc3339(),
            event_type: "response_action".to_string(),
            sensor: "response".to_string(),
            severity: if success {
                crate::models::EventSeverity::Warn
            } else {
                crate::models::EventSeverity::Critical
            },
            message: format!(
                "{} action {} for process {} ({})",
                if automatic { "Automatic" } else { "Manual" },
                action_type_label(&action_type),
                metric.name,
                metric.pid
            ),
            process: Some(crate::models::ProcessIdentity {
                pid: metric.pid,
                ppid: metric.ppid,
                image_name: metric.name.clone(),
                image_path: metric.exe_path.clone(),
                cmdline: None,
                user: metric.user.clone(),
            }),
            network: None,
            registry: None,
            rule_hits: vec![reason_text.to_string()],
            risk_score: Some(metric.risk_score),
            verdict: Some(verdict_label(&metric.verdict)),
            evidence_refs: vec![details],
        };
        let _ = self.push_event(event);

        Ok(record)
    }

    pub fn maybe_run_auto_response(&self, metric: &ProcessMetric) -> Option<ResponseActionRecord> {
        let policy = self.get_response_policy();
        if policy.mode != ResponseMode::Constrain {
            return None;
        }
        if metric.risk_score < policy.auto_constrain_threshold {
            return None;
        }
        let action = if metric.risk_score >= 95 && policy.allow_terminate {
            ResponseActionType::TerminateProcess
        } else if metric.exe_path.is_some() {
            ResponseActionType::BlockProcessNetwork
        } else {
            ResponseActionType::SuspendProcess
        };

        self.run_response_action(
            metric.pid,
            action,
            Some("automatic constrain by risk threshold"),
            true,
        )
        .ok()
    }

    fn is_action_allowed_by_cooldown(
        &self,
        pid: u32,
        action_type: &ResponseActionType,
        cooldown_seconds: u64,
    ) -> bool {
        let key = format!("{}:{}", pid, action_type_label(action_type));
        let lock = self
            .inner
            .action_cooldowns
            .lock()
            .expect("poisoned action cooldown lock");
        match lock.get(&key) {
            None => true,
            Some(last) => {
                Utc::now()
                    .signed_duration_since(*last)
                    .num_seconds()
                    >= cooldown_seconds as i64
            }
        }
    }

    fn update_action_cooldown(&self, pid: u32, action_type: &ResponseActionType) {
        let key = format!("{}:{}", pid, action_type_label(action_type));
        self.inner
            .action_cooldowns
            .lock()
            .expect("poisoned action cooldown lock")
            .insert(key, Utc::now());
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
        if self.is_alert_suppressed(&alert) {
            return Ok(false);
        }
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
        let mut store = self.inner.store.lock().expect("poisoned alert store lock");
        let deleted_alert = store
            .history()
            .into_iter()
            .find(|alert| alert.id == alert_id && alert.status == crate::models::AlertStatus::Active);
        let deleted = store.delete(alert_id)?;
        drop(store);
        if deleted {
            if let Some(alert) = deleted_alert {
                self.mark_alert_dismissed(&alert);
            }
        }
        Ok(deleted)
    }

    pub fn delete_all_active_alerts(&self) -> Result<usize> {
        let mut store = self.inner.store.lock().expect("poisoned alert store lock");
        let active_alerts = store.active_alerts();
        let deleted = store.delete_all_active()?;
        drop(store);
        if deleted > 0 {
            for alert in &active_alerts {
                self.mark_alert_dismissed(alert);
            }
        }
        Ok(deleted)
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
    fn is_alert_suppressed(&self, alert: &Alert) -> bool {
        const ALERT_SUPPRESSION_SECONDS: i64 = 300;
        let now = Utc::now();
        let signature = alert_signature(alert);
        let mut dismissed = self
            .inner
            .dismissed_alerts
            .lock()
            .expect("poisoned dismissed alerts lock");
        dismissed.retain(|_, timestamp| {
            now.signed_duration_since(*timestamp).num_seconds() < ALERT_SUPPRESSION_SECONDS
        });
        dismissed
            .get(&signature)
            .map(|timestamp| {
                now.signed_duration_since(*timestamp).num_seconds() < ALERT_SUPPRESSION_SECONDS
            })
            .unwrap_or(false)
    }

    fn mark_alert_dismissed(&self, alert: &Alert) {
        let signature = alert_signature(alert);
        self.inner
            .dismissed_alerts
            .lock()
            .expect("poisoned dismissed alerts lock")
            .insert(signature, Utc::now());
    }

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

fn percentile(sorted_values: &[f32], percentile: f32) -> f32 {
    if sorted_values.is_empty() {
        return 0.0;
    }
    let rank = ((percentile / 100.0) * (sorted_values.len().saturating_sub(1) as f32)).round();
    let index = rank as usize;
    sorted_values.get(index).copied().unwrap_or(0.0)
}

fn action_type_label(action_type: &ResponseActionType) -> &'static str {
    match action_type {
        ResponseActionType::SuspendProcess => "suspend_process",
        ResponseActionType::BlockProcessNetwork => "block_process_network",
        ResponseActionType::TerminateProcess => "terminate_process",
    }
}

fn alert_signature(alert: &Alert) -> String {
    format!(
        "{}:{}:{}:{}",
        alert.alert_type,
        alert.pid.unwrap_or_default(),
        alert.title.to_lowercase(),
        format!("{:?}", &alert.severity).to_lowercase()
    )
}

fn verdict_label(verdict: &crate::models::ThreatVerdict) -> String {
    match verdict {
        crate::models::ThreatVerdict::Benign => "benign".to_string(),
        crate::models::ThreatVerdict::LowRisk => "low_risk".to_string(),
        crate::models::ThreatVerdict::Suspicious => "suspicious".to_string(),
        crate::models::ThreatVerdict::LikelyMalicious => "likely_malicious".to_string(),
        crate::models::ThreatVerdict::ConfirmedMalicious => "confirmed_malicious".to_string(),
    }
}
