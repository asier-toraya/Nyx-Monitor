mod alerts;
mod known_entities;
mod response;
mod snapshot;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use crate::models::{
    AppUsageEntry, CpuSpikeConfig, DetectionProfile, EventEnvelope, InstalledProgram,
    PerformanceStats, ProcessMetric, ProcessNode, ResponsePolicy, SensorHealth, StartupProcess,
};
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
}

fn percentile(sorted_values: &[f32], percentile: f32) -> f32 {
    if sorted_values.is_empty() {
        return 0.0;
    }
    let rank = ((percentile / 100.0) * (sorted_values.len().saturating_sub(1) as f32)).round();
    let index = rank as usize;
    sorted_values.get(index).copied().unwrap_or(0.0)
}
