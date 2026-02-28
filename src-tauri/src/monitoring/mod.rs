pub mod gpu_collector;
pub mod network_collector;
pub mod process_collector;
pub mod programs;
pub mod registry_collector;
pub mod startup;
pub mod trust;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;
use tauri::{AppHandle, Emitter};

use crate::app_state::RuntimeState;
use crate::detection;
use crate::models::{
    Alert, AlertSeverity, EventEnvelope, EventSeverity, NetworkEvidence, ProcessIdentity,
    ProcessMetric, RegistryEvidence, ThreatVerdict, TrustLevel,
};

const GPU_REFRESH_TICKS: u64 = 3;
const NETWORK_REFRESH_TICKS: u64 = 3;
const REGISTRY_REFRESH_TICKS: u64 = 5;
const INVENTORY_REFRESH_TICKS: u64 = 300;
const SIGNATURE_PROBE_BUDGET: usize = 16;
const CORRELATION_WINDOW_SECS: u64 = 300;

#[derive(Default)]
struct CorrelationState {
    recent_process_start: HashMap<u32, Instant>,
    recent_network_activity: HashMap<u32, Instant>,
    last_registry_change: Option<Instant>,
}

impl CorrelationState {
    fn mark_process_start(&mut self, pid: u32, now: Instant) {
        self.recent_process_start.insert(pid, now);
    }

    fn mark_network_activity(&mut self, pid: u32, now: Instant) {
        self.recent_network_activity.insert(pid, now);
    }

    fn mark_registry_change(&mut self, now: Instant) {
        self.last_registry_change = Some(now);
    }

    fn has_recent_process_start(&self, pid: u32, now: Instant) -> bool {
        self.recent_process_start
            .get(&pid)
            .map(|instant| now.duration_since(*instant).as_secs() <= CORRELATION_WINDOW_SECS)
            .unwrap_or(false)
    }

    fn has_recent_network_activity(&self, pid: u32, now: Instant) -> bool {
        self.recent_network_activity
            .get(&pid)
            .map(|instant| now.duration_since(*instant).as_secs() <= CORRELATION_WINDOW_SECS)
            .unwrap_or(false)
    }

    fn has_recent_registry_change(&self, now: Instant) -> bool {
        self.last_registry_change
            .map(|instant| now.duration_since(instant).as_secs() <= CORRELATION_WINDOW_SECS)
            .unwrap_or(false)
    }

    fn prune(&mut self, now: Instant) {
        self.recent_process_start.retain(|_, instant| {
            now.duration_since(*instant).as_secs() <= CORRELATION_WINDOW_SECS
        });
        self.recent_network_activity.retain(|_, instant| {
            now.duration_since(*instant).as_secs() <= CORRELATION_WINDOW_SECS
        });
        if let Some(last_change) = self.last_registry_change {
            if now.duration_since(last_change).as_secs() > CORRELATION_WINDOW_SECS {
                self.last_registry_change = None;
            }
        }
    }
}

pub fn start_background_tasks(app: AppHandle, state: RuntimeState) {
    refresh_installed_programs(&state);
    refresh_startup_processes(&state);

    tauri::async_runtime::spawn(async move {
        let mut gpu_cache: HashMap<u32, f32> = HashMap::new();
        let mut tick: u64 = 0;
        let mut previous_metrics: HashMap<u32, ProcessMetric> = HashMap::new();
        let mut previous_connections: HashSet<String> = HashSet::new();
        let mut previous_registry_values: HashMap<String, String> = HashMap::new();
        let mut correlation = CorrelationState::default();

        loop {
            let loop_started = Instant::now();
            correlation.prune(loop_started);
            let process_collect_started = Instant::now();
            let mut metrics = process_collector::collect_process_metrics();
            state.record_sensor_success("process", Some(elapsed_ms(process_collect_started.elapsed())));

            if tick % GPU_REFRESH_TICKS == 0 {
                gpu_cache = gpu_collector::collect_gpu_usage_by_pid();
            }

            let profile = state.profile();
            let parent_names: HashMap<u32, String> =
                metrics.iter().map(|m| (m.pid, m.name.to_lowercase())).collect();
            let mut live_pids = Vec::with_capacity(metrics.len());
            let mut signature_probes = 0usize;

            for metric in &mut metrics {
                if !previous_metrics.contains_key(&metric.pid) {
                    correlation.mark_process_start(metric.pid, loop_started);
                }
                live_pids.push(metric.pid);
                metric.gpu_pct = *gpu_cache.get(&metric.pid).unwrap_or(&0.0);

                let signed = if let Some(path) = metric.exe_path.as_ref() {
                    if let Some(cached) = state.get_cached_signature(path) {
                        Some(cached)
                    } else if signature_probes < SIGNATURE_PROBE_BUDGET {
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
                let assessment =
                    detection::assess_process(metric, parent_name, signed, cpu_spike, &profile);
                metric.trust_level =
                    trust::classify_process_trust(&metric.name, metric.exe_path.as_deref(), signed);
                metric.trust_label = None;
                if let Some((level, label)) = state.known_process_override(metric) {
                    metric.trust_level = level;
                    metric.trust_label = label;
                }
                let internal_process = is_internal_process(metric);
                if internal_process {
                    metric.trust_level = TrustLevel::Trusted;
                    if metric.trust_label.is_none() {
                        metric.trust_label = Some("Nyx Internal".to_string());
                    }
                }
                metric.suspicion = assessment.clone();
                let mut correlation_bonuses = Vec::new();
                let mut correlation_reasons = Vec::new();

                if correlation.has_recent_process_start(metric.pid, loop_started) {
                    correlation_bonuses.push(4);
                    correlation_reasons
                        .push("Process creation observed recently in correlation window".to_string());
                }
                if correlation.has_recent_network_activity(metric.pid, loop_started) {
                    correlation_bonuses.push(8);
                    correlation_reasons
                        .push("New outbound network activity correlated to this process".to_string());
                }
                if correlation.has_recent_registry_change(loop_started)
                    && metric.suspicion.score >= 45
                    && metric.trust_level == TrustLevel::Unknown
                {
                    correlation_bonuses.push(6);
                    correlation_reasons
                        .push("Critical registry persistence change observed recently".to_string());
                }

                metric.risk_score =
                    detection::compute_risk_score(metric.suspicion.score, &correlation_bonuses);
                metric.verdict = detection::classify_threat_verdict(
                    metric.risk_score,
                    &metric.suspicion.level,
                    &metric.trust_level,
                    correlation_reasons.len(),
                    internal_process,
                );

                let mut risk_factors = metric.suspicion.reasons.clone();
                for reason in &correlation_reasons {
                    if !risk_factors.iter().any(|existing| existing == reason) {
                        risk_factors.push(reason.clone());
                    }
                }
                if metric.trust_level == TrustLevel::Unknown {
                    risk_factors.push(
                        "Trust classification is unclassified (manual verification recommended)"
                            .to_string(),
                    );
                }
                if risk_factors.is_empty() {
                    risk_factors.push("No suspicious heuristics triggered".to_string());
                }
                metric.risk_factors = risk_factors;

                if !internal_process {
                    if let Some(alert) = detection::build_alert(metric, &assessment, cpu_spike) {
                        if state.add_alert_if_new(alert.clone()).unwrap_or(false) {
                            let _ = app.emit("alert_created", &alert);
                            emit_alert_event(&state, metric, &alert);
                        }
                    }
                    if let Some(correlated_alert) = detection::build_correlated_alert(
                        metric,
                        metric.risk_score,
                        &metric.verdict,
                        &correlation_reasons,
                    ) {
                        if state
                            .add_alert_if_new(correlated_alert.clone())
                            .unwrap_or(false)
                        {
                            let _ = app.emit("alert_created", &correlated_alert);
                            emit_alert_event(&state, metric, &correlated_alert);
                        }
                    }

                    if let Some(response_record) = state.maybe_run_auto_response(metric) {
                        let response_alert = Alert {
                            id: format!(
                                "response-action-{}-{}",
                                response_record.pid,
                                Utc::now().timestamp_millis()
                            ),
                            alert_type: "response_action".to_string(),
                            severity: if response_record.success {
                                AlertSeverity::Warn
                            } else {
                                AlertSeverity::Critical
                            },
                            pid: Some(response_record.pid),
                            title: format!(
                                "Automatic response executed on {}",
                                response_record.process_name
                            ),
                            description: response_record.details.clone(),
                            evidence: vec![
                                response_record.reason.clone(),
                                format!("Action: {:?}", response_record.action_type),
                                format!("Score: {}", response_record.score),
                            ],
                            timestamp: Utc::now().to_rfc3339(),
                            status: crate::models::AlertStatus::Active,
                        };
                        if state.add_alert_if_new(response_alert.clone()).unwrap_or(false) {
                            let _ = app.emit("alert_created", &response_alert);
                            emit_alert_event(&state, metric, &response_alert);
                        }
                    }
                }
            }

            if tick > 0 {
                emit_process_lifecycle_events(&state, &previous_metrics, &metrics);
            }

            let metrics_by_pid: HashMap<u32, &ProcessMetric> =
                metrics.iter().map(|metric| (metric.pid, metric)).collect();

            if tick % NETWORK_REFRESH_TICKS == 0 {
                let started = Instant::now();
                match network_collector::collect_connections() {
                    Ok(connections) => {
                        state.record_sensor_success("network", Some(elapsed_ms(started.elapsed())));
                        let network_pids = emit_network_events(
                            &state,
                            &metrics_by_pid,
                            &mut previous_connections,
                            connections,
                        );
                        for pid in network_pids {
                            correlation.mark_network_activity(pid, Instant::now());
                        }
                    }
                    Err(err) => state.record_sensor_error("network", &err),
                }
            }

            if tick % REGISTRY_REFRESH_TICKS == 0 {
                let started = Instant::now();
                match registry_collector::snapshot_critical_values() {
                    Ok(snapshot) => {
                        state.record_sensor_success("registry", Some(elapsed_ms(started.elapsed())));
                        if emit_registry_change_events(&state, &previous_registry_values, &snapshot) {
                            correlation.mark_registry_change(Instant::now());
                        }
                        previous_registry_values = snapshot;
                    }
                    Err(err) => state.record_sensor_error("registry", &err),
                }
            }

            state.prune_cpu_history(&live_pids);
            let tree = process_collector::build_process_tree(&metrics);
            state.update_snapshot(tree, metrics.clone());
            let _ = app.emit("process_snapshot_updated", &metrics);

            previous_metrics = metrics
                .into_iter()
                .map(|metric| (metric.pid, metric))
                .collect();

            if tick % INVENTORY_REFRESH_TICKS == 0 {
                refresh_installed_programs(&state);
                refresh_startup_processes(&state);
            }

            state.record_loop_timing(elapsed_ms(loop_started.elapsed()));
            tick = tick.saturating_add(1);
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
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

fn is_internal_process(metric: &ProcessMetric) -> bool {
    let name = metric.name.to_lowercase();
    if name.contains("p-control") || name.contains("nyx monitor") || name.contains("nyx-monitor") {
        return true;
    }
    metric
        .exe_path
        .as_ref()
        .map(|path| {
            let lower = path.to_lowercase();
            lower.contains("\\p-control\\")
                || lower.contains("\\nyx monitor\\")
                || lower.contains("\\nyx-monitor\\")
        })
        .unwrap_or(false)
}

fn emit_process_lifecycle_events(
    state: &RuntimeState,
    previous_metrics: &HashMap<u32, ProcessMetric>,
    current_metrics: &[ProcessMetric],
) {
    let current_by_pid: HashMap<u32, &ProcessMetric> = current_metrics
        .iter()
        .map(|metric| (metric.pid, metric))
        .collect();

    for metric in current_metrics {
        if previous_metrics.contains_key(&metric.pid) {
            continue;
        }
        let event = EventEnvelope {
            event_id: next_event_id("process", "process_started"),
            host_id: state.host_id(),
            timestamp_utc: Utc::now().to_rfc3339(),
            event_type: "process_started".to_string(),
            sensor: "process".to_string(),
            severity: EventSeverity::Info,
            message: format!("Process started: {} (PID {})", metric.name, metric.pid),
            process: Some(process_identity(metric)),
            network: None,
            registry: None,
            rule_hits: Vec::new(),
            risk_score: Some(metric.risk_score),
            verdict: Some(verdict_to_string(&metric.verdict)),
            evidence_refs: Vec::new(),
        };
        let _ = state.push_event(event);
    }

    for (pid, metric) in previous_metrics {
        if current_by_pid.contains_key(pid) {
            continue;
        }
        let event = EventEnvelope {
            event_id: next_event_id("process", "process_stopped"),
            host_id: state.host_id(),
            timestamp_utc: Utc::now().to_rfc3339(),
            event_type: "process_stopped".to_string(),
            sensor: "process".to_string(),
            severity: EventSeverity::Info,
            message: format!("Process stopped: {} (PID {})", metric.name, metric.pid),
            process: Some(process_identity(metric)),
            network: None,
            registry: None,
            rule_hits: Vec::new(),
            risk_score: Some(metric.risk_score),
            verdict: Some(verdict_to_string(&metric.verdict)),
            evidence_refs: Vec::new(),
        };
        let _ = state.push_event(event);
    }
}

fn emit_network_events(
    state: &RuntimeState,
    metrics_by_pid: &HashMap<u32, &ProcessMetric>,
    previous_connections: &mut HashSet<String>,
    connections: Vec<network_collector::NetworkConnection>,
) -> HashSet<u32> {
    let mut current_keys = HashSet::new();
    let mut emitted_pids = HashSet::new();

    for connection in connections {
        let key = connection.key();
        current_keys.insert(key.clone());
        if previous_connections.contains(&key) {
            continue;
        }
        if !should_emit_network_connection(&connection) {
            continue;
        }

        let process = metrics_by_pid
            .get(&connection.pid)
            .map(|metric| process_identity(metric));
        let event = EventEnvelope {
            event_id: next_event_id("network", "connection_opened"),
            host_id: state.host_id(),
            timestamp_utc: Utc::now().to_rfc3339(),
            event_type: "connection_opened".to_string(),
            sensor: "network".to_string(),
            severity: EventSeverity::Info,
            message: format!(
                "{} {} -> {} (PID {})",
                connection.protocol.to_uppercase(),
                connection.local_address,
                connection.remote_address,
                connection.pid
            ),
            process,
            network: Some(NetworkEvidence {
                protocol: connection.protocol,
                local_address: connection.local_address,
                remote_address: connection.remote_address,
                state: connection.state,
                pid: connection.pid,
            }),
            registry: None,
            rule_hits: Vec::new(),
            risk_score: None,
            verdict: None,
            evidence_refs: Vec::new(),
        };
        let _ = state.push_event(event);
        emitted_pids.insert(connection.pid);
    }

    *previous_connections = current_keys;
    emitted_pids
}

fn emit_registry_change_events(
    state: &RuntimeState,
    previous_snapshot: &HashMap<String, String>,
    current_snapshot: &HashMap<String, String>,
) -> bool {
    let mut changed = false;
    for (key, new_value) in current_snapshot {
        match previous_snapshot.get(key) {
            None => {
                let (key_path, value_name) = split_registry_composite_key(key);
                let event = EventEnvelope {
                    event_id: next_event_id("registry", "registry_value_added"),
                    host_id: state.host_id(),
                    timestamp_utc: Utc::now().to_rfc3339(),
                    event_type: "registry_value_added".to_string(),
                    sensor: "registry".to_string(),
                    severity: EventSeverity::Warn,
                    message: format!("Registry value added: {}", key),
                    process: None,
                    network: None,
                    registry: Some(RegistryEvidence {
                        key_path,
                        value_name,
                        old_value: None,
                        new_value: Some(new_value.clone()),
                        operation: "add".to_string(),
                    }),
                    rule_hits: vec!["registry_persistence_watch".to_string()],
                    risk_score: Some(35),
                    verdict: Some("low_risk".to_string()),
                    evidence_refs: Vec::new(),
                };
                let _ = state.push_event(event);
                changed = true;
            }
            Some(old_value) if old_value != new_value => {
                let (key_path, value_name) = split_registry_composite_key(key);
                let event = EventEnvelope {
                    event_id: next_event_id("registry", "registry_value_changed"),
                    host_id: state.host_id(),
                    timestamp_utc: Utc::now().to_rfc3339(),
                    event_type: "registry_value_changed".to_string(),
                    sensor: "registry".to_string(),
                    severity: EventSeverity::Warn,
                    message: format!("Registry value changed: {}", key),
                    process: None,
                    network: None,
                    registry: Some(RegistryEvidence {
                        key_path,
                        value_name,
                        old_value: Some(old_value.clone()),
                        new_value: Some(new_value.clone()),
                        operation: "update".to_string(),
                    }),
                    rule_hits: vec!["registry_persistence_watch".to_string()],
                    risk_score: Some(45),
                    verdict: Some("suspicious".to_string()),
                    evidence_refs: Vec::new(),
                };
                let _ = state.push_event(event);
                changed = true;
            }
            _ => {}
        }
    }

    for (key, old_value) in previous_snapshot {
        if current_snapshot.contains_key(key) {
            continue;
        }
        let (key_path, value_name) = split_registry_composite_key(key);
        let event = EventEnvelope {
            event_id: next_event_id("registry", "registry_value_removed"),
            host_id: state.host_id(),
            timestamp_utc: Utc::now().to_rfc3339(),
            event_type: "registry_value_removed".to_string(),
            sensor: "registry".to_string(),
            severity: EventSeverity::Warn,
            message: format!("Registry value removed: {}", key),
            process: None,
            network: None,
            registry: Some(RegistryEvidence {
                key_path,
                value_name,
                old_value: Some(old_value.clone()),
                new_value: None,
                operation: "remove".to_string(),
            }),
            rule_hits: vec!["registry_persistence_watch".to_string()],
            risk_score: Some(40),
            verdict: Some("low_risk".to_string()),
            evidence_refs: Vec::new(),
        };
        let _ = state.push_event(event);
        changed = true;
    }

    changed
}

fn emit_alert_event(state: &RuntimeState, metric: &ProcessMetric, alert: &Alert) {
    let event = EventEnvelope {
        event_id: next_event_id("detection", "alert_generated"),
        host_id: state.host_id(),
        timestamp_utc: Utc::now().to_rfc3339(),
        event_type: "alert_generated".to_string(),
        sensor: "detection".to_string(),
        severity: event_severity_from_alert(&alert.severity),
        message: format!("Alert generated: {}", alert.title),
        process: Some(process_identity(metric)),
        network: None,
        registry: None,
        rule_hits: alert.evidence.clone(),
        risk_score: Some(metric.risk_score),
        verdict: Some(verdict_to_string(&metric.verdict)),
        evidence_refs: Vec::new(),
    };
    let _ = state.push_event(event);
}

fn process_identity(metric: &ProcessMetric) -> ProcessIdentity {
    ProcessIdentity {
        pid: metric.pid,
        ppid: metric.ppid,
        image_name: metric.name.clone(),
        image_path: metric.exe_path.clone(),
        cmdline: None,
        user: metric.user.clone(),
    }
}

fn split_registry_composite_key(key: &str) -> (String, String) {
    if let Some((path, value_name)) = key.rsplit_once('\\') {
        return (path.to_string(), value_name.to_string());
    }
    (key.to_string(), String::new())
}

fn event_severity_from_alert(severity: &AlertSeverity) -> EventSeverity {
    match severity {
        AlertSeverity::Info => EventSeverity::Info,
        AlertSeverity::Warn => EventSeverity::Warn,
        AlertSeverity::Critical => EventSeverity::Critical,
    }
}

fn verdict_to_string(verdict: &ThreatVerdict) -> String {
    match verdict {
        ThreatVerdict::Benign => "benign".to_string(),
        ThreatVerdict::LowRisk => "low_risk".to_string(),
        ThreatVerdict::Suspicious => "suspicious".to_string(),
        ThreatVerdict::LikelyMalicious => "likely_malicious".to_string(),
        ThreatVerdict::ConfirmedMalicious => "confirmed_malicious".to_string(),
    }
}

fn should_emit_network_connection(connection: &network_collector::NetworkConnection) -> bool {
    if connection.protocol.eq_ignore_ascii_case("tcp")
        && connection
            .state
            .as_deref()
            .map(|value| value.eq_ignore_ascii_case("LISTENING"))
            .unwrap_or(false)
    {
        return false;
    }

    let remote = connection.remote_address.trim();
    !(remote.is_empty()
        || remote == "*:*"
        || remote.ends_with(":0")
        || remote.starts_with("0.0.0.0")
        || remote.starts_with("[::]:"))
}

fn elapsed_ms(duration: Duration) -> f32 {
    duration.as_secs_f32() * 1000.0
}

fn next_event_id(sensor: &str, event_type: &str) -> String {
    static EVENT_COUNTER: AtomicU64 = AtomicU64::new(1);
    format!(
        "{}-{}-{}-{}",
        sensor,
        event_type,
        Utc::now().timestamp_millis(),
        EVENT_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}
