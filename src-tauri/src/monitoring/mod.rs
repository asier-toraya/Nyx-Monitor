mod events;

pub mod gpu_collector;
pub mod network_collector;
pub mod process_collector;
pub mod programs;
pub mod registry_collector;
pub mod startup;
pub mod trust;

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use chrono::Utc;
use tauri::{AppHandle, Emitter};

use crate::app_state::RuntimeState;
use crate::detection;
use crate::models::{
    Alert, AlertSeverity, AlertStatus, ProcessMetric, ResponseActionRecord,
    SuspicionAssessment, TrustLevel,
};

use self::events::{
    emit_alert_event, emit_network_events, emit_process_lifecycle_events,
    emit_registry_change_events,
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

struct CorrelationOutcome {
    bonuses: Vec<u8>,
    reasons: Vec<String>,
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
            if tick % GPU_REFRESH_TICKS == 0 {
                gpu_cache = gpu_collector::collect_gpu_usage_by_pid();
            }

            let mut metrics = collect_process_metrics(&state, &gpu_cache);
            let live_pids = enrich_metrics_and_emit_alerts(
                &app,
                &state,
                &previous_metrics,
                &mut metrics,
                &mut correlation,
                loop_started,
            );

            if tick > 0 {
                emit_process_lifecycle_events(&state, &previous_metrics, &metrics);
            }

            let metrics_by_pid: HashMap<u32, &ProcessMetric> =
                metrics.iter().map(|metric| (metric.pid, metric)).collect();

            refresh_network_activity(
                &state,
                &metrics_by_pid,
                &mut previous_connections,
                &mut correlation,
                tick,
            );
            refresh_registry_activity(
                &state,
                &mut previous_registry_values,
                &mut correlation,
                tick,
            );

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

fn collect_process_metrics(state: &RuntimeState, gpu_cache: &HashMap<u32, f32>) -> Vec<ProcessMetric> {
    let process_collect_started = Instant::now();
    let mut metrics = process_collector::collect_process_metrics();
    state.record_sensor_success("process", Some(elapsed_ms(process_collect_started.elapsed())));

    for metric in &mut metrics {
        metric.gpu_pct = *gpu_cache.get(&metric.pid).unwrap_or(&0.0);
    }

    metrics
}

fn enrich_metrics_and_emit_alerts(
    app: &AppHandle,
    state: &RuntimeState,
    previous_metrics: &HashMap<u32, ProcessMetric>,
    metrics: &mut [ProcessMetric],
    correlation: &mut CorrelationState,
    loop_started: Instant,
) -> Vec<u32> {
    let profile = state.profile();
    let parent_names: HashMap<u32, String> =
        metrics.iter().map(|metric| (metric.pid, metric.name.to_lowercase())).collect();
    let mut live_pids = Vec::with_capacity(metrics.len());
    let mut signature_probes = 0usize;

    for metric in metrics {
        if !previous_metrics.contains_key(&metric.pid) {
            correlation.mark_process_start(metric.pid, loop_started);
        }
        live_pids.push(metric.pid);

        let signed =
            resolve_binary_signature(state, metric.exe_path.as_deref(), &mut signature_probes);
        let cpu_spike = state.update_cpu_and_check_spike(metric.pid, metric.cpu_pct);
        let parent_name = metric
            .ppid
            .and_then(|ppid| parent_names.get(&ppid))
            .map(String::as_str);
        let assessment = detection::assess_process(metric, parent_name, signed, cpu_spike, &profile);
        let internal_process = apply_metric_trust(state, metric, signed);
        let correlation_outcome =
            build_correlation_outcome(correlation, metric, &assessment, loop_started);

        update_metric_assessment(metric, &assessment, &correlation_outcome, internal_process);

        if !internal_process {
            emit_metric_alerts(
                app,
                state,
                metric,
                &assessment,
                cpu_spike,
                &correlation_outcome.reasons,
            );
        }
    }

    live_pids
}

fn resolve_binary_signature(
    state: &RuntimeState,
    exe_path: Option<&str>,
    signature_probes: &mut usize,
) -> Option<bool> {
    let path = exe_path?;

    if let Some(cached) = state.get_cached_signature(path) {
        return Some(cached);
    }
    if *signature_probes >= SIGNATURE_PROBE_BUDGET {
        return None;
    }

    *signature_probes = signature_probes.saturating_add(1);
    let discovered = process_collector::is_binary_signed(path);
    state.put_cached_signature(path.to_string(), discovered);
    Some(discovered)
}

fn apply_metric_trust(state: &RuntimeState, metric: &mut ProcessMetric, signed: Option<bool>) -> bool {
    metric.trust_level = trust::classify_process_trust(&metric.name, metric.exe_path.as_deref(), signed);
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

    internal_process
}

fn build_correlation_outcome(
    correlation: &CorrelationState,
    metric: &ProcessMetric,
    assessment: &SuspicionAssessment,
    loop_started: Instant,
) -> CorrelationOutcome {
    let mut bonuses = Vec::new();
    let mut reasons = Vec::new();

    if correlation.has_recent_process_start(metric.pid, loop_started) {
        bonuses.push(4);
        reasons.push("Process creation observed recently in correlation window".to_string());
    }
    if correlation.has_recent_network_activity(metric.pid, loop_started) {
        bonuses.push(8);
        reasons.push("New outbound network activity correlated to this process".to_string());
    }
    if correlation.has_recent_registry_change(loop_started)
        && assessment.score >= 45
        && metric.trust_level == TrustLevel::Unknown
    {
        bonuses.push(6);
        reasons.push("Critical registry persistence change observed recently".to_string());
    }

    CorrelationOutcome { bonuses, reasons }
}

fn update_metric_assessment(
    metric: &mut ProcessMetric,
    assessment: &SuspicionAssessment,
    correlation_outcome: &CorrelationOutcome,
    internal_process: bool,
) {
    metric.suspicion = assessment.clone();
    metric.risk_score =
        detection::compute_risk_score(metric.suspicion.score, &correlation_outcome.bonuses);
    metric.verdict = detection::classify_threat_verdict(
        metric.risk_score,
        &metric.suspicion.level,
        &metric.trust_level,
        correlation_outcome.reasons.len(),
        internal_process,
    );

    let mut risk_factors = metric.suspicion.reasons.clone();
    for reason in &correlation_outcome.reasons {
        if !risk_factors.iter().any(|existing| existing == reason) {
            risk_factors.push(reason.clone());
        }
    }
    if metric.trust_level == TrustLevel::Unknown {
        risk_factors
            .push("Trust classification is unclassified (manual verification recommended)".to_string());
    }
    if risk_factors.is_empty() {
        risk_factors.push("No suspicious heuristics triggered".to_string());
    }
    metric.risk_factors = risk_factors;
}

fn emit_metric_alerts(
    app: &AppHandle,
    state: &RuntimeState,
    metric: &ProcessMetric,
    assessment: &SuspicionAssessment,
    cpu_spike: bool,
    correlation_reasons: &[String],
) {
    if let Some(alert) = detection::build_alert(metric, assessment, cpu_spike) {
        emit_new_alert(app, state, metric, alert);
    }

    if let Some(correlated_alert) = detection::build_correlated_alert(
        metric,
        metric.risk_score,
        &metric.verdict,
        correlation_reasons,
    ) {
        emit_new_alert(app, state, metric, correlated_alert);
    }

    if let Some(response_record) = state.maybe_run_auto_response(metric) {
        emit_new_alert(app, state, metric, build_response_action_alert(&response_record));
    }
}

fn emit_new_alert(app: &AppHandle, state: &RuntimeState, metric: &ProcessMetric, alert: Alert) {
    if state.add_alert_if_new(alert.clone()).unwrap_or(false) {
        let _ = app.emit("alert_created", &alert);
        emit_alert_event(state, metric, &alert);
    }
}

fn build_response_action_alert(response_record: &ResponseActionRecord) -> Alert {
    Alert {
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
        status: AlertStatus::Active,
    }
}

fn refresh_network_activity(
    state: &RuntimeState,
    metrics_by_pid: &HashMap<u32, &ProcessMetric>,
    previous_connections: &mut HashSet<String>,
    correlation: &mut CorrelationState,
    tick: u64,
) {
    if tick % NETWORK_REFRESH_TICKS != 0 {
        return;
    }

    let started = Instant::now();
    match network_collector::collect_connections() {
        Ok(connections) => {
            state.record_sensor_success("network", Some(elapsed_ms(started.elapsed())));
            let network_pids =
                emit_network_events(state, metrics_by_pid, previous_connections, connections);
            for pid in network_pids {
                correlation.mark_network_activity(pid, Instant::now());
            }
        }
        Err(err) => state.record_sensor_error("network", &err),
    }
}

fn refresh_registry_activity(
    state: &RuntimeState,
    previous_registry_values: &mut HashMap<String, String>,
    correlation: &mut CorrelationState,
    tick: u64,
) {
    if tick % REGISTRY_REFRESH_TICKS != 0 {
        return;
    }

    let started = Instant::now();
    match registry_collector::snapshot_critical_values() {
        Ok(snapshot) => {
            state.record_sensor_success("registry", Some(elapsed_ms(started.elapsed())));
            if emit_registry_change_events(state, previous_registry_values, &snapshot) {
                correlation.mark_registry_change(Instant::now());
            }
            *previous_registry_values = snapshot;
        }
        Err(err) => state.record_sensor_error("registry", &err),
    }
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

fn elapsed_ms(duration: Duration) -> f32 {
    duration.as_secs_f32() * 1000.0
}
