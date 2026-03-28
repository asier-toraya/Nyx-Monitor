use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::Utc;

use crate::app_state::RuntimeState;
use crate::models::{
    Alert, AlertSeverity, EventEnvelope, EventSeverity, NetworkEvidence, ProcessMetric,
    RegistryEvidence, ThreatVerdict,
};

use super::network_collector::NetworkConnection;

pub(super) fn emit_process_lifecycle_events(
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
            process: Some(metric.identity()),
            network: None,
            registry: None,
            rule_hits: Vec::new(),
            risk_score: Some(metric.risk_score),
            verdict: Some(metric.verdict.as_str().to_string()),
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
            process: Some(metric.identity()),
            network: None,
            registry: None,
            rule_hits: Vec::new(),
            risk_score: Some(metric.risk_score),
            verdict: Some(metric.verdict.as_str().to_string()),
            evidence_refs: Vec::new(),
        };
        let _ = state.push_event(event);
    }
}

pub(super) fn emit_network_events(
    state: &RuntimeState,
    metrics_by_pid: &HashMap<u32, &ProcessMetric>,
    previous_connections: &mut HashSet<String>,
    connections: Vec<NetworkConnection>,
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
            .map(|metric| metric.identity());
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

pub(super) fn emit_registry_change_events(
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
                    verdict: Some(ThreatVerdict::LowRisk.as_str().to_string()),
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
                    verdict: Some(ThreatVerdict::Suspicious.as_str().to_string()),
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
            verdict: Some(ThreatVerdict::LowRisk.as_str().to_string()),
            evidence_refs: Vec::new(),
        };
        let _ = state.push_event(event);
        changed = true;
    }

    changed
}

pub(super) fn emit_alert_event(state: &RuntimeState, metric: &ProcessMetric, alert: &Alert) {
    let event = EventEnvelope {
        event_id: next_event_id("detection", "alert_generated"),
        host_id: state.host_id(),
        timestamp_utc: Utc::now().to_rfc3339(),
        event_type: "alert_generated".to_string(),
        sensor: "detection".to_string(),
        severity: event_severity_from_alert(&alert.severity),
        message: format!("Alert generated: {}", alert.title),
        process: Some(metric.identity()),
        network: None,
        registry: None,
        rule_hits: alert.evidence.clone(),
        risk_score: Some(metric.risk_score),
        verdict: Some(metric.verdict.as_str().to_string()),
        evidence_refs: Vec::new(),
    };
    let _ = state.push_event(event);
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

fn should_emit_network_connection(connection: &NetworkConnection) -> bool {
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

#[cfg(test)]
mod tests {
    use super::{should_emit_network_connection, split_registry_composite_key};
    use crate::monitoring::network_collector::NetworkConnection;

    #[test]
    fn split_registry_composite_key_extracts_value_name() {
        let (key_path, value_name) =
            split_registry_composite_key("HKCU\\Software\\Nyx\\Run\\Updater");

        assert_eq!(key_path, "HKCU\\Software\\Nyx\\Run");
        assert_eq!(value_name, "Updater");
    }

    #[test]
    fn split_registry_composite_key_handles_single_segment() {
        let (key_path, value_name) = split_registry_composite_key("RunOnce");

        assert_eq!(key_path, "RunOnce");
        assert_eq!(value_name, "");
    }

    #[test]
    fn should_emit_network_connection_skips_listening_tcp_rows() {
        let connection = NetworkConnection {
            protocol: "tcp".to_string(),
            local_address: "127.0.0.1:8080".to_string(),
            remote_address: "0.0.0.0:0".to_string(),
            state: Some("LISTENING".to_string()),
            pid: 1234,
        };

        assert!(!should_emit_network_connection(&connection));
    }

    #[test]
    fn should_emit_network_connection_keeps_real_outbound_rows() {
        let connection = NetworkConnection {
            protocol: "tcp".to_string(),
            local_address: "192.168.1.10:51515".to_string(),
            remote_address: "8.8.8.8:443".to_string(),
            state: Some("ESTABLISHED".to_string()),
            pid: 1234,
        };

        assert!(should_emit_network_connection(&connection));
    }
}
