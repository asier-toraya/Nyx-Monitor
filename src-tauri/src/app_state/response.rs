use chrono::Utc;

use crate::models::{EventEnvelope, ResponseActionRecord, ResponseActionType, ResponseMode, ResponsePolicy};
use crate::response_engine;

use super::RuntimeState;

impl RuntimeState {
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
    ) -> anyhow::Result<ResponseActionRecord> {
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

        if automatic
            && !self.is_action_allowed_by_cooldown(pid, &action_type, policy.cooldown_seconds)
        {
            return Err(anyhow::anyhow!(
                "automatic action skipped by cooldown guardrail"
            ));
        }

        let execution =
            response_engine::execute_action(&action_type, pid, metric.exe_path.as_deref());
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
            event_id: format!("response-action-{}-{}", pid, Utc::now().timestamp_millis()),
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
            process: Some(metric.identity()),
            network: None,
            registry: None,
            rule_hits: vec![reason_text.to_string()],
            risk_score: Some(metric.risk_score),
            verdict: Some(metric.verdict.as_str().to_string()),
            evidence_refs: vec![details],
        };
        let _ = self.push_event(event);

        Ok(record)
    }

    pub fn maybe_run_auto_response(
        &self,
        metric: &crate::models::ProcessMetric,
    ) -> Option<ResponseActionRecord> {
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
                Utc::now().signed_duration_since(*last).num_seconds() >= cooldown_seconds as i64
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
}

fn action_type_label(action_type: &ResponseActionType) -> &'static str {
    match action_type {
        ResponseActionType::SuspendProcess => "suspend_process",
        ResponseActionType::BlockProcessNetwork => "block_process_network",
        ResponseActionType::TerminateProcess => "terminate_process",
    }
}
