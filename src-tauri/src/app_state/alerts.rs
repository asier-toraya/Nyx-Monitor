use chrono::{DateTime, Utc};

use crate::models::{Alert, AlertStatus};

use super::RuntimeState;

impl RuntimeState {
    pub fn add_alert_if_new(&self, alert: Alert) -> anyhow::Result<bool> {
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

    pub fn delete_alert(&self, alert_id: &str) -> anyhow::Result<bool> {
        let mut store = self.inner.store.lock().expect("poisoned alert store lock");
        let deleted_alert = store
            .history()
            .into_iter()
            .find(|alert| alert.id == alert_id && alert.status == AlertStatus::Active);
        let deleted = store.delete(alert_id)?;
        drop(store);
        if deleted {
            if let Some(alert) = deleted_alert {
                self.mark_alert_dismissed(&alert);
            }
        }
        Ok(deleted)
    }

    pub fn delete_all_active_alerts(&self) -> anyhow::Result<usize> {
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

    pub fn active_alerts(&self) -> Vec<Alert> {
        self.inner
            .store
            .lock()
            .expect("poisoned alert store lock")
            .active_alerts()
    }

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

fn alert_signature(alert: &Alert) -> String {
    format!(
        "{}:{}:{}:{}",
        alert.alert_type,
        alert.pid.unwrap_or_default(),
        alert.title.to_lowercase(),
        format!("{:?}", &alert.severity).to_lowercase()
    )
}
