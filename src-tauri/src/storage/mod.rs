use std::cmp::min;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

use chrono::Utc;

use crate::models::{
    Alert, AlertStatus, EventEnvelope, KnownEntity, KnownEntityKind, ResponseActionRecord, TrustLevel,
};

#[derive(Debug)]
pub struct AlertStore {
    path: PathBuf,
    alerts: Vec<Alert>,
}

impl AlertStore {
    pub fn load(path: PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                path,
                alerts: Vec::new(),
            });
        }

        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read alert store from {}", path.display()))?;
        let alerts: Vec<Alert> = serde_json::from_str(&raw).unwrap_or_default();

        Ok(Self { path, alerts })
    }

    pub fn push(&mut self, alert: Alert) -> Result<()> {
        self.alerts.push(alert);
        self.persist()
    }

    pub fn acknowledge(&mut self, alert_id: &str) -> Result<bool> {
        let mut updated = false;
        for alert in &mut self.alerts {
            if alert.id == alert_id && alert.status != AlertStatus::Acknowledged {
                alert.status = AlertStatus::Acknowledged;
                updated = true;
                break;
            }
        }

        if updated {
            self.persist()?;
        }
        Ok(updated)
    }

    pub fn active_alerts(&self) -> Vec<Alert> {
        let mut list: Vec<Alert> = self
            .alerts
            .iter()
            .filter(|a| a.status == AlertStatus::Active)
            .cloned()
            .collect();
        list.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        list
    }

    pub fn history(&self) -> Vec<Alert> {
        let mut list = self.alerts.clone();
        list.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        list
    }

    pub fn delete(&mut self, alert_id: &str) -> Result<bool> {
        let before = self.alerts.len();
        self.alerts.retain(|alert| alert.id != alert_id);
        let changed = self.alerts.len() != before;
        if changed {
            self.persist()?;
        }
        Ok(changed)
    }

    pub fn delete_all_active(&mut self) -> Result<usize> {
        let before = self.alerts.len();
        self.alerts.retain(|alert| alert.status != AlertStatus::Active);
        let deleted = before.saturating_sub(self.alerts.len());
        if deleted > 0 {
            self.persist()?;
        }
        Ok(deleted)
    }

    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed creating alert store directory {}", parent.display())
            })?;
        }

        let payload =
            serde_json::to_string_pretty(&self.alerts).context("failed serializing alert data")?;
        fs::write(&self.path, payload).with_context(|| {
            format!("failed writing alert store to {}", self.path.display())
        })?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct KnownEntityStore {
    path: PathBuf,
    entities: Vec<KnownEntity>,
}

impl KnownEntityStore {
    pub fn load(path: PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                path,
                entities: Vec::new(),
            });
        }

        let raw = fs::read_to_string(&path)
            .with_context(|| format!("failed to read known entity store {}", path.display()))?;
        let entities: Vec<KnownEntity> = serde_json::from_str(&raw).unwrap_or_default();

        Ok(Self { path, entities })
    }

    pub fn upsert(
        &mut self,
        kind: KnownEntityKind,
        key: String,
        trust_level: Option<TrustLevel>,
        label: Option<String>,
    ) -> Result<bool> {
        let mut changed = false;
        if let Some(existing) = self
            .entities
            .iter_mut()
            .find(|item| item.kind == kind && item.key == key)
        {
            if existing.label != label || existing.trust_level != trust_level {
                existing.label = label;
                existing.trust_level = trust_level;
                existing.created_at = Utc::now().to_rfc3339();
                changed = true;
            }
        } else {
            self.entities.push(KnownEntity {
                kind,
                key,
                label,
                trust_level,
                created_at: Utc::now().to_rfc3339(),
            });
            changed = true;
        }

        if changed {
            self.persist()?;
        }
        Ok(changed)
    }

    pub fn sync_process_aliases_by_name(
        &mut self,
        normalized_name: &str,
        trust_level: Option<TrustLevel>,
        label: Option<String>,
    ) -> Result<bool> {
        let mut changed = false;
        for entity in &mut self.entities {
            if entity.kind != KnownEntityKind::Process {
                continue;
            }
            let matches = entity.key == normalized_name
                || key_basename(&entity.key)
                    .map(|file_name| file_name == normalized_name)
                    .unwrap_or(false);
            if !matches {
                continue;
            }
            if entity.trust_level != trust_level || entity.label != label {
                entity.trust_level = trust_level.clone();
                entity.label = label.clone();
                entity.created_at = Utc::now().to_rfc3339();
                changed = true;
            }
        }

        if changed {
            self.persist()?;
        }
        Ok(changed)
    }

    pub fn find(&self, kind: KnownEntityKind, key: &str) -> Option<KnownEntity> {
        self.entities
            .iter()
            .find(|item| item.kind == kind && item.key == key)
            .cloned()
    }

    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed creating known entity store directory {}", parent.display())
            })?;
        }

        let payload = serde_json::to_string_pretty(&self.entities)
            .context("failed serializing known entities")?;
        fs::write(&self.path, payload).with_context(|| {
            format!(
                "failed writing known entity store to {}",
                self.path.display()
            )
        })?;
        Ok(())
    }
}

fn key_basename(key: &str) -> Option<&str> {
    key.rsplit('\\').next().filter(|part| !part.is_empty())
}

#[derive(Debug)]
pub struct EventStore {
    path: PathBuf,
    max_events: usize,
}

#[derive(Debug)]
pub struct ResponseActionStore {
    path: PathBuf,
    actions: Vec<ResponseActionRecord>,
    max_actions: usize,
}

impl ResponseActionStore {
    pub fn load(path: PathBuf) -> Result<Self> {
        if !path.exists() {
            return Ok(Self {
                path,
                actions: Vec::new(),
                max_actions: 5_000,
            });
        }

        let raw = fs::read_to_string(&path).with_context(|| {
            format!(
                "failed to read response action store from {}",
                path.display()
            )
        })?;
        let actions: Vec<ResponseActionRecord> = serde_json::from_str(&raw).unwrap_or_default();

        Ok(Self {
            path,
            actions,
            max_actions: 5_000,
        })
    }

    pub fn push(&mut self, action: ResponseActionRecord) -> Result<()> {
        self.actions.push(action);
        if self.actions.len() > self.max_actions {
            let overflow = self.actions.len().saturating_sub(self.max_actions);
            self.actions.drain(0..overflow);
        }
        self.persist()
    }

    pub fn list_recent(&self, limit: usize) -> Vec<ResponseActionRecord> {
        let mut list = self.actions.clone();
        list.sort_by(|a, b| b.timestamp_utc.cmp(&a.timestamp_utc));
        list.into_iter().take(limit).collect()
    }

    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed creating response action store directory {}",
                    parent.display()
                )
            })?;
        }

        let payload = serde_json::to_string_pretty(&self.actions)
            .context("failed serializing response action data")?;
        fs::write(&self.path, payload).with_context(|| {
            format!(
                "failed writing response action store to {}",
                self.path.display()
            )
        })?;
        Ok(())
    }
}

impl EventStore {
    pub fn load(path: PathBuf) -> Result<Self> {
        let store = Self {
            path,
            max_events: 50_000,
        };
        store.init()?;
        Ok(store)
    }

    pub fn insert_event(&self, event: &EventEnvelope) -> Result<()> {
        let payload =
            serde_json::to_string(event).context("failed serializing event payload for storage")?;
        let conn = self.open_connection()?;
        conn.execute(
            "INSERT OR REPLACE INTO events (
                event_id, timestamp_utc, event_type, sensor, severity, payload
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                event.event_id,
                event.timestamp_utc,
                event.event_type,
                event.sensor,
                format!("{:?}", event.severity).to_lowercase(),
                payload
            ],
        )
        .context("failed inserting event into sqlite store")?;
        self.prune_if_needed(&conn)?;
        Ok(())
    }

    pub fn list_events(
        &self,
        limit: usize,
        event_type: Option<&str>,
        sensor: Option<&str>,
        search: Option<&str>,
    ) -> Result<Vec<EventEnvelope>> {
        let conn = self.open_connection()?;
        let fetch_limit = min(limit.saturating_mul(5).max(200), 5_000) as i64;
        let mut stmt = conn
            .prepare("SELECT payload FROM events ORDER BY timestamp_utc DESC LIMIT ?1")
            .context("failed preparing event list statement")?;
        let rows = stmt
            .query_map(params![fetch_limit], |row| row.get::<_, String>(0))
            .context("failed querying event payload rows")?;

        let event_type_filter = event_type
            .map(|value| value.trim().to_lowercase())
            .filter(|value| !value.is_empty());
        let sensor_filter = sensor
            .map(|value| value.trim().to_lowercase())
            .filter(|value| !value.is_empty());
        let search_filter = search
            .map(|value| value.trim().to_lowercase())
            .filter(|value| !value.is_empty());

        let mut output = Vec::new();
        for row in rows {
            let raw = match row {
                Ok(value) => value,
                Err(_) => continue,
            };
            let event: EventEnvelope = match serde_json::from_str(&raw) {
                Ok(value) => value,
                Err(_) => continue,
            };

            if let Some(filter) = event_type_filter.as_deref() {
                if event.event_type.to_lowercase() != filter {
                    continue;
                }
            }
            if let Some(filter) = sensor_filter.as_deref() {
                if event.sensor.to_lowercase() != filter {
                    continue;
                }
            }
            if let Some(filter) = search_filter.as_deref() {
                let in_message = event.message.to_lowercase().contains(filter);
                let in_process = event
                    .process
                    .as_ref()
                    .map(|proc| {
                        proc.image_name.to_lowercase().contains(filter)
                            || proc
                                .image_path
                                .as_deref()
                                .unwrap_or_default()
                                .to_lowercase()
                                .contains(filter)
                    })
                    .unwrap_or(false);
                if !in_message && !in_process {
                    continue;
                }
            }

            output.push(event);
            if output.len() >= limit {
                break;
            }
        }

        Ok(output)
    }

    pub fn total_events(&self) -> Result<u64> {
        let conn = self.open_connection()?;
        let total: i64 = conn
            .query_row("SELECT COUNT(1) FROM events", [], |row| row.get(0))
            .context("failed reading event count from sqlite store")?;
        Ok(total.max(0) as u64)
    }

    fn init(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed creating event store directory {}", parent.display())
            })?;
        }

        let conn = self.open_connection()?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                timestamp_utc TEXT NOT NULL,
                event_type TEXT NOT NULL,
                sensor TEXT NOT NULL,
                severity TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp_utc DESC);
            CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_sensor ON events(sensor);
            ",
        )
        .context("failed initializing sqlite event store schema")?;
        Ok(())
    }

    fn open_connection(&self) -> Result<Connection> {
        Connection::open(&self.path)
            .with_context(|| format!("failed opening sqlite event store {}", self.path.display()))
    }

    fn prune_if_needed(&self, conn: &Connection) -> Result<()> {
        let total: i64 = conn
            .query_row("SELECT COUNT(1) FROM events", [], |row| row.get(0))
            .context("failed counting events for pruning")?;
        if total <= self.max_events as i64 {
            return Ok(());
        }

        let to_delete = total - self.max_events as i64;
        conn.execute(
            "DELETE FROM events WHERE event_id IN (
                SELECT event_id FROM events
                ORDER BY timestamp_utc ASC
                LIMIT ?1
            )",
            params![to_delete],
        )
        .context("failed pruning old events from sqlite store")?;
        Ok(())
    }
}
