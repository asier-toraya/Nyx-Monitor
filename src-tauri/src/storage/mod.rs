use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};

use chrono::Utc;

use crate::models::{Alert, AlertStatus, KnownEntity, KnownEntityKind, TrustLevel};

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
