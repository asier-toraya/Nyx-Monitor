use std::collections::HashSet;

use crate::models::{InstalledProgram, KnownEntity, KnownEntityKind, ProcessMetric, TrustLevel};
use crate::monitoring::{process_collector, trust};

use super::RuntimeState;

impl RuntimeState {
    pub fn set_process_trust_override(
        &self,
        path: Option<&str>,
        name: &str,
        trust_level: TrustLevel,
        label: Option<&str>,
    ) -> anyhow::Result<bool> {
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
    ) -> anyhow::Result<bool> {
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

    pub fn known_process_override(
        &self,
        metric: &ProcessMetric,
    ) -> Option<(TrustLevel, Option<String>)> {
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

    fn apply_process_override_to_snapshot(
        &self,
        keys: &[String],
        trust_level: &TrustLevel,
        label: Option<&str>,
    ) {
        let key_set: HashSet<String> = keys.iter().cloned().collect();
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

        let refreshed_tree = process_collector::build_process_tree(&metrics_lock);
        drop(metrics_lock);

        let mut tree_lock = self
            .inner
            .process_tree
            .write()
            .expect("poisoned process tree lock");
        *tree_lock = refreshed_tree;
    }
}

fn pick_latest_entity(
    current: Option<KnownEntity>,
    candidate: KnownEntity,
) -> Option<KnownEntity> {
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
