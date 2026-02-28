use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Legitimate,
    Unknown,
    Suspicious,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ThreatVerdict {
    Benign,
    LowRisk,
    Suspicious,
    LikelyMalicious,
    ConfirmedMalicious,
}

impl Default for ThreatVerdict {
    fn default() -> Self {
        Self::Benign
    }
}

impl Default for RiskLevel {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    WindowsNative,
    Trusted,
    Unknown,
}

impl Default for TrustLevel {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SuspicionAssessment {
    pub level: RiskLevel,
    pub score: u8,
    pub reasons: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub exe_path: Option<String>,
    pub user: Option<String>,
    pub risk: RiskLevel,
    pub trust_level: TrustLevel,
    pub trust_label: Option<String>,
    pub children: Vec<ProcessNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessMetric {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub exe_path: Option<String>,
    pub user: Option<String>,
    pub cpu_pct: f32,
    pub gpu_pct: f32,
    pub memory_mb: f32,
    pub status: String,
    pub started_at: Option<String>,
    pub trust_level: TrustLevel,
    pub trust_label: Option<String>,
    pub suspicion: SuspicionAssessment,
    pub risk_factors: Vec<String>,
    pub risk_score: u8,
    pub verdict: ThreatVerdict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionProfile {
    Conservative,
    Balanced,
    Aggressive,
}

impl Default for DetectionProfile {
    fn default() -> Self {
        Self::Conservative
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuSpikeConfig {
    pub threshold_pct: f32,
    pub min_consecutive_samples: usize,
    pub deviation_ratio: f32,
}

impl Default for CpuSpikeConfig {
    fn default() -> Self {
        Self {
            threshold_pct: 90.0,
            min_consecutive_samples: 10,
            deviation_ratio: 1.8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledProgram {
    pub name: String,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_date: Option<String>,
    pub install_location: Option<String>,
    pub executable_path: Option<String>,
    pub trust_level: TrustLevel,
    pub trust_label: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StartupProcess {
    pub name: String,
    pub command: String,
    pub location: String,
    pub source: String,
    pub trust_level: TrustLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppUsageEntry {
    pub app_key: String,
    pub name: String,
    pub executable_path: Option<String>,
    pub launch_count: u64,
    pub max_cpu_pct: f32,
    pub last_pid: Option<u32>,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Warn,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertStatus {
    Active,
    Acknowledged,
    Deleted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub alert_type: String,
    pub severity: AlertSeverity,
    pub pid: Option<u32>,
    pub title: String,
    pub description: String,
    pub evidence: Vec<String>,
    pub timestamp: String,
    pub status: AlertStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KnownEntityKind {
    Process,
    Program,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownEntity {
    pub kind: KnownEntityKind,
    pub key: String,
    pub label: Option<String>,
    pub trust_level: Option<TrustLevel>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSeverity {
    Info,
    Warn,
    Critical,
}

impl Default for EventSeverity {
    fn default() -> Self {
        Self::Info
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub image_name: String,
    pub image_path: Option<String>,
    pub cmdline: Option<String>,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkEvidence {
    pub protocol: String,
    pub local_address: String,
    pub remote_address: String,
    pub state: Option<String>,
    pub pid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryEvidence {
    pub key_path: String,
    pub value_name: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub operation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventEnvelope {
    pub event_id: String,
    pub host_id: String,
    pub timestamp_utc: String,
    pub event_type: String,
    pub sensor: String,
    pub severity: EventSeverity,
    pub message: String,
    pub process: Option<ProcessIdentity>,
    pub network: Option<NetworkEvidence>,
    pub registry: Option<RegistryEvidence>,
    pub rule_hits: Vec<String>,
    pub risk_score: Option<u8>,
    pub verdict: Option<String>,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SensorHealth {
    pub sensor: String,
    pub status: String,
    pub last_success_utc: Option<String>,
    pub last_error: Option<String>,
    pub events_emitted: u64,
    pub last_latency_ms: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PerformanceStats {
    pub loop_last_ms: f32,
    pub loop_avg_ms: f32,
    pub loop_p95_ms: f32,
    pub total_events: u64,
    pub event_store_size: u64,
    pub tracked_processes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    Audit,
    Constrain,
}

impl Default for ResponseMode {
    fn default() -> Self {
        Self::Audit
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseActionType {
    SuspendProcess,
    BlockProcessNetwork,
    TerminateProcess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePolicy {
    pub mode: ResponseMode,
    pub auto_constrain_threshold: u8,
    pub safe_mode: bool,
    pub allow_terminate: bool,
    pub cooldown_seconds: u64,
}

impl ResponsePolicy {
    pub fn secure_default() -> Self {
        Self {
            mode: ResponseMode::Audit,
            auto_constrain_threshold: 95,
            safe_mode: true,
            allow_terminate: false,
            cooldown_seconds: 180,
        }
    }
}

impl Default for ResponsePolicy {
    fn default() -> Self {
        Self::secure_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseActionRecord {
    pub id: String,
    pub timestamp_utc: String,
    pub action_type: ResponseActionType,
    pub mode: ResponseMode,
    pub pid: u32,
    pub process_name: String,
    pub success: bool,
    pub automatic: bool,
    pub score: u8,
    pub verdict: ThreatVerdict,
    pub reason: String,
    pub details: String,
}
