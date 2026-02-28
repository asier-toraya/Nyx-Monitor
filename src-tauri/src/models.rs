use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Legitimate,
    Unknown,
    Suspicious,
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
