export type RiskLevel = "legitimate" | "unknown" | "suspicious";
export type TrustLevel = "windows_native" | "trusted" | "unknown";
export type DetectionProfile = "conservative" | "balanced" | "aggressive";
export type AlertSeverity = "info" | "warn" | "critical";
export type AlertStatus = "active" | "acknowledged" | "deleted";

export interface SuspicionAssessment {
  level: RiskLevel;
  score: number;
  reasons: string[];
  confidence: number;
}

export interface ProcessNode {
  pid: number;
  ppid?: number;
  name: string;
  exe_path?: string;
  user?: string;
  risk: RiskLevel;
  trust_level: TrustLevel;
  trust_label?: string;
  children: ProcessNode[];
}

export interface ProcessMetric {
  pid: number;
  ppid?: number;
  name: string;
  exe_path?: string;
  user?: string;
  cpu_pct: number;
  gpu_pct: number;
  memory_mb: number;
  status: string;
  started_at?: string;
  trust_level: TrustLevel;
  trust_label?: string;
  suspicion: SuspicionAssessment;
}

export interface InstalledProgram {
  name: string;
  version?: string;
  publisher?: string;
  install_date?: string;
  install_location?: string;
  executable_path?: string;
  trust_level: TrustLevel;
  trust_label?: string;
  source: string;
}

export interface StartupProcess {
  name: string;
  command: string;
  location: string;
  source: string;
  trust_level: TrustLevel;
}

export interface AppUsageEntry {
  app_key: string;
  name: string;
  executable_path?: string;
  launch_count: number;
  max_cpu_pct: number;
  last_pid?: number;
  first_seen: string;
  last_seen: string;
}

export interface Alert {
  id: string;
  alert_type: string;
  severity: AlertSeverity;
  pid?: number;
  title: string;
  description: string;
  evidence: string[];
  timestamp: string;
  status: AlertStatus;
}

export interface CpuSpikeConfig {
  threshold_pct: number;
  min_consecutive_samples: number;
  deviation_ratio: number;
}
