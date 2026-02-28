export type RiskLevel = "legitimate" | "unknown" | "suspicious";
export type TrustLevel = "windows_native" | "trusted" | "unknown";
export type ThreatVerdict =
  | "benign"
  | "low_risk"
  | "suspicious"
  | "likely_malicious"
  | "confirmed_malicious";
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
  risk_factors: string[];
  risk_score: number;
  verdict: ThreatVerdict;
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

export type EventSeverity = "info" | "warn" | "critical";

export interface ProcessIdentity {
  pid: number;
  ppid?: number;
  image_name: string;
  image_path?: string;
  cmdline?: string;
  user?: string;
}

export interface NetworkEvidence {
  protocol: string;
  local_address: string;
  remote_address: string;
  state?: string;
  pid: number;
}

export interface RegistryEvidence {
  key_path: string;
  value_name: string;
  old_value?: string;
  new_value?: string;
  operation: string;
}

export interface EventEnvelope {
  event_id: string;
  host_id: string;
  timestamp_utc: string;
  event_type: string;
  sensor: string;
  severity: EventSeverity;
  message: string;
  process?: ProcessIdentity;
  network?: NetworkEvidence;
  registry?: RegistryEvidence;
  rule_hits: string[];
  risk_score?: number;
  verdict?: string;
  evidence_refs: string[];
}

export interface SensorHealth {
  sensor: string;
  status: string;
  last_success_utc?: string;
  last_error?: string;
  events_emitted: number;
  last_latency_ms?: number;
}

export interface PerformanceStats {
  loop_last_ms: number;
  loop_avg_ms: number;
  loop_p95_ms: number;
  total_events: number;
  event_store_size: number;
  tracked_processes: number;
}

export type ResponseMode = "audit" | "constrain";
export type ResponseActionType =
  | "suspend_process"
  | "block_process_network"
  | "terminate_process";

export interface ResponsePolicy {
  mode: ResponseMode;
  auto_constrain_threshold: number;
  safe_mode: boolean;
  allow_terminate: boolean;
  cooldown_seconds: number;
}

export interface ResponseActionRecord {
  id: string;
  timestamp_utc: string;
  action_type: ResponseActionType;
  mode: ResponseMode;
  pid: number;
  process_name: string;
  success: boolean;
  automatic: boolean;
  score: number;
  verdict: ThreatVerdict;
  reason: string;
  details: string;
}
