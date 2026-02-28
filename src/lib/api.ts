import { invoke } from "@tauri-apps/api/core";
import type {
  Alert,
  AppUsageEntry,
  CpuSpikeConfig,
  DetectionProfile,
  EventEnvelope,
  InstalledProgram,
  PerformanceStats,
  ResponseActionRecord,
  ResponseActionType,
  ResponsePolicy,
  ProcessMetric,
  ProcessNode,
  SensorHealth,
  TrustLevel,
  StartupProcess
} from "../types";

const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

async function invokeSafe<T>(command: string, payload?: Record<string, unknown>): Promise<T> {
  if (!isTauri) {
    throw new Error("Tauri runtime not available");
  }
  return invoke<T>(command, payload);
}

export async function getProcessTree(): Promise<ProcessNode[]> {
  if (!isTauri) {
    return [];
  }
  return invokeSafe("get_process_tree");
}

export async function getProcessMetrics(): Promise<ProcessMetric[]> {
  if (!isTauri) {
    return [];
  }
  return invokeSafe("get_process_metrics");
}

export async function getInstalledPrograms(): Promise<InstalledProgram[]> {
  if (!isTauri) {
    return [];
  }
  return invokeSafe("get_installed_programs");
}

export async function getStartupProcesses(): Promise<StartupProcess[]> {
  if (!isTauri) {
    return [];
  }
  return invokeSafe("get_startup_processes");
}

export async function getAppUsageHistory(): Promise<AppUsageEntry[]> {
  if (!isTauri) {
    return [];
  }
  return invokeSafe("get_app_usage_history");
}

export async function getActiveAlerts(): Promise<Alert[]> {
  if (!isTauri) {
    return [];
  }
  return invokeSafe("get_active_alerts");
}

export async function getAlertHistory(): Promise<Alert[]> {
  if (!isTauri) {
    return [];
  }
  return invokeSafe("get_alert_history");
}

export async function getEventTimeline(payload?: {
  limit?: number;
  eventType?: string;
  sensor?: string;
  search?: string;
}): Promise<EventEnvelope[]> {
  if (!isTauri) {
    return [];
  }
  return invokeSafe("get_event_timeline", {
    limit: payload?.limit,
    event_type: payload?.eventType,
    sensor: payload?.sensor,
    search: payload?.search
  });
}

export async function getSensorHealth(): Promise<SensorHealth[]> {
  if (!isTauri) {
    return [];
  }
  return invokeSafe("get_sensor_health");
}

export async function getPerformanceStats(): Promise<PerformanceStats> {
  if (!isTauri) {
    return {
      loop_last_ms: 0,
      loop_avg_ms: 0,
      loop_p95_ms: 0,
      total_events: 0,
      event_store_size: 0,
      tracked_processes: 0
    };
  }
  return invokeSafe("get_performance_stats");
}

export async function getResponsePolicy(): Promise<ResponsePolicy> {
  if (!isTauri) {
    return {
      mode: "audit",
      auto_constrain_threshold: 95,
      safe_mode: true,
      allow_terminate: false,
      cooldown_seconds: 180
    };
  }
  return invokeSafe("get_response_policy");
}

export async function setResponsePolicy(policy: ResponsePolicy): Promise<void> {
  if (!isTauri) {
    return;
  }
  await invokeSafe("set_response_policy", { policy });
}

export async function getResponseActions(limit = 200): Promise<ResponseActionRecord[]> {
  if (!isTauri) {
    return [];
  }
  return invokeSafe("get_response_actions", { limit });
}

export async function runResponseAction(payload: {
  pid: number;
  actionType: ResponseActionType;
  reason?: string;
}): Promise<ResponseActionRecord> {
  if (!isTauri) {
    return {
      id: `mock-${Date.now()}`,
      timestamp_utc: new Date().toISOString(),
      action_type: payload.actionType,
      mode: "audit",
      pid: payload.pid,
      process_name: "mock",
      success: false,
      automatic: false,
      score: 0,
      verdict: "low_risk",
      reason: payload.reason ?? "",
      details: "Tauri runtime not available"
    };
  }
  return invokeSafe("run_response_action", {
    pid: payload.pid,
    action_type: payload.actionType,
    reason: payload.reason
  });
}

export async function acknowledgeAlert(alertId: string): Promise<boolean> {
  if (!isTauri) {
    return false;
  }
  return invokeSafe("ack_alert", { alert_id: alertId });
}

export async function deleteAlert(alertId: string): Promise<boolean> {
  if (!isTauri) {
    return false;
  }
  return invokeSafe("delete_alert", { alert_id: alertId });
}

export async function deleteAllAlerts(): Promise<number> {
  if (!isTauri) {
    return 0;
  }
  return invokeSafe("delete_all_alerts");
}

export async function setDetectionProfile(profile: DetectionProfile): Promise<void> {
  if (!isTauri) {
    return;
  }
  await invokeSafe("set_detection_profile", { profile });
}

export async function setCpuSpikeThreshold(config: CpuSpikeConfig): Promise<void> {
  if (!isTauri) {
    return;
  }
  await invokeSafe("set_cpu_spike_threshold", { config });
}

export async function openPathInExplorer(path?: string): Promise<boolean> {
  if (!isTauri || !path) {
    return false;
  }
  return invokeSafe("open_path_in_explorer", { path });
}

export async function openProcessFolderByPid(pid: number): Promise<boolean> {
  if (!isTauri) {
    return false;
  }
  return invokeSafe("open_process_folder_by_pid", { pid });
}

export async function addKnownProcess(payload: {
  path?: string;
  name: string;
  label: string;
}): Promise<boolean> {
  if (!isTauri) {
    return false;
  }
  return invokeSafe("add_known_process", {
    path: payload.path,
    name: payload.name,
    label: payload.label
  });
}

export async function addKnownProgram(payload: {
  executablePath?: string;
  installLocation?: string;
  name: string;
  label: string;
}): Promise<boolean> {
  if (!isTauri) {
    return false;
  }
  return invokeSafe("add_known_program", {
    executable_path: payload.executablePath,
    install_location: payload.installLocation,
    name: payload.name,
    label: payload.label
  });
}

export async function setProcessTrustOverride(payload: {
  path?: string;
  name: string;
  trustLevel: TrustLevel;
  label?: string;
}): Promise<boolean> {
  if (!isTauri) {
    return false;
  }
  return invokeSafe("set_process_trust_override", {
    path: payload.path,
    name: payload.name,
    trust_level: payload.trustLevel,
    label: payload.label
  });
}

export async function openUrlInBrowser(url: string): Promise<boolean> {
  if (!isTauri) {
    return false;
  }
  return invokeSafe("open_url_in_browser", { url });
}

export async function getFileSha256(path?: string): Promise<string | null> {
  if (!isTauri || !path) {
    return null;
  }
  return invokeSafe("get_file_sha256", { path });
}
