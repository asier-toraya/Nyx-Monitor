import { invoke } from "@tauri-apps/api/core";
import type {
  Alert,
  AppUsageEntry,
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

const defaultPerformanceStats: PerformanceStats = {
  loop_last_ms: 0,
  loop_avg_ms: 0,
  loop_p95_ms: 0,
  total_events: 0,
  event_store_size: 0,
  tracked_processes: 0
};

const defaultResponsePolicy: ResponsePolicy = {
  mode: "audit",
  auto_constrain_threshold: 95,
  safe_mode: true,
  allow_terminate: false,
  cooldown_seconds: 180
};

function resolveFallback<T>(fallback: T | (() => T)): T {
  return typeof fallback === "function" ? (fallback as () => T)() : fallback;
}

async function invokeOrFallback<T>(
  command: string,
  fallback: T | (() => T),
  payload?: Record<string, unknown>
): Promise<T> {
  if (!isTauri) {
    return resolveFallback(fallback);
  }

  return invoke<T>(command, payload);
}

async function invokeOrSkip(command: string, payload?: Record<string, unknown>): Promise<void> {
  if (!isTauri) {
    return;
  }

  await invoke(command, payload);
}

export async function getProcessTree(): Promise<ProcessNode[]> {
  return invokeOrFallback("get_process_tree", []);
}

export async function getProcessMetrics(): Promise<ProcessMetric[]> {
  return invokeOrFallback("get_process_metrics", []);
}

export async function getInstalledPrograms(): Promise<InstalledProgram[]> {
  return invokeOrFallback("get_installed_programs", []);
}

export async function getStartupProcesses(): Promise<StartupProcess[]> {
  return invokeOrFallback("get_startup_processes", []);
}

export async function getAppUsageHistory(): Promise<AppUsageEntry[]> {
  return invokeOrFallback("get_app_usage_history", []);
}

export async function getActiveAlerts(): Promise<Alert[]> {
  return invokeOrFallback("get_active_alerts", []);
}

export async function getEventTimeline(payload?: {
  limit?: number;
  eventType?: string;
  sensor?: string;
  search?: string;
}): Promise<EventEnvelope[]> {
  return invokeOrFallback("get_event_timeline", [], {
    limit: payload?.limit,
    event_type: payload?.eventType,
    sensor: payload?.sensor,
    search: payload?.search
  });
}

export async function getSensorHealth(): Promise<SensorHealth[]> {
  return invokeOrFallback("get_sensor_health", []);
}

export async function getPerformanceStats(): Promise<PerformanceStats> {
  return invokeOrFallback("get_performance_stats", defaultPerformanceStats);
}

export async function getResponsePolicy(): Promise<ResponsePolicy> {
  return invokeOrFallback("get_response_policy", defaultResponsePolicy);
}

export async function setResponsePolicy(policy: ResponsePolicy): Promise<void> {
  await invokeOrSkip("set_response_policy", { policy });
}

export async function getResponseActions(limit = 200): Promise<ResponseActionRecord[]> {
  return invokeOrFallback("get_response_actions", [], { limit });
}

export async function runResponseAction(payload: {
  pid: number;
  actionType: ResponseActionType;
  reason?: string;
}): Promise<ResponseActionRecord> {
  return invokeOrFallback(
    "run_response_action",
    () => ({
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
    }),
    {
      pid: payload.pid,
      action_type: payload.actionType,
      reason: payload.reason
    }
  );
}

export async function deleteAlert(alertId: string): Promise<boolean> {
  return invokeOrFallback("delete_alert", false, { alert_id: alertId });
}

export async function deleteAllAlerts(): Promise<number> {
  return invokeOrFallback("delete_all_alerts", 0);
}

export async function setDetectionProfile(profile: DetectionProfile): Promise<void> {
  await invokeOrSkip("set_detection_profile", { profile });
}

export async function openPathInExplorer(path?: string): Promise<boolean> {
  if (!isTauri || !path) {
    return false;
  }
  return invokeOrFallback("open_path_in_explorer", false, { path });
}

export async function openProcessFolderByPid(pid: number): Promise<boolean> {
  return invokeOrFallback("open_process_folder_by_pid", false, { pid });
}

export async function addKnownProgram(payload: {
  executablePath?: string;
  installLocation?: string;
  name: string;
  label: string;
}): Promise<boolean> {
  return invokeOrFallback("add_known_program", false, {
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
  return invokeOrFallback("set_process_trust_override", false, {
    path: payload.path,
    name: payload.name,
    trust_level: payload.trustLevel,
    label: payload.label
  });
}

export async function openUrlInBrowser(url: string): Promise<boolean> {
  return invokeOrFallback("open_url_in_browser", false, { url });
}

export async function getFileSha256(path?: string): Promise<string | null> {
  if (!isTauri || !path) {
    return null;
  }
  return invokeOrFallback("get_file_sha256", null, { path });
}
