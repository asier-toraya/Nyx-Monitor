import { invoke } from "@tauri-apps/api/core";
import type {
  Alert,
  AppUsageEntry,
  CpuSpikeConfig,
  DetectionProfile,
  InstalledProgram,
  ProcessMetric,
  ProcessNode,
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
