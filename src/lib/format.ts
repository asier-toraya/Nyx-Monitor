import type { AlertSeverity, RiskLevel, TrustLevel } from "../types";

export function formatPercent(value: number): string {
  return `${value.toFixed(1)}%`;
}

export function formatMemoryMb(value: number): string {
  if (!Number.isFinite(value)) {
    return "0 MB";
  }
  if (value >= 1024) {
    return `${(value / 1024).toFixed(2)} GB`;
  }
  return `${value.toFixed(1)} MB`;
}

export function formatDate(value?: string): string {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

export function riskLabel(level: RiskLevel): string {
  if (level === "legitimate") {
    return "Legit";
  }
  if (level === "unknown") {
    return "Unknown";
  }
  return "Suspicious";
}

export function severityLabel(level: AlertSeverity): string {
  if (level === "critical") {
    return "Critical";
  }
  if (level === "warn") {
    return "Warning";
  }
  return "Info";
}

export function trustLabel(level: TrustLevel): string {
  if (level === "windows_native") {
    return "Windows";
  }
  if (level === "trusted") {
    return "Known";
  }
  return "Unknown";
}
