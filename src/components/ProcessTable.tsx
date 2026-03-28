import { useMemo, useState } from "react";
import { useSearchQuery } from "../hooks/useSearchQuery";
import { buildVirusTotalSearchUrl } from "../lib/externalLinks";
import { formatDate, formatMemoryMb, formatPercent, riskLabel } from "../lib/format";
import { matchesSearchQuery } from "../lib/search";
import type { ProcessMetric, TrustLevel } from "../types";
import { DataPanel } from "./DataPanel";
import { TrustIndicator } from "./TrustIndicator";

export type RefreshSpeed = "very_low" | "low" | "normal" | "fast";

type ProcessFilter = "all" | TrustLevel;

interface ProcessTableProps {
  metrics: ProcessMetric[];
  paused: boolean;
  speed: RefreshSpeed;
  onTogglePause: () => void;
  onSpeedChange: (speed: RefreshSpeed) => void;
  onProcessClick: (process: ProcessMetric) => void;
  onOpenExternalUrl: (url: string) => Promise<void>;
}

const filters: { id: ProcessFilter; title: string }[] = [
  { id: "all", title: "All" },
  { id: "windows_native", title: "Windows Native" },
  { id: "trusted", title: "Trusted" },
  { id: "unknown", title: "Unclassified" }
];

const speedLabels: Record<RefreshSpeed, string> = {
  very_low: "Muy baja",
  low: "Baja",
  normal: "Normal",
  fast: "Rapida"
};

function trustSortOrder(level: TrustLevel): number {
  if (level === "unknown") {
    return 0;
  }
  if (level === "trusted") {
    return 1;
  }
  return 2;
}

export function ProcessTable({
  metrics,
  paused,
  speed,
  onTogglePause,
  onSpeedChange,
  onProcessClick,
  onOpenExternalUrl
}: ProcessTableProps) {
  const { query, setQuery, normalizedQuery } = useSearchQuery();
  const [activeFilter, setActiveFilter] = useState<ProcessFilter>("all");

  const rows = useMemo(() => {
    const searched = [...metrics].filter((item) =>
      matchesSearchQuery(normalizedQuery, item.name, item.exe_path, item.pid, item.ppid)
    );

    const trustFiltered =
      activeFilter === "all"
        ? searched
        : searched.filter((item) => item.trust_level === activeFilter);

    return trustFiltered.sort((a, b) => {
      const trustDiff = trustSortOrder(a.trust_level) - trustSortOrder(b.trust_level);
      if (trustDiff !== 0) {
        return trustDiff;
      }

      return b.cpu_pct - a.cpu_pct;
    });
  }, [metrics, normalizedQuery, activeFilter]);

  const counts = useMemo(() => {
    const result: Record<ProcessFilter, number> = {
      all: metrics.length,
      windows_native: 0,
      trusted: 0,
      unknown: 0
    };

    for (const item of metrics) {
      result[item.trust_level] += 1;
    }

    return result;
  }, [metrics]);

  return (
    <DataPanel
      title="Live Processes"
      subtitle={`${rows.length} visible rows`}
      className="process-panel"
      actions={
        <div className="process-controls">
          <button className="btn btn--small" onClick={onTogglePause}>
            {paused ? "Reanudar refresco" : "Pausar refresco"}
          </button>
          <label className="control-label">
            Velocidad
            <select
              value={speed}
              onChange={(event) => onSpeedChange(event.target.value as RefreshSpeed)}
            >
              {(Object.keys(speedLabels) as RefreshSpeed[]).map((item) => (
                <option key={item} value={item}>
                  {speedLabels[item]}
                </option>
              ))}
            </select>
          </label>
        </div>
      }
      toolbar={
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Buscar proceso por nombre, ruta, PID o PPID"
        />
      }
      filters={
        <div className="process-filters" role="tablist" aria-label="Filter process groups">
          {filters.map((filter) => (
            <button
              key={filter.id}
              className={`process-filter ${activeFilter === filter.id ? "process-filter--active" : ""}`}
              onClick={() => setActiveFilter(filter.id)}
            >
              <span>{filter.title}</span>
              <strong>{counts[filter.id]}</strong>
            </button>
          ))}
        </div>
      }
      tableWrapperClassName="process-table-wrapper"
    >
      <table className="data-table data-table--compact">
        <thead>
          <tr>
            <th>Process</th>
            <th>Running</th>
            <th>CPU Load</th>
            <th>GPU</th>
            <th>Memory</th>
            <th>Started</th>
            <th>Risk</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.pid} className="click-row" onClick={() => onProcessClick(row)}>
              <td>
                <div className="cell-primary with-actions">
                  <span>{row.name}</span>
                  {row.trust_level === "unknown" ? (
                    <button
                      className="vt-link"
                      onClick={async (event) => {
                        event.preventDefault();
                        event.stopPropagation();
                        await onOpenExternalUrl(buildVirusTotalSearchUrl(row.name));
                      }}
                      title="Buscar este proceso en VirusTotal"
                    >
                      VT
                    </button>
                  ) : null}
                </div>
                <div className="cell-secondary">
                  PID {row.pid}
                  {row.ppid ? ` | PPID ${row.ppid}` : ""}
                </div>
                <div className="cell-secondary">{row.exe_path ?? "-"}</div>
              </td>
              <td>
                <TrustIndicator level={row.trust_level} compact labelOverride={row.trust_label} />
                <div className="cell-secondary">{row.status}</div>
              </td>
              <td>
                <div className="metric-with-bar">
                  <span>{formatPercent(row.cpu_pct)}</span>
                  <div className="cpu-meter" aria-hidden>
                    <span
                      className="cpu-meter__fill"
                      style={{ width: `${Math.min(100, row.cpu_pct)}%` }}
                    />
                  </div>
                </div>
              </td>
              <td>{formatPercent(row.gpu_pct)}</td>
              <td>{formatMemoryMb(row.memory_mb)}</td>
              <td>{formatDate(row.started_at)}</td>
              <td>
                <span className={`risk-pill risk-pill--${row.suspicion.level}`}>
                  {riskLabel(row.suspicion.level)} ({row.risk_score}) - {row.verdict}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </DataPanel>
  );
}
