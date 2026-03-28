import { useMemo } from "react";
import { formatDate, formatMemoryMb, formatPercent } from "../lib/format";
import { useSearchQuery } from "../hooks/useSearchQuery";
import { matchesSearchQuery } from "../lib/search";
import type { ProcessMetric } from "../types";
import { DataPanel } from "./DataPanel";

interface ThreatsTableProps {
  metrics: ProcessMetric[];
  onProcessClick: (process: ProcessMetric) => void;
}

export function ThreatsTable({ metrics, onProcessClick }: ThreatsTableProps) {
  const { query, setQuery, normalizedQuery } = useSearchQuery();

  const rows = useMemo(() => {
    return metrics
      .filter((item) => item.suspicion.level !== "legitimate")
      .filter((item) => matchesSearchQuery(normalizedQuery, item.name, item.exe_path, item.pid))
      .sort((a, b) => {
        if (b.risk_score !== a.risk_score) {
          return b.risk_score - a.risk_score;
        }
        if (b.suspicion.score !== a.suspicion.score) {
          return b.suspicion.score - a.suspicion.score;
        }
        return b.cpu_pct - a.cpu_pct;
      });
  }, [metrics, normalizedQuery]);

  return (
    <DataPanel
      title="Threat Surface"
      subtitle={`${rows.length} processes under review`}
      toolbar={
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Filtrar amenazas por nombre, ruta o PID"
        />
      }
    >
      <table className="data-table">
        <thead>
          <tr>
            <th>Proceso</th>
            <th>CPU</th>
            <th>GPU</th>
            <th>Memoria</th>
            <th>Inicio</th>
            <th>Verdict</th>
            <th>Riesgo</th>
            <th>Evidencias</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.pid} className="click-row" onClick={() => onProcessClick(row)}>
              <td>
                <div className="cell-primary with-actions">
                  <span>{row.name}</span>
                </div>
                <div className="cell-secondary">PID {row.pid}</div>
                <div className="cell-secondary">{row.exe_path ?? "-"}</div>
              </td>
              <td>{formatPercent(row.cpu_pct)}</td>
              <td>{formatPercent(row.gpu_pct)}</td>
              <td>{formatMemoryMb(row.memory_mb)}</td>
              <td>{formatDate(row.started_at)}</td>
              <td>{row.verdict}</td>
              <td>
                <span className={`risk-pill risk-pill--${row.suspicion.level}`}>
                  {row.suspicion.level} ({row.risk_score})
                </span>
              </td>
              <td>
                <ul className="threat-evidence">
                  {(row.risk_factors ?? row.suspicion.reasons).slice(0, 3).map((reason) => (
                    <li key={reason}>{reason}</li>
                  ))}
                </ul>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </DataPanel>
  );
}
