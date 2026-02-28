import { useMemo, useState } from "react";
import { formatDate, formatMemoryMb, formatPercent } from "../lib/format";
import type { ProcessMetric } from "../types";

interface ThreatsTableProps {
  metrics: ProcessMetric[];
  onProcessClick: (process: ProcessMetric) => void;
}

export function ThreatsTable({ metrics, onProcessClick }: ThreatsTableProps) {
  const [query, setQuery] = useState("");
  const rows = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return metrics
      .filter((item) => item.suspicion.level !== "legitimate")
      .filter((item) => {
        if (!normalized) {
          return true;
        }
        return (
          item.name.toLowerCase().includes(normalized) ||
          (item.exe_path ?? "").toLowerCase().includes(normalized) ||
          item.pid.toString().includes(normalized)
        );
      })
      .sort((a, b) => {
        if (b.suspicion.score !== a.suspicion.score) {
          return b.suspicion.score - a.suspicion.score;
        }
        return b.cpu_pct - a.cpu_pct;
      });
  }, [metrics, query]);

  return (
    <div className="panel">
      <div className="panel__header panel__header--stack">
        <div>
          <h3>Threat Surface</h3>
          <p className="panel__subtle">{rows.length} processes under review</p>
        </div>
      </div>
      <div className="panel__toolbar">
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Filtrar amenazas por nombre, ruta o PID"
        />
      </div>
      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Proceso</th>
              <th>CPU</th>
              <th>GPU</th>
              <th>Memoria</th>
              <th>Inicio</th>
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
                <td>
                  <span className={`risk-pill risk-pill--${row.suspicion.level}`}>
                    {row.suspicion.level} ({row.suspicion.score})
                  </span>
                </td>
                <td>
                  <ul className="threat-evidence">
                    {row.suspicion.reasons.slice(0, 3).map((reason) => (
                      <li key={reason}>{reason}</li>
                    ))}
                  </ul>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

