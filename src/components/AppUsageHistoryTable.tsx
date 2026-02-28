import { useMemo, useState } from "react";
import { formatDate, formatPercent } from "../lib/format";
import type { AppUsageEntry } from "../types";

interface AppUsageHistoryTableProps {
  entries: AppUsageEntry[];
  onOpenPath: (path?: string) => void;
}

export function AppUsageHistoryTable({ entries, onOpenPath }: AppUsageHistoryTableProps) {
  const [query, setQuery] = useState("");
  const rows = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) {
      return entries;
    }
    return entries.filter((entry) => {
      return (
        entry.name.toLowerCase().includes(normalized) ||
        entry.executable_path?.toLowerCase().includes(normalized)
      );
    });
  }, [entries, query]);

  return (
    <div className="panel">
      <div className="panel__header panel__header--stack">
        <div>
          <h3>App Usage History</h3>
          <p className="panel__subtle">Historial en la sesion actual ({rows.length})</p>
        </div>
      </div>
      <div className="panel__toolbar">
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Buscar aplicacion por nombre o ruta"
        />
      </div>
      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Aplicacion</th>
              <th>Lanzamientos</th>
              <th>CPU pico</th>
              <th>Primer uso</th>
              <th>Ultimo uso</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((entry) => (
              <tr
                key={entry.app_key}
                className="click-row"
                onClick={() => onOpenPath(entry.executable_path)}
              >
                <td>
                  <div className="cell-primary">{entry.name}</div>
                  <div className="cell-secondary">{entry.executable_path ?? "-"}</div>
                </td>
                <td>{entry.launch_count}</td>
                <td>{formatPercent(entry.max_cpu_pct)}</td>
                <td>{formatDate(entry.first_seen)}</td>
                <td>{formatDate(entry.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
