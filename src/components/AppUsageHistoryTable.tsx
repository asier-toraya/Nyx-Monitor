import { useMemo } from "react";
import { formatDate, formatPercent } from "../lib/format";
import { useSearchQuery } from "../hooks/useSearchQuery";
import { matchesSearchQuery } from "../lib/search";
import type { AppUsageEntry } from "../types";
import { DataPanel } from "./DataPanel";

interface AppUsageHistoryTableProps {
  entries: AppUsageEntry[];
  onOpenPath: (path?: string) => void;
}

export function AppUsageHistoryTable({ entries, onOpenPath }: AppUsageHistoryTableProps) {
  const { query, setQuery, normalizedQuery } = useSearchQuery();

  const rows = useMemo(() => {
    return entries.filter((entry) =>
      matchesSearchQuery(normalizedQuery, entry.name, entry.executable_path)
    );
  }, [entries, normalizedQuery]);

  return (
    <DataPanel
      title="App Usage History"
      subtitle={`Historial en la sesion actual (${rows.length})`}
      toolbar={
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Buscar aplicacion por nombre o ruta"
        />
      }
    >
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
    </DataPanel>
  );
}
