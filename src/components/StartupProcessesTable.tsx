import { useMemo, useState } from "react";
import type { StartupProcess, TrustLevel } from "../types";
import { TrustIndicator } from "./TrustIndicator";

interface StartupProcessesTableProps {
  processes: StartupProcess[];
  onOpenPath: (path?: string) => void;
}

const filters: { id: "all" | TrustLevel; label: string }[] = [
  { id: "all", label: "Todos" },
  { id: "windows_native", label: "Windows" },
  { id: "trusted", label: "Conocidos" },
  { id: "unknown", label: "Desconocidos" }
];

export function StartupProcessesTable({ processes, onOpenPath }: StartupProcessesTableProps) {
  const [query, setQuery] = useState("");
  const [activeFilter, setActiveFilter] = useState<(typeof filters)[number]["id"]>("all");

  const rows = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return processes.filter((item) => {
      if (activeFilter !== "all" && item.trust_level !== activeFilter) {
        return false;
      }
      if (!normalized) {
        return true;
      }
      return (
        item.name.toLowerCase().includes(normalized) ||
        item.command.toLowerCase().includes(normalized) ||
        item.source.toLowerCase().includes(normalized)
      );
    });
  }, [processes, query, activeFilter]);

  return (
    <div className="panel">
      <div className="panel__header panel__header--stack">
        <div>
          <h3>Startup Processes</h3>
          <p className="panel__subtle">{rows.length} entradas</p>
        </div>
      </div>
      <nav className="mini-tabs">
        {filters.map((filter) => (
          <button
            key={filter.id}
            className={`mini-tab ${activeFilter === filter.id ? "mini-tab--active" : ""}`}
            onClick={() => setActiveFilter(filter.id)}
          >
            {filter.label}
          </button>
        ))}
      </nav>
      <div className="panel__toolbar">
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Filtrar por nombre, comando o fuente"
        />
      </div>
      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Confianza</th>
              <th>Comando</th>
              <th>Fuente</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((item) => (
              <tr
                key={`${item.name}-${item.command}-${item.source}`}
                className="click-row"
                onClick={() => onOpenPath(item.location || item.command)}
              >
                <td>{item.name}</td>
                <td>
                  <TrustIndicator level={item.trust_level} compact />
                </td>
                <td className="cell-secondary">{item.command}</td>
                <td>{item.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
