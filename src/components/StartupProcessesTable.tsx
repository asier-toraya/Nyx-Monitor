import { useMemo, useState } from "react";
import { useSearchQuery } from "../hooks/useSearchQuery";
import { matchesSearchQuery } from "../lib/search";
import type { StartupProcess, TrustLevel } from "../types";
import { DataPanel } from "./DataPanel";
import { MiniTabs } from "./MiniTabs";
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
  const { query, setQuery, normalizedQuery } = useSearchQuery();
  const [activeFilter, setActiveFilter] = useState<(typeof filters)[number]["id"]>("all");

  const rows = useMemo(() => {
    return processes.filter((item) => {
      if (activeFilter !== "all" && item.trust_level !== activeFilter) {
        return false;
      }

      return matchesSearchQuery(normalizedQuery, item.name, item.command, item.source);
    });
  }, [processes, normalizedQuery, activeFilter]);

  return (
    <DataPanel
      title="Startup Processes"
      subtitle={`${rows.length} entradas`}
      filters={<MiniTabs options={filters} activeId={activeFilter} onChange={setActiveFilter} />}
      toolbar={
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Filtrar por nombre, comando o fuente"
        />
      }
    >
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
    </DataPanel>
  );
}
