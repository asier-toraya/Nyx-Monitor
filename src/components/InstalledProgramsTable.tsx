import { useMemo, useState } from "react";
import type { InstalledProgram, TrustLevel } from "../types";
import { TrustIndicator } from "./TrustIndicator";

interface InstalledProgramsTableProps {
  programs: InstalledProgram[];
  onOpenPath: (path?: string) => void;
  onAddKnownProgram: (program: InstalledProgram, label: string) => Promise<void>;
  onOpenExternalUrl: (url: string) => Promise<void>;
}

type ProgramsFilter = "trusted" | "unknown";

const filters: { id: ProgramsFilter; label: string }[] = [
  { id: "trusted", label: "Confiables" },
  { id: "unknown", label: "Desconocidos" }
];

function buildVirusTotalUrl(name: string): string {
  return `https://www.virustotal.com/gui/search/${encodeURIComponent(name)}`;
}

function matchesFilter(level: TrustLevel, active: ProgramsFilter): boolean {
  if (active === "unknown") {
    return level === "unknown";
  }
  return level === "trusted" || level === "windows_native";
}

export function InstalledProgramsTable({
  programs,
  onOpenPath,
  onAddKnownProgram,
  onOpenExternalUrl
}: InstalledProgramsTableProps) {
  const [query, setQuery] = useState("");
  const [activeFilter, setActiveFilter] = useState<ProgramsFilter>("trusted");
  const normalized = query.trim().toLowerCase();

  const rows = useMemo(() => {
    const trustFiltered = programs.filter((program) => matchesFilter(program.trust_level, activeFilter));
    if (!normalized) {
      return trustFiltered;
    }
    return trustFiltered.filter((program) => {
      return (
        program.name.toLowerCase().includes(normalized) ||
        program.publisher?.toLowerCase().includes(normalized) ||
        program.version?.toLowerCase().includes(normalized)
      );
    });
  }, [programs, normalized, activeFilter]);

  return (
    <div className="panel">
      <div className="panel__header panel__header--stack">
        <div>
          <h3>Installed Programs</h3>
          <p className="panel__subtle">{rows.length} visible</p>
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
          placeholder="Buscar por nombre, publisher o version"
        />
      </div>
      <div className="table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Programa</th>
              <th>Confianza</th>
              <th>Version</th>
              <th>Publisher</th>
              <th>Install date</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((program) => {
              const openPath = program.executable_path ?? program.install_location;
              return (
                <tr
                  key={`${program.name}-${program.version ?? "no-version"}-${program.source}`}
                  className="click-row"
                  onClick={() => onOpenPath(openPath)}
                >
                  <td>
                    <div className="cell-primary with-actions">
                      <span>{program.name}</span>
                      {program.trust_level === "unknown" ? (
                        <button
                          className="vt-link"
                          onClick={async (event) => {
                            event.preventDefault();
                            event.stopPropagation();
                            await onOpenExternalUrl(buildVirusTotalUrl(program.name));
                          }}
                          title="Buscar en VirusTotal"
                        >
                          VT
                        </button>
                      ) : null}
                    </div>
                    <div className="cell-secondary">{openPath ?? "-"}</div>
                  </td>
                  <td>
                    <TrustIndicator
                      level={program.trust_level}
                      compact
                      labelOverride={program.trust_label}
                      addActionLabel="Anadir a programas conocidos"
                      onAddKnown={
                        program.trust_level === "unknown"
                          ? async (label) => onAddKnownProgram(program, label)
                          : undefined
                      }
                    />
                  </td>
                  <td>{program.version ?? "-"}</td>
                  <td>{program.publisher ?? "-"}</td>
                  <td>{program.install_date ?? "-"}</td>
                  <td>{program.source}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
