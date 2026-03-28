import { useMemo, useState } from "react";
import { useSearchQuery } from "../hooks/useSearchQuery";
import { buildVirusTotalSearchUrl } from "../lib/externalLinks";
import { matchesSearchQuery } from "../lib/search";
import type { InstalledProgram, TrustLevel } from "../types";
import { DataPanel } from "./DataPanel";
import { MiniTabs } from "./MiniTabs";
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
  const { query, setQuery, normalizedQuery } = useSearchQuery();
  const [activeFilter, setActiveFilter] = useState<ProgramsFilter>("trusted");

  const rows = useMemo(() => {
    const trustFiltered = programs.filter((program) =>
      matchesFilter(program.trust_level, activeFilter)
    );

    return trustFiltered.filter((program) =>
      matchesSearchQuery(normalizedQuery, program.name, program.publisher, program.version)
    );
  }, [programs, normalizedQuery, activeFilter]);

  return (
    <DataPanel
      title="Installed Programs"
      subtitle={`${rows.length} visible`}
      filters={<MiniTabs options={filters} activeId={activeFilter} onChange={setActiveFilter} />}
      toolbar={
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Buscar por nombre, publisher o version"
        />
      }
    >
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
                          await onOpenExternalUrl(buildVirusTotalSearchUrl(program.name));
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
    </DataPanel>
  );
}
