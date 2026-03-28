import { useMemo, useState } from "react";
import type { EventEnvelope } from "../types";
import { formatDate } from "../lib/format";
import { useSearchQuery } from "../hooks/useSearchQuery";
import { matchesSearchQuery } from "../lib/search";
import { DataPanel } from "./DataPanel";

interface EventTimelineTableProps {
  events: EventEnvelope[];
}

export function EventTimelineTable({ events }: EventTimelineTableProps) {
  const { query, setQuery, normalizedQuery } = useSearchQuery();
  const [sensorFilter, setSensorFilter] = useState("all");

  const sensors = useMemo(() => {
    const values = new Set(events.map((event) => event.sensor));
    return ["all", ...Array.from(values).sort()];
  }, [events]);

  const rows = useMemo(() => {
    return events.filter((event) => {
      if (sensorFilter !== "all" && event.sensor !== sensorFilter) {
        return false;
      }

      return matchesSearchQuery(
        normalizedQuery,
        event.message,
        event.event_type,
        event.process?.image_name
      );
    });
  }, [events, normalizedQuery, sensorFilter]);

  return (
    <DataPanel
      title="Event Timeline"
      subtitle={`${rows.length} events loaded`}
      toolbar={
        <>
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Buscar por mensaje, tipo o proceso"
          />
          <select value={sensorFilter} onChange={(event) => setSensorFilter(event.target.value)}>
            {sensors.map((sensor) => (
              <option key={sensor} value={sensor}>
                {sensor === "all" ? "Todos los sensores" : sensor}
              </option>
            ))}
          </select>
        </>
      }
    >
      <table className="data-table data-table--compact">
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Tipo</th>
            <th>Sensor</th>
            <th>Severidad</th>
            <th>Proceso</th>
            <th>Detalle</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((event) => (
            <tr key={event.event_id}>
              <td>{formatDate(event.timestamp_utc)}</td>
              <td>{event.event_type}</td>
              <td>{event.sensor}</td>
              <td>{event.severity}</td>
              <td>{event.process ? `${event.process.image_name} (${event.process.pid})` : "-"}</td>
              <td>{event.message}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </DataPanel>
  );
}
