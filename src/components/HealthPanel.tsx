import type { PerformanceStats, SensorHealth } from "../types";

interface HealthPanelProps {
  sensors: SensorHealth[];
  performance: PerformanceStats;
}

export function HealthPanel({ sensors, performance }: HealthPanelProps) {
  return (
    <div className="panel-stack panel-stack--health">
      <div className="panel panel--health-metrics">
        <div className="panel__header">
          <h3>Pipeline Performance</h3>
        </div>
        <div className="panel__content panel__content--metrics">
          <p>Loop last: {performance.loop_last_ms.toFixed(1)} ms</p>
          <p>Loop avg: {performance.loop_avg_ms.toFixed(1)} ms</p>
          <p>Loop p95: {performance.loop_p95_ms.toFixed(1)} ms</p>
          <p>Tracked processes: {performance.tracked_processes}</p>
          <p>Total events: {performance.total_events}</p>
        </div>
      </div>

      <div className="panel panel--table">
        <div className="panel__header">
          <h3>Sensor Health</h3>
        </div>
        {sensors.length === 0 ? (
          <p className="panel__empty">No sensor telemetry available yet.</p>
        ) : (
          <div className="table-wrapper table-wrapper--tall">
            <table className="data-table data-table--compact data-table--health">
              <thead>
                <tr>
                  <th>Sensor</th>
                  <th>Status</th>
                  <th>Events</th>
                  <th>Latency</th>
                  <th>Last success</th>
                  <th>Last error</th>
                </tr>
              </thead>
              <tbody>
                {sensors.map((sensor) => (
                  <tr key={sensor.sensor}>
                    <td>{sensor.sensor}</td>
                    <td>{sensor.status}</td>
                    <td>{sensor.events_emitted}</td>
                    <td>
                      {sensor.last_latency_ms != null ? `${sensor.last_latency_ms.toFixed(1)} ms` : "-"}
                    </td>
                    <td>{sensor.last_success_utc ?? "-"}</td>
                    <td>{sensor.last_error ?? "-"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
