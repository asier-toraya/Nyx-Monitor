import { formatDate, severityLabel } from "../lib/format";
import type { Alert } from "../types";

interface AlertsPanelProps {
  alerts: Alert[];
  onDelete: (alertId: string) => Promise<void>;
  onDeleteAll?: () => Promise<void>;
}

export function AlertsPanel({ alerts, onDelete, onDeleteAll }: AlertsPanelProps) {
  return (
    <div className="panel">
      <div className="panel__header">
        <h3>Active Incidents</h3>
        <div className="panel__actions">
          <span>{alerts.length} active</span>
          {onDeleteAll ? (
            <button className="btn btn--small" onClick={onDeleteAll} disabled={alerts.length === 0}>
              Clear all
            </button>
          ) : null}
        </div>
      </div>
      {alerts.length === 0 ? (
        <p className="panel__empty">No active incidents. Monitoring is currently stable.</p>
      ) : (
        <ul className="alert-list">
          {alerts.map((alert) => (
            <li key={alert.id} className={`alert-card alert-card--${alert.severity}`}>
              <div className="alert-card__head">
                <div>
                  <p className="alert-card__title">{alert.title}</p>
                  <p className="alert-card__meta">
                    {severityLabel(alert.severity)} | {formatDate(alert.timestamp)}
                  </p>
                </div>
                <div className="alert-card__actions">
                  <button onClick={() => onDelete(alert.id)} className="btn btn--small btn--danger">
                    Remove
                  </button>
                </div>
              </div>
              <p className="alert-card__description">{alert.description}</p>
              {alert.evidence.length > 0 ? (
                <ul className="alert-evidence">
                  {alert.evidence.slice(0, 4).map((item) => (
                    <li key={item}>{item}</li>
                  ))}
                </ul>
              ) : null}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

