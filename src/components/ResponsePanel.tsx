import { useEffect, useMemo, useState } from "react";
import type {
  ProcessMetric,
  ResponseActionRecord,
  ResponseActionType,
  ResponsePolicy
} from "../types";
import { formatDate } from "../lib/format";

interface ResponsePanelProps {
  policy: ResponsePolicy;
  actions: ResponseActionRecord[];
  processes: ProcessMetric[];
  onSavePolicy: (policy: ResponsePolicy) => Promise<void>;
  onRunAction: (payload: { pid: number; actionType: ResponseActionType; reason?: string }) => Promise<void>;
}

export function ResponsePanel({
  policy,
  actions,
  processes,
  onSavePolicy,
  onRunAction
}: ResponsePanelProps) {
  const [draft, setDraft] = useState<ResponsePolicy>(policy);

  useEffect(() => {
    setDraft(policy);
  }, [policy]);

  const candidates = useMemo(() => {
    return [...processes]
      .filter((proc) => proc.risk_score >= 60)
      .sort((a, b) => b.risk_score - a.risk_score)
      .slice(0, 12);
  }, [processes]);

  return (
    <div className="panel-stack panel-stack--response">
      <div className="panel panel--response-policy">
        <div className="panel__header">
          <h3>Response Policy</h3>
        </div>
        <div className="panel__content panel__content--policy">
          <label className="control-label control-label--stack">
            Mode
            <select
              value={draft.mode}
              onChange={(event) =>
                setDraft((prev) => ({ ...prev, mode: event.target.value as ResponsePolicy["mode"] }))
              }
            >
              <option value="audit">Audit</option>
              <option value="constrain">Constrain</option>
            </select>
          </label>
          <label className="control-label control-label--stack">
            Auto constrain threshold
            <input
              type="number"
              min={50}
              max={100}
              value={draft.auto_constrain_threshold}
              onChange={(event) =>
                setDraft((prev) => ({
                  ...prev,
                  auto_constrain_threshold: Number(event.target.value)
                }))
              }
            />
          </label>
          <label className="control-label">
            <input
              type="checkbox"
              checked={draft.safe_mode}
              onChange={(event) => setDraft((prev) => ({ ...prev, safe_mode: event.target.checked }))}
            />
            Safe mode (block critical process actions)
          </label>
          <label className="control-label">
            <input
              type="checkbox"
              checked={draft.allow_terminate}
              onChange={(event) =>
                setDraft((prev) => ({ ...prev, allow_terminate: event.target.checked }))
              }
            />
            Allow terminate process
          </label>
          <label className="control-label control-label--stack">
            Cooldown seconds
            <input
              type="number"
              min={30}
              max={3600}
              value={draft.cooldown_seconds}
              onChange={(event) =>
                setDraft((prev) => ({ ...prev, cooldown_seconds: Number(event.target.value) }))
              }
            />
          </label>
          <button className="btn btn--small" onClick={async () => onSavePolicy(draft)}>
            Save policy
          </button>
        </div>
      </div>

      <div className="panel panel--table">
        <div className="panel__header">
          <h3>Manual Constrain</h3>
        </div>
        {candidates.length === 0 ? (
          <p className="panel__empty">No high-risk process candidates right now.</p>
        ) : (
          <div className="table-wrapper table-wrapper--tall">
            <table className="data-table data-table--compact data-table--response">
              <thead>
                <tr>
                  <th>Process</th>
                  <th>Risk</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {candidates.map((proc) => (
                  <tr key={proc.pid}>
                    <td>
                      {proc.name} (PID {proc.pid})
                    </td>
                    <td>
                      {proc.risk_score} / {proc.verdict}
                    </td>
                    <td>
                      <div className="panel__actions response-actions">
                        <button
                          className="btn btn--small"
                          onClick={async () =>
                            onRunAction({
                              pid: proc.pid,
                              actionType: "suspend_process",
                              reason: "manual suspend from response panel"
                            })
                          }
                        >
                          Suspend
                        </button>
                        <button
                          className="btn btn--small"
                          onClick={async () =>
                            onRunAction({
                              pid: proc.pid,
                              actionType: "block_process_network",
                              reason: "manual network constrain from response panel"
                            })
                          }
                        >
                          Block Network
                        </button>
                        {policy.allow_terminate ? (
                          <button
                            className="btn btn--small btn--danger"
                            onClick={async () =>
                              onRunAction({
                                pid: proc.pid,
                                actionType: "terminate_process",
                                reason: "manual terminate from response panel"
                              })
                            }
                          >
                            Terminate
                          </button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="panel panel--table">
        <div className="panel__header">
          <h3>Response Audit Trail</h3>
        </div>
        {actions.length === 0 ? (
          <p className="panel__empty">No response actions recorded yet.</p>
        ) : (
          <div className="table-wrapper table-wrapper--tall">
            <table className="data-table data-table--compact data-table--response-audit">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Mode</th>
                  <th>Action</th>
                  <th>Process</th>
                  <th>Score</th>
                  <th>Status</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {actions.map((item) => (
                  <tr key={item.id}>
                    <td>{formatDate(item.timestamp_utc)}</td>
                    <td>{item.mode}</td>
                    <td>{item.action_type}</td>
                    <td>
                      {item.process_name} ({item.pid})
                    </td>
                    <td>
                      {item.score} / {item.verdict}
                    </td>
                    <td>{item.success ? "success" : "failed"}</td>
                    <td>{item.details}</td>
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
