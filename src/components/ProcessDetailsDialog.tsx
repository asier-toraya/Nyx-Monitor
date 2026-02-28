import { useEffect, useState } from "react";
import type { ProcessMetric, TrustLevel } from "../types";

interface ProcessDetailsDialogProps {
  process: ProcessMetric | null;
  parentInfo?: {
    pid: number;
    name?: string;
    exe_path?: string;
  } | null;
  hashValue: string;
  isHashLoading: boolean;
  onClose: () => void;
  onSaveTrust: (payload: { trustLevel: TrustLevel; label?: string }) => Promise<void>;
  onCalculateHash: () => Promise<void>;
  onSearchVirusTotal: () => Promise<void>;
  onSearchGoogle: () => Promise<void>;
  onOpenPath: () => Promise<void>;
  onOpenParentPath: () => Promise<void>;
}

const trustOptions: { value: TrustLevel; label: string }[] = [
  { value: "trusted", label: "Verde (Confiable)" },
  { value: "windows_native", label: "Amarillo (Nativo de Windows)" },
  { value: "unknown", label: "Rojo (Desconocido/Sospechoso)" }
];

export function ProcessDetailsDialog({
  process,
  parentInfo,
  hashValue,
  isHashLoading,
  onClose,
  onSaveTrust,
  onCalculateHash,
  onSearchVirusTotal,
  onSearchGoogle,
  onOpenPath,
  onOpenParentPath
}: ProcessDetailsDialogProps) {
  const [trustLevel, setTrustLevel] = useState<TrustLevel>("unknown");
  const [label, setLabel] = useState("");

  useEffect(() => {
    if (!process) {
      return;
    }
    setTrustLevel(process.trust_level);
    setLabel(process.trust_label ?? "");
  }, [process?.pid, process?.started_at]);

  if (!process) {
    return null;
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-card" onClick={(event) => event.stopPropagation()}>
        <div className="modal-head">
          <div>
            <h3 className="modal-title">{process.name}</h3>
            <p className="modal-subtitle">Detailed process intelligence panel</p>
          </div>
          <button className="btn btn--small" onClick={onClose}>
            Cerrar
          </button>
        </div>

        <div className="modal-grid">
          <div className="modal-block">
            <h4>Confianza y etiqueta</h4>
            <label className="control-label control-label--stack">
              Nivel de confianza
              <select
                value={trustLevel}
                onChange={(event) => setTrustLevel(event.target.value as TrustLevel)}
              >
                {trustOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="control-label control-label--stack">
              Etiqueta personalizada
              <input
                value={label}
                onChange={(event) => setLabel(event.target.value)}
                placeholder="Ej: Servicio de empresa interno"
              />
            </label>
            <button
              className="btn btn--small"
              onClick={async () => onSaveTrust({ trustLevel, label: label.trim() || undefined })}
            >
              Guardar confianza/etiqueta
            </button>
          </div>

          <div className="modal-block">
            <h4>Datos del proceso</h4>
            <p>
              <strong>Ruta:</strong> {process.exe_path ?? "(sin ruta disponible)"}
            </p>
            <p>
              <strong>PID:</strong> {process.pid}
            </p>
            <p>
              <strong>PPID:</strong>{" "}
              {parentInfo ? (
                <>
                  <button
                    className="inline-link-btn"
                    onClick={onOpenParentPath}
                    disabled={!parentInfo}
                    title={parentInfo?.exe_path ?? "Ruta del proceso padre no disponible"}
                  >
                    {parentInfo.pid}
                  </button>{" "}
                  ({parentInfo.name ?? "Nombre no disponible"})
                </>
              ) : (
                "-"
              )}
            </p>
            <p>
              <strong>Hash SHA-256:</strong> {hashValue || "(vacio)"}
            </p>
          </div>
        </div>

        <div className="modal-actions">
          <button className="btn btn--small" onClick={onOpenPath} disabled={!process.exe_path}>
            Abrir carpeta
          </button>
          <button
            className="btn btn--small"
            onClick={onCalculateHash}
            disabled={isHashLoading || !process.exe_path}
          >
            {isHashLoading ? "Calculando hash..." : "Calcular hash"}
          </button>
          <button className="btn btn--small" onClick={onSearchVirusTotal}>
            Buscar en VirusTotal (hash o nombre)
          </button>
          <button className="btn btn--small" onClick={onSearchGoogle}>
            Buscar en Google (nombre)
          </button>
        </div>
      </div>
    </div>
  );
}

