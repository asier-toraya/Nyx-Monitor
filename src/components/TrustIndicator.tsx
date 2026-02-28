import { useState, type MouseEvent } from "react";
import { trustLabel } from "../lib/format";
import type { TrustLevel } from "../types";

interface TrustIndicatorProps {
  level: TrustLevel;
  compact?: boolean;
  labelOverride?: string;
  addActionLabel?: string;
  onAddKnown?: (label: string) => Promise<void> | void;
  configureActionLabel?: string;
  onConfigure?: () => Promise<void> | void;
}

export function TrustIndicator({
  level,
  compact = false,
  labelOverride,
  addActionLabel,
  onAddKnown,
  configureActionLabel,
  onConfigure
}: TrustIndicatorProps) {
  const [menuOpen, setMenuOpen] = useState(false);
  const hasActions = Boolean(onAddKnown || onConfigure);
  const displayLabel = labelOverride ?? trustLabel(level);

  const openPrompt = async (event: MouseEvent<HTMLButtonElement>) => {
    event.preventDefault();
    event.stopPropagation();
    setMenuOpen(false);
    if (!onAddKnown) {
      return;
    }

    const label = window.prompt("Nombre para mostrar como proceso/programa conocido:");
    if (!label || !label.trim()) {
      return;
    }
    await onAddKnown(label.trim());
  };

  if (!hasActions) {
    return (
      <span className={`trust-indicator ${compact ? "trust-indicator--compact" : ""}`}>
        <span className={`trust-dot trust-dot--${level}`} />
        <span>{displayLabel}</span>
      </span>
    );
  }

  return (
    <div
      className={`trust-indicator trust-indicator--interactive ${compact ? "trust-indicator--compact" : ""}`}
      onClick={(event) => {
        event.preventDefault();
        event.stopPropagation();
      }}
    >
      <button
        className="trust-indicator__button"
        onClick={(event) => {
          event.preventDefault();
          event.stopPropagation();
          setMenuOpen((previous) => !previous);
        }}
        title="Opciones de confianza"
      >
        <span className={`trust-dot trust-dot--${level}`} />
        <span>{displayLabel}</span>
      </button>
      {menuOpen ? (
        <div className="trust-menu">
          {onAddKnown ? (
            <button className="trust-menu__item" onClick={openPrompt}>
              {addActionLabel ?? "Anadir a conocidos"}
            </button>
          ) : null}
          {onConfigure ? (
            <button
              className="trust-menu__item"
              onClick={async (event) => {
                event.preventDefault();
                event.stopPropagation();
                setMenuOpen(false);
                await onConfigure();
              }}
            >
              {configureActionLabel ?? "Personalizar indicador"}
            </button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
