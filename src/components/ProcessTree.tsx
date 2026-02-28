import { useMemo, useState } from "react";
import type { ProcessNode, TrustLevel } from "../types";
import { TrustIndicator } from "./TrustIndicator";

interface ProcessTreeProps {
  tree: ProcessNode[];
  onProcessClick: (process: { pid: number }) => void;
  onOpenExternalUrl: (url: string) => Promise<void>;
}

function filterTree(nodes: ProcessNode[], query: string): ProcessNode[] {
  const normalized = query.trim().toLowerCase();
  if (!normalized) {
    return nodes;
  }

  const visit = (node: ProcessNode): ProcessNode | null => {
    const matchesSelf =
      node.name.toLowerCase().includes(normalized) ||
      (node.exe_path ?? "").toLowerCase().includes(normalized) ||
      node.pid.toString().includes(normalized);
    const children = node.children.map(visit).filter((item): item is ProcessNode => item !== null);
    if (!matchesSelf && children.length === 0) {
      return null;
    }
    return { ...node, children };
  };

  return nodes.map(visit).filter((item): item is ProcessNode => item !== null);
}

function sortTree(nodes: ProcessNode[], byColor: boolean): ProcessNode[] {
  const trustOrder: Record<TrustLevel, number> = {
    unknown: 0,
    trusted: 1,
    windows_native: 2
  };

  return [...nodes]
    .map((node) => ({ ...node, children: sortTree(node.children, byColor) }))
    .sort((a, b) => {
      if (byColor) {
        const levelDiff = trustOrder[a.trust_level] - trustOrder[b.trust_level];
        if (levelDiff !== 0) {
          return levelDiff;
        }
      }
      return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
    });
}

function TreeNode({
  node,
  onProcessClick,
  forceExpanded,
  onOpenExternalUrl
}: {
  node: ProcessNode;
  onProcessClick: (process: { pid: number }) => void;
  forceExpanded: boolean;
  onOpenExternalUrl: (url: string) => Promise<void>;
}) {
  const hasChildren = node.children.length > 0;
  const [isExpanded, setIsExpanded] = useState(false);
  const expanded = forceExpanded || isExpanded;

  return (
    <li className="tree-node">
      <div className="tree-node__row">
        {hasChildren ? (
          <button
            className="tree-toggle"
            onClick={(event) => {
              event.preventDefault();
              event.stopPropagation();
              setIsExpanded((previous) => !previous);
            }}
            title={expanded ? "Contraer rama" : "Expandir rama"}
          >
            {expanded ? "v" : ">"}
          </button>
        ) : (
          <span className="tree-toggle tree-toggle--ghost" />
        )}
        <button
          className="tree-node__link"
          onClick={(event) => {
            event.preventDefault();
            event.stopPropagation();
            onProcessClick({ pid: node.pid });
          }}
          title={node.exe_path ?? "Path not available"}
        >
          {node.name}
        </button>
        {node.trust_level === "unknown" ? (
          <button
            className="vt-link"
            title="Buscar este proceso en VirusTotal"
            onClick={async (event) => {
              event.preventDefault();
              event.stopPropagation();
              await onOpenExternalUrl(
                `https://www.virustotal.com/gui/search/${encodeURIComponent(node.name)}`
              );
            }}
          >
            VT
          </button>
        ) : null}
        <span className="tree-node__meta">PID {node.pid}</span>
        <TrustIndicator level={node.trust_level} compact labelOverride={node.trust_label} />
      </div>
      {hasChildren && expanded ? (
        <ul className="tree-children">
          {node.children.map((child) => (
            <TreeNode
              key={child.pid}
              node={child}
              onProcessClick={onProcessClick}
              forceExpanded={forceExpanded}
              onOpenExternalUrl={onOpenExternalUrl}
            />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

export function ProcessTree({ tree, onProcessClick, onOpenExternalUrl }: ProcessTreeProps) {
  const [query, setQuery] = useState("");
  const [orderByColor, setOrderByColor] = useState(false);

  const sorted = useMemo(() => sortTree(tree, orderByColor), [tree, orderByColor]);
  const filtered = useMemo(() => filterTree(sorted, query), [sorted, query]);
  const forceExpanded = query.trim().length > 0;

  return (
    <div className="panel">
      <div className="panel__header">
        <h3>Process Lineage</h3>
        <div className="panel__actions">
          <button className="btn btn--small" onClick={() => setOrderByColor((prev) => !prev)}>
            {orderByColor ? "Orden alfabetico" : "Ordenar por color"}
          </button>
          <span>{filtered.length} roots</span>
        </div>
      </div>
      <div className="panel__toolbar">
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="Buscar nodo por nombre, ruta o PID"
        />
      </div>
      {filtered.length === 0 ? (
        <p className="panel__empty">No hay procesos para ese filtro.</p>
      ) : (
        <ul className="process-tree">
          {filtered.map((node) => (
            <TreeNode
              key={node.pid}
              node={node}
              onProcessClick={onProcessClick}
              forceExpanded={forceExpanded}
              onOpenExternalUrl={onOpenExternalUrl}
            />
          ))}
        </ul>
      )}
    </div>
  );
}

