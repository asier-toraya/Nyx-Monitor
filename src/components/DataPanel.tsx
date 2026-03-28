import type { ReactNode } from "react";

interface DataPanelProps {
  title: string;
  subtitle: string;
  children: ReactNode;
  className?: string;
  actions?: ReactNode;
  filters?: ReactNode;
  toolbar?: ReactNode;
  tableWrapperClassName?: string;
}

function joinClassNames(...values: Array<string | undefined>): string {
  return values.filter(Boolean).join(" ");
}

export function DataPanel({
  title,
  subtitle,
  children,
  className,
  actions,
  filters,
  toolbar,
  tableWrapperClassName
}: DataPanelProps) {
  return (
    <div className={joinClassNames("panel", className)}>
      <div className="panel__header panel__header--stack">
        <div>
          <h3>{title}</h3>
          <p className="panel__subtle">{subtitle}</p>
        </div>
        {actions}
      </div>
      {filters}
      {toolbar ? <div className="panel__toolbar">{toolbar}</div> : null}
      <div className={joinClassNames("table-wrapper", tableWrapperClassName)}>{children}</div>
    </div>
  );
}
