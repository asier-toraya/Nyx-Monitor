import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ProcessMetric } from "../types";

interface UsageChartProps {
  metrics: ProcessMetric[];
}

export function UsageChart({ metrics }: UsageChartProps) {
  const top = [...metrics]
    .sort((a, b) => b.cpu_pct - a.cpu_pct)
    .slice(0, 12)
    .map((item) => ({
      name: item.name.length > 24 ? `${item.name.slice(0, 24)}...` : item.name,
      cpu: Number(item.cpu_pct.toFixed(1))
    }))
    .reverse();

  return (
    <div className="panel usage-panel">
      <div className="panel__header">
        <h3>CPU Pressure by Process</h3>
      </div>
      <div className="usage-chart">
        <ResponsiveContainer width="100%" height={330}>
          <BarChart data={top} layout="vertical" margin={{ left: 24, right: 18, top: 8, bottom: 8 }}>
            <XAxis type="number" domain={[0, 100]} tick={{ fontSize: 11 }} />
            <YAxis type="category" dataKey="name" width={170} tick={{ fontSize: 11 }} />
            <Tooltip />
            <Bar dataKey="cpu" fill="var(--chart-bar)" radius={[0, 2, 2, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
