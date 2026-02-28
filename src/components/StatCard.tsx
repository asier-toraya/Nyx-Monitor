interface StatCardProps {
  title: string;
  value: string;
  hint: string;
  tone?: "neutral" | "warn" | "critical";
}

export function StatCard({ title, value, hint, tone = "neutral" }: StatCardProps) {
  return (
    <article className={`stat-card stat-card--${tone}`}>
      <p className="stat-card__title">{title}</p>
      <p className="stat-card__value">{value}</p>
      <p className="stat-card__hint">{hint}</p>
    </article>
  );
}
