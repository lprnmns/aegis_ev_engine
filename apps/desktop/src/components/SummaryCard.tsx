import type { ReactNode } from "react";

interface SummaryCardProps {
  title: string;
  value: ReactNode;
  detail?: string;
}

export function SummaryCard({ title, value, detail }: SummaryCardProps) {
  return (
    <section className="summary-card">
      <div className="summary-card__title">{title}</div>
      <div className="summary-card__value">{value}</div>
      {detail ? <div className="summary-card__detail">{detail}</div> : null}
    </section>
  );
}
