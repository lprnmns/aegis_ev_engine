import type { StatusTone } from "../types";

interface StatusChipProps {
  label: string;
  tone?: StatusTone;
}

export function StatusChip({ label, tone = "neutral" }: StatusChipProps) {
  return <span className={`status-chip status-chip--${tone}`}>{label}</span>;
}
