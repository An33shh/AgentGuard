"use client";

import { useHealthStatus, type HealthStatus } from "@/lib/useHealthStatus";

const STATUS_STYLES: Record<HealthStatus, { bg: string; border: string; text: string; dot: string; label: string; pulse: boolean }> = {
  healthy: {
    bg: "rgba(63,185,80,0.08)", border: "rgba(63,185,80,0.15)", text: "#3FB950", dot: "#3FB950",
    label: "Monitoring Active", pulse: true,
  },
  degraded: {
    bg: "rgba(210,153,34,0.08)", border: "rgba(210,153,34,0.15)", text: "#D29922", dot: "#D29922",
    label: "Degraded", pulse: false,
  },
  down: {
    bg: "rgba(248,81,73,0.08)", border: "rgba(248,81,73,0.15)", text: "#F85149", dot: "#F85149",
    label: "API Unreachable", pulse: false,
  },
  checking: {
    bg: "rgba(110,125,145,0.08)", border: "rgba(110,125,145,0.15)", text: "#6E7D91", dot: "#6E7D91",
    label: "Checking…", pulse: false,
  },
};

export function MonitoringBadge() {
  const status = useHealthStatus();
  const s = STATUS_STYLES[status];
  return (
    <div
      className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs"
      style={{ background: s.bg, border: `1px solid ${s.border}`, color: s.text }}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full shrink-0 ${s.pulse ? "pulse" : ""}`}
        style={{ background: s.dot, boxShadow: s.pulse ? `0 0 4px ${s.dot}cc` : undefined }}
      />
      <span className="font-mono">{s.label}</span>
    </div>
  );
}
