"use client";

import type { Stats } from "@/types";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  accent?: "red" | "green" | "blue" | "default";
  icon?: React.ReactNode;
}

function StatCard({ title, value, subtitle, accent = "default", icon }: StatCardProps) {
  const config = {
    red: {
      value: "text-[#F85149]",
      top: "#F85149",
      glow: "rgba(248,81,73,0.08)",
      border: "rgba(248,81,73,0.15)",
      iconBg: "rgba(248,81,73,0.1)",
      iconColor: "#F85149",
    },
    green: {
      value: "text-[#3FB950]",
      top: "#3FB950",
      glow: "rgba(63,185,80,0.06)",
      border: "rgba(63,185,80,0.12)",
      iconBg: "rgba(63,185,80,0.1)",
      iconColor: "#3FB950",
    },
    blue: {
      value: "text-indigo-400",
      top: "#6366F1",
      glow: "rgba(99,102,241,0.06)",
      border: "rgba(99,102,241,0.12)",
      iconBg: "rgba(99,102,241,0.1)",
      iconColor: "#818CF8",
    },
    default: {
      value: "text-[#E6EDF3]",
      top: "#1C2844",
      glow: "transparent",
      border: "#1C2844",
      iconBg: "rgba(255,255,255,0.04)",
      iconColor: "#6E7D91",
    },
  };

  const c = config[accent];

  return (
    <div
      className="rounded-xl p-5 relative overflow-hidden transition-transform duration-150 hover:-translate-y-px"
      style={{
        background: `linear-gradient(135deg, #101828 0%, #0C1220 100%)`,
        border: `1px solid ${c.border}`,
        boxShadow: accent !== "default" ? `0 0 0 1px ${c.border}, inset 0 1px 0 rgba(255,255,255,0.03)` : `inset 0 1px 0 rgba(255,255,255,0.03)`,
      }}
    >
      {/* Top accent line */}
      <div
        className="absolute top-0 left-0 right-0 h-px"
        style={{ background: `linear-gradient(90deg, transparent, ${c.top}60, transparent)` }}
      />

      <div className="flex items-start justify-between">
        <div className="flex-1 min-w-0">
          <p className="text-[11px] font-medium uppercase tracking-[0.1em]" style={{ color: "#6E7D91" }}>
            {title}
          </p>
          <p className={`text-3xl font-semibold mt-2.5 tabular-nums font-mono ${c.value}`} style={{ letterSpacing: "-0.02em" }}>
            {value}
          </p>
          {subtitle && (
            <p className="text-xs mt-1.5" style={{ color: "#484F58" }}>
              {subtitle}
            </p>
          )}
        </div>
        {icon && (
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ml-3"
            style={{ background: c.iconBg, color: c.iconColor }}
          >
            {icon}
          </div>
        )}
      </div>
    </div>
  );
}

export function StatCards({ stats }: { stats: Stats }) {
  const blockRate = stats.total_events > 0
    ? ((stats.blocked_events / stats.total_events) * 100).toFixed(1) + "%"
    : "0%";

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
      <StatCard
        title="Total Events"
        value={stats.total_events.toLocaleString()}
        subtitle={`${stats.active_sessions} active session${stats.active_sessions !== 1 ? "s" : ""}`}
        icon={
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
            <path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2" />
            <rect x="9" y="3" width="6" height="4" rx="1" />
            <path d="M9 12h6M9 16h4" />
          </svg>
        }
      />
      <StatCard
        title="Blocked"
        value={stats.blocked_events.toLocaleString()}
        subtitle={`${blockRate} block rate`}
        accent="red"
        icon={
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" />
            <line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
          </svg>
        }
      />
      <StatCard
        title="Avg Risk Score"
        value={(stats.avg_risk_score * 100).toFixed(1) + "%"}
        subtitle="Across all events"
        accent={stats.avg_risk_score >= 0.6 ? "red" : "green"}
        icon={
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        }
      />
      <StatCard
        title="Active Sessions"
        value={stats.active_sessions}
        subtitle="Monitored agents"
        accent="blue"
        icon={
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="8" r="4" />
            <path d="M6 20v-1a6 6 0 0112 0v1" />
          </svg>
        }
      />
    </div>
  );
}
