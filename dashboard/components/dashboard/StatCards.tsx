"use client";

import type { Stats } from "@/types";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  color?: string;
}

function StatCard({ title, value, subtitle, color = "text-gray-900" }: StatCardProps) {
  return (
    <div className="bg-white rounded-xl border border-gray-200 p-6 shadow-sm">
      <p className="text-sm font-medium text-gray-500">{title}</p>
      <p className={`text-3xl font-bold mt-1 ${color}`}>{value}</p>
      {subtitle && <p className="text-xs text-gray-400 mt-1">{subtitle}</p>}
    </div>
  );
}

export function StatCards({ stats }: { stats: Stats }) {
  const blockRate = stats.total_events > 0
    ? ((stats.blocked_events / stats.total_events) * 100).toFixed(1) + "%"
    : "0%";

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard
        title="Total Events"
        value={stats.total_events.toLocaleString()}
        subtitle={`${stats.active_sessions} active sessions`}
      />
      <StatCard
        title="Blocked"
        value={stats.blocked_events.toLocaleString()}
        subtitle={`${blockRate} block rate`}
        color="text-red-600"
      />
      <StatCard
        title="Avg Risk Score"
        value={(stats.avg_risk_score * 100).toFixed(1) + "%"}
        subtitle="Across all events"
        color={stats.avg_risk_score >= 0.6 ? "text-orange-600" : "text-green-600"}
      />
      <StatCard
        title="Active Sessions"
        value={stats.active_sessions}
        subtitle="Monitored agents"
        color="text-blue-600"
      />
    </div>
  );
}
