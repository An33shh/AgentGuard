"use client";

import Link from "next/link";
import type { AgentProfile } from "@/types";
import { getRiskLevel } from "@/types";
import { formatDate } from "@/lib/utils";

function RiskBar({ score }: { score: number }) {
  const level = getRiskLevel(score);
  const color: Record<string, string> = {
    low: "bg-green-400",
    medium: "bg-yellow-400",
    high: "bg-orange-400",
    critical: "bg-red-500",
  };
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${color[level]}`}
          style={{ width: `${Math.min(score * 100, 100)}%` }}
        />
      </div>
      <span className="text-xs font-mono text-gray-600 w-10 text-right">
        {(score * 100).toFixed(0)}%
      </span>
    </div>
  );
}

function MiniSparkline({ values }: { values: number[] }) {
  if (values.length < 2) return null;
  const max = Math.max(...values, 0.01);
  const w = 80;
  const h = 24;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * w;
    const y = h - (v / max) * h;
    return `${x},${y}`;
  });
  return (
    <svg width={w} height={h} className="opacity-60">
      <polyline
        points={pts.join(" ")}
        fill="none"
        stroke="#6366f1"
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}

interface AgentCardProps {
  agent: AgentProfile;
}

export function AgentCard({ agent }: AgentCardProps) {
  const blockRate =
    agent.total_events > 0
      ? ((agent.blocked_events / agent.total_events) * 100).toFixed(0)
      : "0";

  return (
    <Link href={`/agents/${encodeURIComponent(agent.agent_id)}`}>
      <div className="bg-white border border-gray-200 rounded-xl p-5 hover:border-indigo-300 hover:shadow-md transition-all cursor-pointer space-y-3">
        {/* Header */}
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-0.5">
              <span
                className={`w-2 h-2 rounded-full shrink-0 ${
                  agent.is_registered ? "bg-indigo-400" : "bg-gray-300"
                }`}
                title={agent.is_registered ? "Registered" : "Auto-detected"}
              />
              <h3 className="font-semibold text-gray-900 text-sm truncate">
                {agent.agent_goal}
              </h3>
            </div>
            {agent.agent_id === "legacy-unknown" ? (
              <p className="text-xs text-gray-400 truncate">
                {agent.framework !== "unknown" ? agent.framework : "Pre-migration events"}
              </p>
            ) : (
              <p className="text-xs text-gray-400 font-mono truncate">
                {agent.agent_id}
              </p>
            )}
          </div>
          <MiniSparkline values={agent.risk_trend} />
        </div>

        {/* Risk bar */}
        <div>
          <div className="flex justify-between text-xs text-gray-500 mb-1">
            <span>Avg risk</span>
            <span>Max: {(agent.max_risk_score * 100).toFixed(0)}%</span>
          </div>
          <RiskBar score={agent.avg_risk_score} />
        </div>

        {/* Stats row */}
        <div className="flex items-center gap-4 text-xs text-gray-500 border-t border-gray-50 pt-2">
          <span>
            <span className="font-medium text-gray-700">{agent.total_events}</span> events
          </span>
          <span>
            <span className="font-medium text-red-600">{blockRate}%</span> blocked
          </span>
          <span>
            <span className="font-medium text-gray-700">{agent.total_sessions}</span>{" "}
            {agent.total_sessions === 1 ? "session" : "sessions"}
          </span>
          <span className="ml-auto text-gray-400">{formatDate(agent.last_seen)}</span>
        </div>

        {/* Attack patterns */}
        {agent.attack_patterns.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {agent.attack_patterns.slice(0, 4).map((p) => (
              <span
                key={p}
                className="text-xs px-1.5 py-0.5 bg-red-50 text-red-600 rounded font-mono"
              >
                {p.replace(/_/g, " ")}
              </span>
            ))}
            {agent.attack_patterns.length > 4 && (
              <span className="text-xs px-1.5 py-0.5 bg-gray-100 text-gray-500 rounded">
                +{agent.attack_patterns.length - 4} more
              </span>
            )}
          </div>
        )}
      </div>
    </Link>
  );
}
