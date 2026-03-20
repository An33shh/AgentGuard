"use client";

import Link from "next/link";
import type { AgentProfile } from "@/types";
import { getRiskLevel } from "@/types";
import { formatDate } from "@/lib/utils";

function RiskBar({ score }: { score: number }) {
  const level = getRiskLevel(score);
  const color: Record<string, string> = {
    low: "bg-[#3FB950]",
    medium: "bg-[#D29922]",
    high: "bg-[#F85149]",
    critical: "bg-[#F85149]",
  };
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1 bg-[#1C2844] rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${color[level]}`}
          style={{ width: `${Math.min(score * 100, 100)}%` }}
        />
      </div>
      <span className="text-xs font-mono text-[#6E7D91] w-10 text-right tabular-nums">
        {(score * 100).toFixed(0)}%
      </span>
    </div>
  );
}

function MiniSparkline({ values }: { values: number[] }) {
  if (values.length < 2) return null;
  const max = Math.max(...values, 0.01);
  const w = 64;
  const h = 20;
  const pts = values.map((v, i) => {
    const x = (i / (values.length - 1)) * w;
    const y = h - (v / max) * h;
    return `${x},${y}`;
  });
  return (
    <svg width={w} height={h} className="opacity-50">
      <polyline
        points={pts.join(" ")}
        fill="none"
        stroke="#6366F1"
        strokeWidth="1.5"
        strokeLinejoin="round"
        strokeLinecap="round"
      />
    </svg>
  );
}

export function AgentCard({ agent }: { agent: AgentProfile }) {
  const blockRate =
    agent.total_events > 0
      ? ((agent.blocked_events / agent.total_events) * 100).toFixed(0)
      : "0";

  const isHighRisk = agent.max_risk_score >= 0.75;

  return (
    <Link href={`/agents/${encodeURIComponent(agent.agent_id)}`}>
      <div className={`bg-[#0C1220] border rounded-xl p-5 hover:bg-[#0E1625] transition-colors cursor-pointer space-y-3.5 ${
        isHighRisk ? "border-[#F85149]/20 hover:border-[#F85149]/35 ring-1 ring-red-500/10" : "border-[#1C2844] hover:border-[#243354]"
      }`}>
        {/* Header */}
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span
                className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                  agent.is_registered ? "bg-indigo-400" : "bg-[#3A4A5C]"
                }`}
              />
              <h3 className="font-medium text-[#E6EDF3] text-sm truncate">
                {agent.display_name || agent.agent_goal}
              </h3>
            </div>
            <p className="text-xs text-[#484F58] truncate pl-3.5" title={agent.agent_goal}>
              {agent.agent_goal}
            </p>
          </div>
          <MiniSparkline values={agent.risk_trend} />
        </div>

        {/* Risk bar */}
        <div>
          <div className="flex justify-between text-xs text-[#484F58] mb-1.5">
            <span>Avg risk</span>
            <span>Max: {(agent.max_risk_score * 100).toFixed(0)}%</span>
          </div>
          <RiskBar score={agent.avg_risk_score} />
        </div>

        {/* Stats row */}
        <div className="flex items-center gap-3.5 text-xs text-[#484F58] border-t border-[#1C2844] pt-2.5">
          <span>
            <span className="font-medium text-[#8B949E]">{agent.total_events}</span> events
          </span>
          <span>
            <span className={`font-medium tabular-nums ${parseFloat(blockRate) > 0 ? "text-[#F85149]" : "text-[#3FB950]"}`}>
              {blockRate}%
            </span> blocked
          </span>
          <span>
            <span className="font-medium text-[#8B949E] tabular-nums">{agent.total_sessions}</span>{" "}
            {agent.total_sessions === 1 ? "session" : "sessions"}
          </span>
          <span className="ml-auto text-[#3A4A5C] tabular-nums">{formatDate(agent.last_seen)}</span>
        </div>

        {/* Attack patterns */}
        {agent.attack_patterns.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {agent.attack_patterns.slice(0, 4).map((p) => (
              <span
                key={p}
                className="text-xs px-1.5 py-0.5 bg-[#F85149]/8 text-[#F85149]/80 rounded border border-[#F85149]/15 font-mono"
              >
                {p.replace(/_/g, " ")}
              </span>
            ))}
            {agent.attack_patterns.length > 4 && (
              <span className="text-xs px-1.5 py-0.5 bg-[#101828] text-[#484F58] rounded border border-[#243354]">
                +{agent.attack_patterns.length - 4} more
              </span>
            )}
          </div>
        )}
      </div>
    </Link>
  );
}
