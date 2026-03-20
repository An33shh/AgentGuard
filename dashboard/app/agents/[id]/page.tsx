import { notFound } from "next/navigation";
import Link from "next/link";
import { getAgent, getAgentGraph } from "@/lib/api";
import { KnowledgeGraph } from "@/components/agents/KnowledgeGraph";
import { RiskTrendSparkline } from "@/components/agents/RiskTrendSparkline";
import { getRiskLevel } from "@/types";
import { formatDate } from "@/lib/utils";
import type { AgentProfile, AgentGraphData } from "@/types";

function StatPill({ label, value, danger }: { label: string; value: string | number; danger?: boolean }) {
  return (
    <div className={`bg-[#0A1120] border rounded-lg p-3 text-center ${danger ? "border-red-900/20" : "border-[#1C2844]"}`}>
      <p className={`text-lg font-bold tabular-nums ${danger ? "text-[#F85149]" : "text-[#E6EDF3]"}`}>{value}</p>
      <p className="text-xs text-[#484F58] mt-0.5">{label}</p>
    </div>
  );
}

function RiskGauge({ score }: { score: number }) {
  const level = getRiskLevel(score);
  const colors: Record<string, { bg: string; text: string }> = {
    low:      { bg: "bg-[#3FB950]/10 border-[#3FB950]/20",  text: "text-[#3FB950]"  },
    medium:   { bg: "bg-[#D29922]/10 border-[#D29922]/20",  text: "text-[#D29922]" },
    high:     { bg: "bg-[#F85149]/10 border-[#F85149]/20",  text: "text-[#F85149]"  },
    critical: { bg: "bg-[#F85149]/15 border-[#F85149]/30",  text: "text-[#F85149]"  },
  };
  const { bg, text } = colors[level];
  return (
    <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border ${bg}`}>
      <span className={`text-2xl font-bold font-mono tabular-nums ${text}`}>
        {(score * 100).toFixed(1)}%
      </span>
      <span className={`text-xs font-medium uppercase tracking-wide ${text}`}>{level}</span>
    </div>
  );
}

interface AgentDetailPageProps {
  params: Promise<{ id: string }>;
}

export default async function AgentDetailPage({ params }: AgentDetailPageProps) {
  const { id } = await params;
  const agentId = decodeURIComponent(id);

  let profile: AgentProfile;
  let graph: AgentGraphData;

  try {
    [profile, graph] = await Promise.all([
      getAgent(agentId),
      getAgentGraph(agentId),
    ]);
  } catch {
    notFound();
  }

  const blockRate =
    profile.total_events > 0
      ? ((profile.blocked_events / profile.total_events) * 100).toFixed(1)
      : "0";

  return (
    <div className="space-y-5">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-[#484F58]">
        <Link href="/agents" className="hover:text-[#8B949E] transition-colors">
          Agents
        </Link>
        <span className="text-[#243354]">/</span>
        <span className="text-[#6E7D91] truncate max-w-xs">
          {profile.display_name || profile.agent_goal}
        </span>
      </div>

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className={`w-1.5 h-1.5 rounded-full ${profile.is_registered ? "bg-indigo-400" : "bg-[#3A4A5C]"}`} />
            <span className="text-xs text-[#484F58]">
              {profile.is_registered ? "Registered agent" : "Auto-detected agent"}
            </span>
            <span className="text-[#243354]">·</span>
            <span className="text-xs text-[#484F58] font-mono">{profile.framework}</span>
          </div>
          <h1 className="text-xl font-semibold text-[#E6EDF3] tracking-tight">
            {profile.display_name || profile.agent_goal}
          </h1>
          <p className="text-sm text-[#484F58] mt-0.5" title={profile.agent_goal}>
            {profile.agent_goal}
          </p>
          {profile.agent_id !== "legacy-unknown" && (
            <p className="text-xs text-[#3A4A5C] font-mono mt-0.5">{profile.agent_id}</p>
          )}
        </div>
        <RiskGauge score={profile.avg_risk_score} />
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-2.5">
        <StatPill label="Total Events" value={profile.total_events} />
        <StatPill label="Blocked" value={profile.blocked_events} danger={profile.blocked_events > 0} />
        <StatPill label="Reviewed" value={profile.reviewed_events} />
        <StatPill label="Allowed" value={profile.allowed_events} />
        <StatPill label="Block Rate" value={`${blockRate}%`} danger={parseFloat(blockRate) > 50} />
        <StatPill label="Sessions" value={profile.total_sessions} />
      </div>

      {/* First/Last seen */}
      <div className="grid grid-cols-2 gap-3">
        <div className="bg-[#0C1220] border border-[#1C2844] rounded-xl p-4">
          <p className="text-xs text-[#484F58] uppercase tracking-wider mb-1.5">First seen</p>
          <p className="font-medium text-[#A0AEBB] text-sm tabular-nums">{formatDate(profile.first_seen)}</p>
        </div>
        <div className="bg-[#0C1220] border border-[#1C2844] rounded-xl p-4">
          <p className="text-xs text-[#484F58] uppercase tracking-wider mb-1.5">Last seen</p>
          <p className="font-medium text-[#A0AEBB] text-sm tabular-nums">{formatDate(profile.last_seen)}</p>
        </div>
      </div>

      {/* Knowledge Graph */}
      <div className="bg-[#0C1220] border border-[#1C2844] rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-semibold text-[#E6EDF3]">Knowledge Graph</h2>
            <p className="text-xs text-[#484F58] mt-0.5">
              {graph.nodes.length} nodes · {graph.edges.length} edges
            </p>
          </div>
          <div className="flex gap-4 text-xs text-[#484F58]">
            {[
              { color: "bg-indigo-400", label: "agent" },
              { color: "bg-sky-400", label: "session" },
              { color: "bg-emerald-400", label: "tool" },
              { color: "bg-[#F85149]", label: "attack" },
            ].map(({ color, label }) => (
              <span key={label} className="flex items-center gap-1.5">
                <span className={`w-1.5 h-1.5 rounded-full ${color} inline-block`} />
                {label}
              </span>
            ))}
          </div>
        </div>
        <KnowledgeGraph data={graph} height={520} />
      </div>

      {/* Attack Patterns + Tools */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-[#0C1220] border border-[#1C2844] rounded-xl p-5">
          <h3 className="text-xs font-semibold text-[#6E7D91] uppercase tracking-wider mb-3">Attack Patterns</h3>
          {profile.attack_patterns.length === 0 ? (
            <p className="text-xs text-[#484F58]">None observed.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {profile.attack_patterns.map((p) => (
                <span key={p} className="text-xs px-2 py-1 bg-[#F85149]/8 text-[#F85149]/80 rounded border border-[#F85149]/15 font-mono">
                  {p.replace(/_/g, " ")}
                </span>
              ))}
            </div>
          )}
        </div>
        <div className="bg-[#0C1220] border border-[#1C2844] rounded-xl p-5">
          <h3 className="text-xs font-semibold text-[#6E7D91] uppercase tracking-wider mb-3">Tools Used</h3>
          {profile.tools_used.length === 0 ? (
            <p className="text-xs text-[#484F58]">None observed.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {profile.tools_used.map((t) => (
                <span key={t} className="text-xs px-2 py-1 bg-[#101828] text-[#8B949E] rounded border border-[#243354] font-mono">
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Risk trend */}
      {profile.risk_trend.length > 1 && (
        <RiskTrendSparkline trend={profile.risk_trend} />
      )}
    </div>
  );
}
