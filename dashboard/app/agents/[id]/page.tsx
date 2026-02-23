import { notFound } from "next/navigation";
import Link from "next/link";
import { getAgent, getAgentGraph } from "@/lib/api";
import { KnowledgeGraph } from "@/components/agents/KnowledgeGraph";
import { getRiskLevel } from "@/types";
import { formatDate } from "@/lib/utils";
import type { AgentProfile, AgentGraphData } from "@/types";

function StatPill({ label, value, danger }: { label: string; value: string | number; danger?: boolean }) {
  return (
    <div className="bg-gray-50 rounded-lg p-3 text-center">
      <p className={`text-lg font-bold ${danger ? "text-red-600" : "text-gray-900"}`}>{value}</p>
      <p className="text-xs text-gray-500 mt-0.5">{label}</p>
    </div>
  );
}

function RiskGauge({ score }: { score: number }) {
  const level = getRiskLevel(score);
  const colors: Record<string, { bg: string; text: string }> = {
    low:      { bg: "bg-green-100",  text: "text-green-700"  },
    medium:   { bg: "bg-yellow-100", text: "text-yellow-700" },
    high:     { bg: "bg-orange-100", text: "text-orange-700" },
    critical: { bg: "bg-red-100",    text: "text-red-700"    },
  };
  const { bg, text } = colors[level];
  return (
    <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg ${bg}`}>
      <span className={`text-2xl font-bold font-mono ${text}`}>
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
    <div className="space-y-6">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-gray-500">
        <Link href="/agents" className="hover:text-indigo-600 transition-colors">
          Agents
        </Link>
        <span>/</span>
        <span className="text-gray-700 truncate max-w-xs">{profile.agent_goal}</span>
      </div>

      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                profile.is_registered ? "bg-indigo-500" : "bg-gray-400"
              }`}
            />
            <span className="text-xs text-gray-500">
              {profile.is_registered ? "Registered agent" : "Auto-detected agent"}
            </span>
            <span className="text-xs text-gray-400">·</span>
            <span className="text-xs text-gray-500 font-mono">{profile.framework}</span>
          </div>
          <h1 className="text-2xl font-bold text-gray-900">{profile.agent_goal}</h1>
          {profile.agent_id !== "legacy-unknown" && (
            <p className="text-xs text-gray-400 font-mono mt-0.5">{profile.agent_id}</p>
          )}
        </div>
        <RiskGauge score={profile.avg_risk_score} />
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 sm:grid-cols-6 gap-3">
        <StatPill label="Total Events" value={profile.total_events} />
        <StatPill label="Blocked" value={profile.blocked_events} danger={profile.blocked_events > 0} />
        <StatPill label="Reviewed" value={profile.reviewed_events} />
        <StatPill label="Allowed" value={profile.allowed_events} />
        <StatPill label="Block Rate" value={`${blockRate}%`} danger={parseFloat(blockRate) > 50} />
        <StatPill label="Sessions" value={profile.total_sessions} />
      </div>

      {/* Timeline */}
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div className="bg-white border border-gray-200 rounded-xl p-4">
          <p className="text-xs text-gray-500 mb-1">First seen</p>
          <p className="font-medium text-gray-900">{formatDate(profile.first_seen)}</p>
        </div>
        <div className="bg-white border border-gray-200 rounded-xl p-4">
          <p className="text-xs text-gray-500 mb-1">Last seen</p>
          <p className="font-medium text-gray-900">{formatDate(profile.last_seen)}</p>
        </div>
      </div>

      {/* Knowledge Graph */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <div>
            <h2 className="text-base font-semibold text-gray-900">Knowledge Graph</h2>
            <p className="text-xs text-gray-500 mt-0.5">
              {graph.nodes.length} nodes · {graph.edges.length} edges
            </p>
          </div>
          <div className="flex gap-3 text-xs text-gray-500">
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-indigo-400 inline-block" /> agent
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-sky-400 inline-block" /> session
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" /> tool
            </span>
            <span className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full bg-red-400 inline-block" /> attack pattern
            </span>
          </div>
        </div>
        <KnowledgeGraph data={graph} height={520} />
      </div>

      {/* Attack Patterns + Tools */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-white border border-gray-200 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-gray-900 mb-3">Attack Patterns</h3>
          {profile.attack_patterns.length === 0 ? (
            <p className="text-xs text-gray-400">None observed.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {profile.attack_patterns.map((p) => (
                <span
                  key={p}
                  className="text-xs px-2 py-1 bg-red-50 text-red-600 rounded-lg font-mono border border-red-100"
                >
                  {p.replace(/_/g, " ")}
                </span>
              ))}
            </div>
          )}
        </div>

        <div className="bg-white border border-gray-200 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-gray-900 mb-3">Tools Used</h3>
          {profile.tools_used.length === 0 ? (
            <p className="text-xs text-gray-400">None observed.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {profile.tools_used.map((t) => (
                <span
                  key={t}
                  className="text-xs px-2 py-1 bg-gray-50 text-gray-700 rounded-lg font-mono border border-gray-200"
                >
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Risk trend */}
      {profile.risk_trend.length > 1 && (
        <div className="bg-white border border-gray-200 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-gray-900 mb-3">Risk Trend (last {profile.risk_trend.length} events)</h3>
          <div className="flex items-end gap-1 h-16">
            {profile.risk_trend.map((v, i) => {
              const level = getRiskLevel(v);
              const barColors: Record<string, string> = {
                low:      "bg-green-300",
                medium:   "bg-yellow-300",
                high:     "bg-orange-400",
                critical: "bg-red-500",
              };
              return (
                <div
                  key={i}
                  className={`flex-1 rounded-sm ${barColors[level]}`}
                  style={{ height: `${Math.max(v * 100, 4)}%` }}
                  title={`${(v * 100).toFixed(1)}%`}
                />
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
