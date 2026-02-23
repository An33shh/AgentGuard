import { notFound } from "next/navigation";
import Link from "next/link";
import { getEvent } from "@/lib/api";
import { getRiskLevel, getRiskColor, getDecisionColor } from "@/types";
import { formatDate } from "@/lib/utils";

interface Props {
  params: Promise<{ id: string }>;
}

function RiskGauge({ score }: { score: number }) {
  const level = getRiskLevel(score);
  const color = getRiskColor(level);
  const barColors: Record<string, string> = {
    low: "bg-green-500",
    medium: "bg-yellow-500",
    high: "bg-orange-500",
    critical: "bg-red-500",
  };

  return (
    <div className="flex flex-col items-center gap-2">
      <div className={`text-4xl font-bold ${color}`}>
        {(score * 100).toFixed(1)}%
      </div>
      <div className="w-full h-2 bg-gray-100 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${barColors[level]} transition-all`}
          style={{ width: `${score * 100}%` }}
        />
      </div>
      <span className={`text-sm font-medium uppercase tracking-wide ${color}`}>
        {level} risk
      </span>
    </div>
  );
}

export default async function EventDetailPage({ params }: Props) {
  const { id } = await params;

  // `.catch(() => null)` lets notFound() short-circuit while keeping TypeScript happy
  const event = await getEvent(id).catch(() => null);
  if (!event) notFound();

  const decisionStyle = getDecisionColor(event.decision);

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-center gap-3">
        <Link href="/events" className="text-sm text-gray-500 hover:text-gray-700">
          ← Events
        </Link>
        <span className="text-gray-300">/</span>
        <span className="text-sm font-mono text-gray-600">{event.event_id.slice(0, 16)}…</span>
      </div>

      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Forensic Investigation</h1>
        <span className={`px-3 py-1 rounded-full text-sm font-medium ${decisionStyle}`}>
          {event.decision.toUpperCase()}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Risk Assessment */}
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
          <h2 className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-4">
            Risk Assessment
          </h2>
          <RiskGauge score={event.assessment.risk_score} />
          <p className="text-sm text-gray-600 mt-4 text-center">
            {event.assessment.reason}
          </p>
          {event.assessment.indicators.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-3 justify-center">
              {event.assessment.indicators.map((ind) => (
                <span key={ind} className="text-xs bg-gray-100 text-gray-600 px-2 py-0.5 rounded-full">
                  {ind}
                </span>
              ))}
            </div>
          )}
          <p className="text-xs text-gray-400 text-center mt-3">
            Model: {event.assessment.analyzer_model} · {event.assessment.latency_ms.toFixed(0)}ms
          </p>
        </div>

        {/* Action Panel */}
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
          <h2 className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-4">
            Action
          </h2>
          <dl className="space-y-3 text-sm">
            {[
              ["Tool", event.action.tool_name],
              ["Type", event.action.type],
              ["Framework", event.framework],
              ["Session", event.session_id],
              ["Timestamp", formatDate(event.timestamp)],
            ].map(([label, value]) => (
              <div key={label}>
                <dt className="text-xs text-gray-400 uppercase tracking-wide">{label}</dt>
                <dd className="font-mono text-gray-800 mt-0.5 break-all">{value}</dd>
              </div>
            ))}
          </dl>
        </div>

        {/* Policy Panel */}
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
          <h2 className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-4">
            Policy
          </h2>
          {event.policy_violation ? (
            <dl className="space-y-3 text-sm">
              {[
                ["Rule", event.policy_violation.rule_name],
                ["Type", event.policy_violation.rule_type],
                ["Detail", event.policy_violation.detail],
                ["Goal Aligned", event.assessment.is_goal_aligned ? "Yes" : "No"],
              ].map(([label, value]) => (
                <div key={label}>
                  <dt className="text-xs text-gray-400 uppercase tracking-wide">{label}</dt>
                  <dd className="text-gray-800 mt-0.5 break-all">{value}</dd>
                </div>
              ))}
            </dl>
          ) : (
            <div className="space-y-3 text-sm">
              <p className="text-gray-500">No policy rule triggered.</p>
              <dl>
                <div>
                  <dt className="text-xs text-gray-400 uppercase tracking-wide">Goal Aligned</dt>
                  <dd className="text-gray-800 mt-0.5">
                    {event.assessment.is_goal_aligned ? "Yes" : "No"}
                  </dd>
                </div>
              </dl>
            </div>
          )}

          <div className="mt-4 pt-4 border-t border-gray-100">
            <p className="text-xs text-gray-400 uppercase tracking-wide mb-2">Agent Goal</p>
            <p className="text-sm text-gray-700 italic">&ldquo;{event.agent_goal}&rdquo;</p>
          </div>
        </div>
      </div>

      {/* Parameters */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
        <h2 className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-3">
          Action Parameters
        </h2>
        <pre className="bg-gray-50 rounded-lg p-4 text-xs font-mono text-gray-800 overflow-auto max-h-64">
          {JSON.stringify(event.action.parameters, null, 2)}
        </pre>
      </div>

      {/* Raw Event JSON */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
        <h2 className="text-sm font-semibold text-gray-500 uppercase tracking-wide mb-3">
          Raw Event
        </h2>
        <pre className="bg-gray-50 rounded-lg p-4 text-xs font-mono text-gray-800 overflow-auto max-h-96">
          {JSON.stringify(event, null, 2)}
        </pre>
      </div>
    </div>
  );
}
