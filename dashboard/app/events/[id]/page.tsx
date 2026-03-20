import { notFound } from "next/navigation";
import Link from "next/link";
import { getEvent } from "@/lib/api";
import { getRiskLevel } from "@/types";
import { formatDate } from "@/lib/utils";
import { ProvenancePanel } from "@/components/events/ProvenancePanel";
import { ThreatTaxonomyPanel } from "@/components/events/ThreatTaxonomyPanel";

interface Props {
  params: Promise<{ id: string }>;
}

function RiskGauge({ score }: { score: number }) {
  const level = getRiskLevel(score);
  const colors: Record<string, { text: string; bar: string }> = {
    low:      { text: "text-[#3FB950]", bar: "bg-[#3FB950]" },
    medium:   { text: "text-[#D29922]", bar: "bg-[#D29922]" },
    high:     { text: "text-[#F85149]", bar: "bg-[#F85149]" },
    critical: { text: "text-[#F85149]", bar: "bg-[#F85149]" },
  };
  const { text, bar } = colors[level];

  return (
    <div className="flex flex-col items-center gap-2">
      <div className={`text-4xl font-bold font-mono tabular-nums ${text}`}>
        {(score * 100).toFixed(1)}%
      </div>
      <div className="w-full h-1.5 bg-[#1C2844] rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${bar} transition-all`} style={{ width: `${score * 100}%` }} />
      </div>
      <span className={`text-xs font-medium uppercase tracking-widest ${text}`}>
        {level} risk
      </span>
    </div>
  );
}

function formatActionType(raw: string): string {
  return raw.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="bg-[#0C1220] rounded-xl border border-[#1C2844] p-6">
      <h2 className="text-xs font-semibold text-[#6E7D91] uppercase tracking-wider mb-5">{title}</h2>
      {children}
    </div>
  );
}

function Field({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <dt className="text-xs text-[#484F58] uppercase tracking-wider">{label}</dt>
      <dd className={`mt-0.5 break-all text-sm text-[#A0AEBB] ${mono ? "font-mono" : ""}`}>{value}</dd>
    </div>
  );
}

export default async function EventDetailPage({ params }: Props) {
  const { id } = await params;
  const event = await getEvent(id).catch(() => null);
  if (!event) notFound();

  const showGoalAligned = event.assessment.analyzer_model !== "policy_engine";

  const decisionColors: Record<string, string> = {
    block: "bg-[#F85149]/10 text-[#F85149] border border-[#F85149]/20",
    review: "bg-[#D29922]/10 text-[#D29922] border border-[#D29922]/20",
    allow: "bg-[#3FB950]/10 text-[#3FB950] border border-[#3FB950]/20",
  };

  return (
    <div className="space-y-5 max-w-4xl">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm text-[#484F58]">
        <Link href="/events" className="hover:text-[#8B949E] transition-colors">
          Events
        </Link>
        <span className="text-[#243354]">/</span>
        <span className="text-[#6E7D91] font-mono">{event.event_id.slice(0, 16)}…</span>
      </div>

      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-[#E6EDF3] tracking-tight">Forensic Investigation</h1>
        <span className={`px-3 py-1 rounded-full text-xs font-semibold ${decisionColors[event.decision]}`}>
          {event.decision.toUpperCase()}
        </span>
      </div>

      {/* Three-panel row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Risk Assessment */}
        <Panel title="Risk Assessment">
          <RiskGauge score={event.assessment.risk_score} />
          <p className="text-xs text-[#6E7D91] mt-4 text-center leading-relaxed">
            {event.assessment.reason}
          </p>
          {event.assessment.indicators.length > 0 && (
            <div className="flex flex-wrap gap-1.5 mt-3 justify-center">
              {event.assessment.indicators.map((ind) => (
                <span key={ind} className="text-xs bg-[#101828] text-[#6E7D91] border border-[#243354] px-2 py-0.5 rounded font-mono">
                  {ind}
                </span>
              ))}
            </div>
          )}
          <p className="text-xs text-[#3A4A5C] text-center mt-3 tabular-nums">
            {event.assessment.analyzer_model} · {event.assessment.latency_ms.toFixed(0)}ms
          </p>
        </Panel>

        {/* Action */}
        <Panel title="Action">
          <dl className="space-y-3.5">
            <Field label="Tool" value={event.action.tool_name} mono />
            <Field label="Type" value={formatActionType(event.action.type)} />
            <Field label="Framework" value={event.framework} />
            <Field label="Session" value={event.session_id} mono />
            <Field label="Timestamp" value={formatDate(event.timestamp)} />
          </dl>
        </Panel>

        {/* Policy */}
        <Panel title="Policy">
          {event.policy_violation ? (
            <dl className="space-y-3.5">
              <Field label="Rule" value={event.policy_violation.rule_name} mono />
              <Field label="Type" value={event.policy_violation.rule_type} mono />
              <Field label="Detail" value={event.policy_violation.detail} />
              {showGoalAligned && (
                <Field label="Goal Aligned" value={event.assessment.is_goal_aligned ? "Yes" : "No"} />
              )}
            </dl>
          ) : (
            <div className="space-y-3.5">
              <p className="text-sm text-[#484F58]">No policy rule triggered.</p>
              {showGoalAligned && (
                <dl>
                  <Field label="Goal Aligned" value={event.assessment.is_goal_aligned ? "Yes" : "No"} />
                </dl>
              )}
            </div>
          )}
          <div className="mt-5 pt-4 border-t border-[#1C2844]">
            <p className="text-xs text-[#484F58] uppercase tracking-wider mb-1.5">Agent Goal</p>
            <p className="text-sm text-[#8B949E] italic">&ldquo;{event.agent_goal}&rdquo;</p>
          </div>
        </Panel>
      </div>

      {/* Parameters */}
      <div className="bg-[#0C1220] rounded-xl border border-[#1C2844] p-6">
        <h2 className="text-xs font-semibold text-[#6E7D91] uppercase tracking-wider mb-3">
          Action Parameters
        </h2>
        <pre className="bg-[#070B14] border border-[#1C2844] rounded-lg p-4 text-xs font-mono text-[#8B949E] overflow-auto max-h-64 leading-relaxed">
          {JSON.stringify(event.action.parameters, null, 2)}
        </pre>
      </div>

      {/* Provenance */}
      {event.provenance.length > 0 && <ProvenancePanel tags={event.provenance} />}

      {/* Threat Intelligence */}
      <ThreatTaxonomyPanel event={event} />

      {/* Raw Event */}
      <div className="bg-[#0C1220] rounded-xl border border-[#1C2844] p-6">
        <h2 className="text-xs font-semibold text-[#6E7D91] uppercase tracking-wider mb-3">
          Raw Event
        </h2>
        <pre className="bg-[#070B14] border border-[#1C2844] rounded-lg p-4 text-xs font-mono text-[#484F58] overflow-auto max-h-96 leading-relaxed">
          {JSON.stringify(event, null, 2)}
        </pre>
      </div>
    </div>
  );
}
