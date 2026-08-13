import Link from "next/link";
import type { Decision, Event, Insight } from "@/types";
import { formatDate } from "@/lib/utils";
import { SeverityBadge } from "@/components/ui/SeverityBadge";

const DECISION_STYLES: Record<Decision, string> = {
  block: "bg-[#F85149]/10 text-[#F85149] border-[#F85149]/20",
  review: "bg-[#D29922]/10 text-[#D29922] border-[#D29922]/20",
  allow: "bg-[#3FB950]/10 text-[#3FB950] border-[#3FB950]/20",
};

export function InsightRow({ insight, event }: { insight: Insight; event: Event | null }) {
  const fpPct = Math.round(insight.false_positive_likelihood * 100);
  // Lower false-positive likelihood = higher confidence this is a real
  // attack, so the bar reads inversely: a short, red-leaning bar means
  // "very likely a real positive", a long amber bar means "probably noise".
  const fpColor = fpPct >= 60 ? "#D29922" : fpPct >= 30 ? "#6E7D91" : "#F85149";

  return (
    <div className="bg-[#0C1220] border border-[#1C2844] rounded-xl p-4 space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={insight.severity} />
        {event && (
          <span className={`text-xs px-2 py-0.5 rounded font-medium border ${DECISION_STYLES[event.decision]}`}>
            {event.decision.toUpperCase()}
          </span>
        )}
        {event && (
          <span className="font-mono text-xs text-[#A0AEBB]">{event.action.tool_name}</span>
        )}
        <span className="text-xs text-[#3A4A5C] ml-auto">{formatDate(insight.created_at)}</span>
      </div>

      <p className="text-sm text-[#A0AEBB] leading-relaxed">{insight.analysis}</p>

      {insight.attack_patterns.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {insight.attack_patterns.map((p) => (
            <span
              key={p}
              className="text-xs px-2 py-0.5 bg-[#F85149]/8 text-[#F85149]/80 rounded border border-[#F85149]/15 font-mono"
            >
              {p.replace(/_/g, " ")}
            </span>
          ))}
        </div>
      )}

      <div className="flex items-center gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between text-xs text-[#6E7D91] mb-1">
            <span>False-positive likelihood</span>
            <span className="tabular-nums">{fpPct}%</span>
          </div>
          <div className="h-1.5 rounded-full bg-[#1C2844] overflow-hidden">
            <div
              className="h-full rounded-full"
              style={{ width: `${fpPct}%`, backgroundColor: fpColor }}
            />
          </div>
        </div>
      </div>

      <p className="text-xs text-[#6E7D91]">
        <span className="text-[#484F58] uppercase tracking-wide mr-1.5">Recommended:</span>
        {insight.recommended_action}
      </p>

      {!event && (
        <p className="text-xs text-[#484F58] italic">Event details unavailable</p>
      )}

      <Link
        href={`/events/${insight.event_id}`}
        className="inline-block text-xs font-medium text-indigo-400 hover:text-indigo-300 transition-colors"
      >
        View full event →
      </Link>
    </div>
  );
}
