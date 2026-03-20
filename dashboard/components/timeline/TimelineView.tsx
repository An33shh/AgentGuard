"use client";

import Link from "next/link";
import type { Event } from "@/types";
import { getRiskLevel } from "@/types";
import { formatDate } from "@/lib/utils";

function DecisionIcon({ decision }: { decision: string }) {
  if (decision === "block") {
    return (
      <div className="w-7 h-7 rounded-full bg-[#F85149]/15 border border-[#F85149]/25 flex items-center justify-center shrink-0">
        <svg className="w-3.5 h-3.5 text-[#F85149]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </div>
    );
  }
  if (decision === "review") {
    return (
      <div className="w-7 h-7 rounded-full bg-[#D29922]/15 border border-[#D29922]/25 flex items-center justify-center shrink-0">
        <svg className="w-3.5 h-3.5 text-[#D29922]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01" />
        </svg>
      </div>
    );
  }
  return (
    <div className="w-7 h-7 rounded-full bg-[#3FB950]/15 border border-[#3FB950]/25 flex items-center justify-center shrink-0">
      <svg className="w-3.5 h-3.5 text-[#3FB950]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
      </svg>
    </div>
  );
}

function RiskBar({ score }: { score: number }) {
  const level = getRiskLevel(score);
  const colors: Record<string, string> = {
    low: "bg-[#3FB950]",
    medium: "bg-[#D29922]",
    high: "bg-[#F85149]",
    critical: "bg-[#F85149]",
  };
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1 bg-[#1C2844] rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${colors[level]}`} style={{ width: `${score * 100}%` }} />
      </div>
      <span className="text-xs font-mono text-[#6E7D91] w-10 text-right tabular-nums">
        {(score * 100).toFixed(0)}%
      </span>
    </div>
  );
}

export function TimelineView({ events }: { events: Event[] }) {
  if (events.length === 0) {
    return (
      <div className="text-center py-20 text-[#484F58]">
        <p>No events in this session.</p>
        <p className="text-sm mt-1 text-[#3A4A5C]">Select a different session or run the demo.</p>
      </div>
    );
  }

  return (
    <div className="relative">
      {/* Vertical connector line */}
      <div className="absolute left-3 top-4 bottom-4 w-px bg-[#1C2844]" />

      <ul className="space-y-3">
        {events.map((event) => (
          <li key={event.event_id} className="relative flex gap-4">
            <div className="shrink-0 z-10 mt-0.5">
              <DecisionIcon decision={event.decision} />
            </div>

            <Link
              href={`/events/${event.event_id}`}
              className="flex-1 bg-[#0C1220] border border-[#1C2844] rounded-xl p-4 hover:bg-[#0E1625] hover:border-[#243354] transition-colors"
            >
              <div className="flex items-start justify-between gap-2 mb-3">
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-sm font-semibold text-[#A0AEBB]">
                    {event.action.tool_name}
                  </span>
                  <span className={`text-xs px-1.5 py-0.5 rounded border font-medium ${
                    event.decision === "block"
                      ? "bg-[#F85149]/10 text-[#F85149] border-[#F85149]/20"
                      : event.decision === "review"
                      ? "bg-[#D29922]/10 text-[#D29922] border-[#D29922]/20"
                      : "bg-[#3FB950]/10 text-[#3FB950] border-[#3FB950]/20"
                  }`}>
                    {event.decision.toUpperCase()}
                  </span>
                </div>
                <span className="text-xs text-[#484F58] shrink-0 tabular-nums">
                  {formatDate(event.timestamp)}
                </span>
              </div>

              <RiskBar score={event.assessment.risk_score} />

              <p className="text-xs text-[#6E7D91] mt-2.5 leading-relaxed line-clamp-2">
                {event.assessment.reason}
              </p>

              {event.assessment.indicators.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2.5">
                  {event.assessment.indicators.slice(0, 3).map((ind) => (
                    <span key={ind} className="text-xs bg-[#101828] text-[#6E7D91] border border-[#243354] px-2 py-0.5 rounded font-mono">
                      {ind}
                    </span>
                  ))}
                </div>
              )}
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
