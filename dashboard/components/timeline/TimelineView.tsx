"use client";

import Link from "next/link";
import type { Event } from "@/types";
import { getRiskLevel } from "@/types";
import { formatDate } from "@/lib/utils";

function DecisionIcon({ decision }: { decision: string }) {
  if (decision === "block") {
    return <div className="w-8 h-8 rounded-full bg-red-100 flex items-center justify-center">
      <svg className="w-4 h-4 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
      </svg>
    </div>;
  }
  if (decision === "review") {
    return <div className="w-8 h-8 rounded-full bg-yellow-100 flex items-center justify-center">
      <svg className="w-4 h-4 text-yellow-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    </div>;
  }
  return <div className="w-8 h-8 rounded-full bg-green-100 flex items-center justify-center">
    <svg className="w-4 h-4 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
    </svg>
  </div>;
}

function RiskBar({ score }: { score: number }) {
  const level = getRiskLevel(score);
  const colors: Record<string, string> = {
    low: "bg-green-500",
    medium: "bg-yellow-500",
    high: "bg-orange-500",
    critical: "bg-red-500",
  };
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${colors[level]}`}
          style={{ width: `${score * 100}%` }}
        />
      </div>
      <span className="text-xs font-mono text-gray-600 w-10 text-right">
        {(score * 100).toFixed(0)}%
      </span>
    </div>
  );
}

export function TimelineView({ events }: { events: Event[] }) {
  if (events.length === 0) {
    return (
      <div className="text-center py-16 text-gray-400">
        <p className="text-lg">No events in timeline.</p>
        <p className="text-sm mt-1">Run the demo to populate data.</p>
      </div>
    );
  }

  return (
    <div className="relative">
      {/* Vertical line */}
      <div className="absolute left-3.5 top-4 bottom-4 w-0.5 bg-gray-200" />

      <ul className="space-y-4">
        {events.map((event) => (
          <li key={event.event_id} className="relative flex gap-4">
            {/* Icon */}
            <div className="shrink-0 z-10">
              <DecisionIcon decision={event.decision} />
            </div>

            {/* Card */}
            <Link
              href={`/events/${event.event_id}`}
              className="flex-1 bg-white border border-gray-200 rounded-xl p-4 hover:border-indigo-300 hover:shadow-sm transition-all"
            >
              <div className="flex items-start justify-between gap-2 mb-2">
                <div>
                  <span className="font-mono text-sm font-semibold text-gray-900">
                    {event.action.tool_name}
                  </span>
                  <span className={`ml-2 text-xs px-2 py-0.5 rounded-full font-medium ${
                    event.decision === "block" ? "bg-red-100 text-red-700" :
                    event.decision === "review" ? "bg-yellow-100 text-yellow-700" :
                    "bg-green-100 text-green-700"
                  }`}>
                    {event.decision.toUpperCase()}
                  </span>
                </div>
                <span className="text-xs text-gray-400 shrink-0">
                  {formatDate(event.timestamp)}
                </span>
              </div>

              <RiskBar score={event.assessment.risk_score} />

              <p className="text-xs text-gray-600 mt-2 line-clamp-2">
                {event.assessment.reason}
              </p>

              {event.assessment.indicators.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {event.assessment.indicators.slice(0, 3).map((ind) => (
                    <span key={ind} className="text-xs bg-gray-100 text-gray-600 px-2 py-0.5 rounded">
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
