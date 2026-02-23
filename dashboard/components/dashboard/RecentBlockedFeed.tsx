"use client";

import Link from "next/link";
import type { Event } from "@/types";
import { getRiskLevel } from "@/types";
import { timeAgo } from "@/lib/utils";

function RiskBadge({ score }: { score: number }) {
  const level = getRiskLevel(score);
  const colors: Record<string, string> = {
    low: "bg-green-100 text-green-800",
    medium: "bg-yellow-100 text-yellow-800",
    high: "bg-orange-100 text-orange-800",
    critical: "bg-red-100 text-red-800",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${colors[level]}`}>
      {(score * 100).toFixed(0)}%
    </span>
  );
}

export function RecentBlockedFeed({ events }: { events: Event[] }) {
  if (events.length === 0) {
    return (
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
        <h3 className="text-base font-semibold text-gray-900 mb-4">Recent Blocked Actions</h3>
        <p className="text-sm text-gray-500">No blocked actions yet.</p>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm">
      <div className="px-6 py-4 border-b border-gray-100">
        <h3 className="text-base font-semibold text-gray-900">Recent Blocked Actions</h3>
      </div>
      <ul className="divide-y divide-gray-50">
        {events.slice(0, 8).map((event) => (
          <li key={event.event_id} className="px-6 py-3 hover:bg-gray-50 transition-colors">
            <Link href={`/events/${event.event_id}`} className="flex items-start gap-3">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm font-medium text-gray-800 truncate">
                    {event.action.tool_name}
                  </span>
                  <RiskBadge score={event.assessment.risk_score} />
                </div>
                <p className="text-xs text-gray-500 mt-0.5 truncate">
                  {event.assessment.reason}
                </p>
                <p className="text-xs text-gray-400 mt-0.5">
                  {timeAgo(event.timestamp)} · {event.session_id.slice(0, 12)}…
                </p>
              </div>
              <span className="text-red-500 text-xs font-medium shrink-0 mt-0.5">BLOCKED</span>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
