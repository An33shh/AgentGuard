"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import type { Event, Decision } from "@/types";
import { getRiskLevel } from "@/types";
import { formatDate } from "@/lib/utils";

const DECISIONS: Decision[] = ["block", "review", "allow"];

function DecisionBadge({ decision }: { decision: Decision }) {
  const styles: Record<Decision, string> = {
    block: "bg-red-100 text-red-700",
    review: "bg-yellow-100 text-yellow-700",
    allow: "bg-green-100 text-green-700",
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${styles[decision]}`}>
      {decision.toUpperCase()}
    </span>
  );
}

function RiskCell({ score }: { score: number }) {
  const level = getRiskLevel(score);
  const color: Record<string, string> = {
    low: "text-green-600",
    medium: "text-yellow-600",
    high: "text-orange-600",
    critical: "text-red-600 font-semibold",
  };
  return (
    <span className={`font-mono text-sm ${color[level]}`}>
      {(score * 100).toFixed(1)}%
    </span>
  );
}

interface EventTableProps {
  events: Event[];
}

export function EventTable({ events }: EventTableProps) {
  const router = useRouter();
  const [decisionFilter, setDecisionFilter] = useState<Decision | "">("");
  const [minRisk, setMinRisk] = useState<string>("");
  const [search, setSearch] = useState<string>("");

  const filtered = useMemo(() => {
    const minRiskValue = minRisk === "" ? NaN : parseFloat(minRisk);
    return events.filter((e) => {
      if (decisionFilter && e.decision !== decisionFilter) return false;
      if (!isNaN(minRiskValue) && e.assessment.risk_score < minRiskValue / 100) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          e.action.tool_name.toLowerCase().includes(q) ||
          e.assessment.reason.toLowerCase().includes(q) ||
          e.session_id.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [events, decisionFilter, minRisk, search]);

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input
          type="text"
          placeholder="Search tools, reasons, sessions…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="border border-gray-200 rounded-lg px-3 py-2 text-sm flex-1 min-w-48 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
        <select
          value={decisionFilter}
          onChange={(e) => setDecisionFilter(e.target.value as Decision | "")}
          className="border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          <option value="">All Decisions</option>
          {DECISIONS.map((d) => (
            <option key={d} value={d}>{d.toUpperCase()}</option>
          ))}
        </select>
        <input
          type="number"
          placeholder="Min risk %"
          value={minRisk}
          onChange={(e) => setMinRisk(e.target.value)}
          min={0}
          max={100}
          className="border border-gray-200 rounded-lg px-3 py-2 text-sm w-32 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
        <span className="text-sm text-gray-500 self-center">{filtered.length} events</span>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-100">
              <th className="text-left px-4 py-3 font-medium text-gray-600">Tool</th>
              <th className="text-left px-4 py-3 font-medium text-gray-600">Decision</th>
              <th className="text-left px-4 py-3 font-medium text-gray-600">Risk</th>
              <th className="text-left px-4 py-3 font-medium text-gray-600 hidden md:table-cell">Session</th>
              <th className="text-left px-4 py-3 font-medium text-gray-600 hidden lg:table-cell">Reason</th>
              <th className="text-left px-4 py-3 font-medium text-gray-600">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="text-center py-8 text-gray-400">No events match your filters.</td>
              </tr>
            )}
            {filtered.map((event) => (
              <tr
                key={event.event_id}
                onClick={() => router.push(`/events/${event.event_id}`)}
                className="hover:bg-gray-50 cursor-pointer transition-colors"
              >
                <td className="px-4 py-3 font-mono font-medium text-gray-900">
                  {event.action.tool_name}
                </td>
                <td className="px-4 py-3">
                  <DecisionBadge decision={event.decision} />
                </td>
                <td className="px-4 py-3">
                  <RiskCell score={event.assessment.risk_score} />
                </td>
                <td className="px-4 py-3 hidden md:table-cell text-gray-500 font-mono text-xs">
                  <span title={event.session_id}>
                    {event.session_id.slice(0, 12)}…
                  </span>
                </td>
                <td className="px-4 py-3 hidden lg:table-cell text-gray-500 max-w-xs truncate">
                  {event.assessment.reason}
                </td>
                <td className="px-4 py-3 text-gray-400 text-xs whitespace-nowrap">
                  {formatDate(event.timestamp)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
