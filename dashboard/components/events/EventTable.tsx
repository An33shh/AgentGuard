"use client";

import { useMemo, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import type { Event, Decision } from "@/types";
import { getRiskLevel } from "@/types";
import { formatDate } from "@/lib/utils";
import { searchEvents } from "@/lib/api";

const DECISIONS: Decision[] = ["block", "review", "allow"];

function DecisionBadge({ decision }: { decision: Decision }) {
  const styles: Record<Decision, string> = {
    block: "bg-[#F85149]/10 text-[#F85149] border-[#F85149]/20",
    review: "bg-[#D29922]/10 text-[#D29922] border-[#D29922]/20",
    allow: "bg-[#3FB950]/10 text-[#3FB950] border-[#3FB950]/20",
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded font-medium border ${styles[decision]}`}>
      {decision.toUpperCase()}
    </span>
  );
}

function RiskCell({ score }: { score: number }) {
  const level = getRiskLevel(score);
  const color: Record<string, string> = {
    low: "text-[#3FB950]",
    medium: "text-[#D29922]",
    high: "text-[#F85149]",
    critical: "text-[#F85149] font-semibold",
  };
  return (
    <span className={`font-mono text-sm tabular-nums ${color[level]}`}>
      {(score * 100).toFixed(1)}%
    </span>
  );
}

interface EventTableProps {
  initialEvents: Event[];
}

export function EventTable({ initialEvents }: EventTableProps) {
  const router = useRouter();
  const [decisionFilter, setDecisionFilter] = useState<Decision | "">("");
  const [minRisk, setMinRisk] = useState<string>("");
  const [search, setSearch] = useState<string>("");
  const [searchResults, setSearchResults] = useState<Event[] | null>(null);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  const isServerSearch = searchResults !== null;
  const baseEvents = isServerSearch ? searchResults : initialEvents;

  const filtered = useMemo(() => {
    const minRiskValue = minRisk === "" ? NaN : parseFloat(minRisk);
    return baseEvents.filter((e) => {
      if (decisionFilter && e.decision !== decisionFilter) return false;
      if (!isNaN(minRiskValue) && e.assessment.risk_score < minRiskValue / 100) return false;
      if (!isServerSearch && search) {
        const q = search.toLowerCase();
        return (
          e.action.tool_name.toLowerCase().includes(q) ||
          e.assessment.reason.toLowerCase().includes(q) ||
          e.session_id.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [baseEvents, decisionFilter, minRisk, search, isServerSearch]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const q = search.trim();
    if (!q) {
      setSearchResults(null);
      setSearchError(null);
      return;
    }
    startTransition(async () => {
      setSearchError(null);
      try {
        const data = await searchEvents(q, 200);
        setSearchResults(data);
      } catch (err) {
        setSearchError(err instanceof Error ? err.message : "Search failed");
        setSearchResults(null);
      }
    });
  };

  const handleClear = () => {
    setSearch("");
    setSearchResults(null);
    setSearchError(null);
  };

  const inputClass =
    "bg-[#141F33] border border-[#1C2844] rounded-lg px-3 py-2 text-sm text-[#A0AEBB] placeholder-[#3A4A5C] focus:outline-none focus:ring-1 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-colors";

  return (
    <div className="space-y-4">
      {/* Filters */}
      <form onSubmit={handleSearch} className="flex flex-wrap gap-2 items-center">
        <div className="relative flex-1 min-w-48">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-[#484F58] pointer-events-none">
            <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
              <path d="M10.442 10.442a1 1 0 0 1 1.415 0l3.85 3.85a1 1 0 0 1-1.414 1.415l-3.85-3.85a1 1 0 0 1 0-1.415z"/>
              <path d="M6.5 12a5.5 5.5 0 1 0 0-11 5.5 5.5 0 0 0 0 11zM13 6.5C13 10.09 10.09 13 6.5 13S0 10.09 0 6.5 2.91 0 6.5 0 13 2.91 13 6.5z"/>
            </svg>
          </span>
          <input
            type="text"
            placeholder="Search tools, reasons, sessions…"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              if (!e.target.value.trim()) {
                setSearchResults(null);
                setSearchError(null);
              }
            }}
            className={`${inputClass} w-full pl-8`}
          />
        </div>
        <button
          type="submit"
          disabled={isPending || !search.trim()}
          className="px-3 py-2 rounded-lg bg-indigo-600/80 text-white text-xs font-medium hover:bg-indigo-500 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
        >
          {isPending ? "…" : "Search"}
        </button>
        {isServerSearch && (
          <button
            type="button"
            onClick={handleClear}
            className="px-3 py-2 rounded-lg border border-[#1C2844] text-[#6E7D91] text-xs hover:text-[#A0AEBB] hover:border-[#2C3854] transition-colors"
          >
            Clear
          </button>
        )}
        <select
          value={decisionFilter}
          onChange={(e) => setDecisionFilter(e.target.value as Decision | "")}
          className={`${inputClass} bg-[#141F33]`}
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
          className={`${inputClass} w-28`}
        />
        <div className="flex items-center gap-2 text-xs text-[#484F58] tabular-nums">
          <span>{filtered.length} events</span>
          {isServerSearch && (
            <span className="px-1.5 py-0.5 rounded bg-indigo-600/15 text-indigo-400 border border-indigo-600/20 font-mono">
              fulltext
            </span>
          )}
        </div>
      </form>

      {searchError && (
        <div className="bg-[#F85149]/8 border border-[#F85149]/20 rounded-xl p-3 text-sm text-[#F85149]">
          Search error: {searchError}
        </div>
      )}

      {/* Table */}
      <div className="bg-[#0C1220] border border-[#1C2844] rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-[#0A1120] border-b border-[#1C2844]">
              <th className="text-left px-4 py-3 text-xs font-medium text-[#6E7D91] uppercase tracking-wider">Tool</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-[#6E7D91] uppercase tracking-wider">Decision</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-[#6E7D91] uppercase tracking-wider">Risk</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-[#6E7D91] uppercase tracking-wider hidden md:table-cell">Session</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-[#6E7D91] uppercase tracking-wider hidden lg:table-cell">Reason</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-[#6E7D91] uppercase tracking-wider">Time</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1C2844]">
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="text-center py-12 text-[#484F58] text-sm">
                  No events match your filters.
                </td>
              </tr>
            )}
            {filtered.map((event) => (
              <tr
                key={event.event_id}
                onClick={() => router.push(`/events/${event.event_id}`)}
                className="hover:bg-[#0E1625] cursor-pointer transition-colors group"
              >
                <td className="px-4 py-3 font-mono font-medium text-[#A0AEBB] group-hover:text-[#E6EDF3] transition-colors">
                  {event.action.tool_name}
                </td>
                <td className="px-4 py-3">
                  <DecisionBadge decision={event.decision} />
                </td>
                <td className="px-4 py-3">
                  <RiskCell score={event.assessment.risk_score} />
                </td>
                <td className="px-4 py-3 hidden md:table-cell text-[#484F58] font-mono text-xs">
                  <span title={event.session_id}>
                    {event.session_id.slice(0, 14)}…
                  </span>
                </td>
                <td className="px-4 py-3 hidden lg:table-cell text-[#6E7D91] max-w-xs truncate text-xs">
                  {event.assessment.reason}
                </td>
                <td className="px-4 py-3 text-[#484F58] text-xs whitespace-nowrap tabular-nums">
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
