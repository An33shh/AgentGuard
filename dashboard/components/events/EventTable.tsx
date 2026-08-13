"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import type { Event, Decision } from "@/types";
import { getRiskLevel } from "@/types";
import { formatDate } from "@/lib/utils";
import { getEvents, searchEvents } from "@/lib/api";
import type { EventsFilter } from "@/lib/api";
import { EVENTS_PAGE_SIZE, EVENTS_POLL_INTERVAL_MS } from "@/lib/constants";
import { useEventsFilterState } from "@/lib/useEventsFilterState";

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
  initialFilters: EventsFilter;
}

export function EventTable({ initialEvents, initialFilters }: EventTableProps) {
  const router = useRouter();
  const { filters, setFilters } = useEventsFilterState();

  const [events, setEvents] = useState<Event[]>(initialEvents);
  const [offset, setOffset] = useState(initialEvents.length);
  const [hasMore, setHasMore] = useState(initialEvents.length === EVENTS_PAGE_SIZE);
  const [loading, setLoading] = useState(false);

  const [sessionIdInput, setSessionIdInput] = useState(initialFilters.session_id ?? "");
  const [search, setSearch] = useState("");
  const [searchPending, setSearchPending] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  const [isServerSearch, setIsServerSearch] = useState(false);

  const offsetRef = useRef(offset);
  useEffect(() => {
    offsetRef.current = offset;
  }, [offset]);

  // Debounced session_id filter — every other filter change is immediate
  // (selects/date pickers don't need debouncing).
  useEffect(() => {
    const id = setTimeout(() => {
      if (sessionIdInput !== (filters.session_id ?? "")) {
        setFilters({ session_id: sessionIdInput || undefined });
      }
    }, 400);
    return () => clearTimeout(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionIdInput]);

  const refetchFirstPage = useCallback(
    async (activeFilters: EventsFilter) => {
      setLoading(true);
      try {
        const fresh = await getEvents({ ...activeFilters, limit: EVENTS_PAGE_SIZE, offset: 0 });
        setEvents(fresh);
        setOffset(fresh.length);
        setHasMore(fresh.length === EVENTS_PAGE_SIZE);
      } finally {
        setLoading(false);
      }
    },
    []
  );

  // Refetch page 1 whenever the URL-driven filters change (session_id,
  // decision, min/max risk, since/until) — every filter is server-applied,
  // no client-side .filter() anywhere.
  useEffect(() => {
    if (isServerSearch) return;
    refetchFirstPage(filters);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters.agent_id, filters.session_id, filters.decision, filters.min_risk, filters.max_risk, filters.since, filters.until]);

  const loadMore = useCallback(async () => {
    if (loading || !hasMore || isServerSearch) return;
    setLoading(true);
    try {
      const next = await getEvents({ ...filters, limit: EVENTS_PAGE_SIZE, offset: offsetRef.current });
      setEvents((prev) => [...prev, ...next]);
      setOffset((prev) => prev + next.length);
      setHasMore(next.length === EVENTS_PAGE_SIZE);
    } finally {
      setLoading(false);
    }
  }, [loading, hasMore, isServerSearch, filters]);

  const sentinelRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (isServerSearch) return;
    const el = sentinelRef.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0]?.isIntersecting) loadMore();
      },
      { rootMargin: "200px" }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [isServerSearch, loadMore]);

  // Own poll, not router.refresh() — a fresh SSR render would clobber the
  // client-owned accumulated infinite-scroll state. Only refetches page 1,
  // and only when the user hasn't scrolled past it or entered search mode.
  useEffect(() => {
    if (isServerSearch) return;
    const id = setInterval(() => {
      if (document.visibilityState !== "visible" || offsetRef.current > EVENTS_PAGE_SIZE) return;
      getEvents({ ...filters, limit: EVENTS_PAGE_SIZE, offset: 0 })
        .then((fresh) => {
          setEvents(fresh);
          setOffset(fresh.length);
          setHasMore(fresh.length === EVENTS_PAGE_SIZE);
        })
        .catch(() => {
          /* stale data over a broken poll */
        });
    }, EVENTS_POLL_INTERVAL_MS);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isServerSearch, filters.agent_id, filters.session_id, filters.decision, filters.min_risk, filters.max_risk, filters.since, filters.until]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const q = search.trim();
    if (!q) {
      setIsServerSearch(false);
      setSearchError(null);
      return;
    }
    setSearchPending(true);
    setSearchError(null);
    searchEvents(q, filters, 200)
      .then((data) => {
        setEvents(data);
        setIsServerSearch(true);
      })
      .catch((err) => {
        setSearchError(err instanceof Error ? err.message : "Search failed");
        setIsServerSearch(false);
      })
      .finally(() => setSearchPending(false));
  };

  const handleClearSearch = () => {
    setSearch("");
    setIsServerSearch(false);
    setSearchError(null);
    refetchFirstPage(filters);
  };

  const inputClass =
    "bg-[#141F33] border border-[#1C2844] rounded-lg px-3 py-2 text-sm text-[#A0AEBB] placeholder-[#3A4A5C] focus:outline-none focus:ring-1 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-colors";

  const toLocalInputValue = (iso?: string) => (iso ? iso.slice(0, 16) : "");

  return (
    <div className="space-y-4">
      {/* Search */}
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
            placeholder="Full-text search reasons…"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              if (!e.target.value.trim() && isServerSearch) handleClearSearch();
            }}
            className={`${inputClass} w-full pl-8`}
          />
        </div>
        <button
          type="submit"
          disabled={searchPending || !search.trim()}
          className="px-3 py-2 rounded-lg bg-indigo-600/80 text-white text-xs font-medium hover:bg-indigo-500 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
        >
          {searchPending ? "…" : "Search"}
        </button>
        {isServerSearch && (
          <button
            type="button"
            onClick={handleClearSearch}
            className="px-3 py-2 rounded-lg border border-[#1C2844] text-[#6E7D91] text-xs hover:text-[#A0AEBB] hover:border-[#2C3854] transition-colors"
          >
            Clear
          </button>
        )}
      </form>

      {/* Filters */}
      <div className="flex flex-wrap gap-2 items-center">
        <input
          type="text"
          placeholder="Filter by session_id…"
          value={sessionIdInput}
          onChange={(e) => setSessionIdInput(e.target.value)}
          className={`${inputClass} w-56`}
        />
        <select
          value={filters.decision ?? ""}
          onChange={(e) => setFilters({ decision: (e.target.value || undefined) as Decision | undefined })}
          className={`${inputClass}`}
        >
          <option value="">All Decisions</option>
          {DECISIONS.map((d) => (
            <option key={d} value={d}>{d.toUpperCase()}</option>
          ))}
        </select>
        <input
          type="number"
          placeholder="Min risk %"
          value={filters.min_risk !== undefined ? Math.round(filters.min_risk * 100) : ""}
          onChange={(e) => setFilters({ min_risk: e.target.value === "" ? undefined : Number(e.target.value) / 100 })}
          min={0}
          max={100}
          className={`${inputClass} w-28`}
        />
        <input
          type="number"
          placeholder="Max risk %"
          value={filters.max_risk !== undefined ? Math.round(filters.max_risk * 100) : ""}
          onChange={(e) => setFilters({ max_risk: e.target.value === "" ? undefined : Number(e.target.value) / 100 })}
          min={0}
          max={100}
          className={`${inputClass} w-28`}
        />
        <input
          type="datetime-local"
          value={toLocalInputValue(filters.since)}
          onChange={(e) => setFilters({ since: e.target.value ? new Date(e.target.value).toISOString() : undefined })}
          className={`${inputClass}`}
        />
        <input
          type="datetime-local"
          value={toLocalInputValue(filters.until)}
          onChange={(e) => setFilters({ until: e.target.value ? new Date(e.target.value).toISOString() : undefined })}
          className={`${inputClass}`}
        />
        <div className="flex items-center gap-2 text-xs text-[#484F58] tabular-nums">
          <span>{events.length}{hasMore && !isServerSearch ? "+" : ""} events</span>
          {isServerSearch && (
            <span className="px-1.5 py-0.5 rounded bg-indigo-600/15 text-indigo-400 border border-indigo-600/20 font-mono">
              fulltext
            </span>
          )}
        </div>
      </div>

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
            {events.length === 0 && !loading && (
              <tr>
                <td colSpan={6} className="text-center py-12 text-[#484F58] text-sm">
                  No events match your filters.
                </td>
              </tr>
            )}
            {events.map((event) => (
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
        {!isServerSearch && hasMore && (
          <div ref={sentinelRef} className="py-4 text-center text-xs text-[#484F58]">
            {loading ? "Loading more…" : ""}
          </div>
        )}
      </div>
    </div>
  );
}
