import { getSessionSummaries, getTimeline, getTimelineSummary } from "@/lib/api";
import { TimelineView } from "@/components/timeline/TimelineView";
import { SessionSelector } from "@/components/timeline/SessionSelector";
import { formatDate } from "@/lib/utils";
import type { Event, SessionSummary, TimelineSummary } from "@/types";

interface Props {
  searchParams: Promise<{ session_id?: string }>;
}

export default async function TimelinePage({ searchParams }: Props) {
  const { session_id } = await searchParams;

  let sessions: SessionSummary[] = [];
  let events: Event[] = [];
  let summary: TimelineSummary | null = null;
  let apiError = false;

  try {
    sessions = await getSessionSummaries();
    const active = session_id || sessions[0]?.session_id;
    if (active) {
      [events, summary] = await Promise.all([
        getTimeline(active),
        getTimelineSummary(active).catch(() => null),
      ]);
    }
  } catch {
    apiError = true;
  }

  const activeSession = session_id || sessions[0]?.session_id;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-[#E6EDF3] tracking-tight">Attack Timeline</h1>
          <p className="text-sm text-[#484F58] mt-0.5">
            Chronological view of agent actions
          </p>
        </div>
        {sessions.length > 0 && activeSession && (
          <SessionSelector sessions={sessions} activeSession={activeSession} />
        )}
      </div>

      {apiError && (
        <div className="bg-[#D29922]/8 border border-[#D29922]/20 rounded-xl p-4 text-sm text-[#D29922]">
          API unavailable — start the API server first.
        </div>
      )}

      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total Events", value: summary.total_events, danger: false },
            { label: "Blocked", value: summary.blocked_events, danger: summary.blocked_events > 0 },
            { label: "Max Risk", value: (summary.max_risk_score * 100).toFixed(0) + "%", danger: summary.max_risk_score >= 0.75 },
            { label: "Avg Risk", value: (summary.avg_risk_score * 100).toFixed(0) + "%", danger: false },
          ].map(({ label, value, danger }) => (
            <div key={label} className={`bg-[#0C1220] border rounded-xl p-4 ${danger ? "border-red-900/20" : "border-[#1C2844]"}`}>
              <p className="text-xs text-[#6E7D91] uppercase tracking-wider font-medium">{label}</p>
              <p className={`text-2xl font-bold mt-2 tabular-nums ${danger ? "text-[#F85149]" : "text-[#E6EDF3]"}`}>
                {value}
              </p>
            </div>
          ))}
        </div>
      )}

      {summary && (summary.start_time || summary.attack_vectors.length > 0) && (
        <div className="bg-[#0C1220] border border-[#1C2844] rounded-xl p-4 space-y-3">
          {summary.start_time && summary.end_time && (
            <p className="text-xs text-[#484F58]">
              <span className="text-[#6E7D91]">Session window:</span>{" "}
              {formatDate(summary.start_time)} → {formatDate(summary.end_time)}
            </p>
          )}
          {summary.attack_vectors.length > 0 && (
            <div>
              <p className="text-xs text-[#484F58] uppercase tracking-wider mb-2">Attack Vectors</p>
              <div className="flex flex-wrap gap-1.5">
                {summary.attack_vectors.map((v) => (
                  <span key={v} className="text-xs px-2 py-0.5 bg-[#F85149]/8 text-[#F85149]/80 rounded border border-[#F85149]/15 font-mono">
                    {v.replace(/_/g, " ")}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      <TimelineView events={events} />
    </div>
  );
}
