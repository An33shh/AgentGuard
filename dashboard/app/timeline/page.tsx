import { getSessions, getTimeline, getTimelineSummary } from "@/lib/api";
import { TimelineView } from "@/components/timeline/TimelineView";
import { SessionSelector } from "@/components/timeline/SessionSelector";
import type { Event, TimelineSummary } from "@/types";

interface Props {
  searchParams: Promise<{ session_id?: string }>;
}

export default async function TimelinePage({ searchParams }: Props) {
  const { session_id } = await searchParams;

  let sessions: string[] = [];
  let events: Event[] = [];
  let summary: TimelineSummary | null = null;
  let apiError = false;

  try {
    sessions = await getSessions();
    const active = session_id || sessions[0];
    if (active) {
      [events, summary] = await Promise.all([
        getTimeline(active),
        getTimelineSummary(active).catch(() => null),
      ]);
    }
  } catch {
    apiError = true;
  }

  const activeSession = session_id || sessions[0];

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

      <TimelineView events={events} />
    </div>
  );
}
