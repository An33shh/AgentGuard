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
    const activeSession = session_id || sessions[0];
    if (activeSession) {
      [events, summary] = await Promise.all([
        getTimeline(activeSession),
        getTimelineSummary(activeSession).catch(() => null),
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
          <h1 className="text-2xl font-bold text-gray-900">Attack Timeline</h1>
          <p className="text-sm text-gray-500 mt-1">
            Chronological view of agent actions — Microsoft Defender style
          </p>
        </div>

        {sessions.length > 0 && activeSession && (
          <SessionSelector sessions={sessions} activeSession={activeSession} />
        )}
      </div>

      {apiError && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-4 text-sm text-yellow-800">
          API unavailable — start the API server first.
        </div>
      )}

      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { label: "Total Events", value: summary.total_events, color: "" },
            { label: "Blocked", value: summary.blocked_events, color: "text-red-600" },
            { label: "Max Risk", value: (summary.max_risk_score * 100).toFixed(0) + "%", color: "text-red-600" },
            { label: "Avg Risk", value: (summary.avg_risk_score * 100).toFixed(0) + "%", color: "" },
          ].map(({ label, value, color }) => (
            <div key={label} className="bg-white rounded-xl border border-gray-200 p-4">
              <p className="text-xs text-gray-500">{label}</p>
              <p className={`text-2xl font-bold mt-1 ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      )}

      <TimelineView events={events} />
    </div>
  );
}
