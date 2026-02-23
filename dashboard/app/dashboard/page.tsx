import { getEvents, getPolicy, getStats } from "@/lib/api";
import { StatCards } from "@/components/dashboard/StatCards";
import { RiskSparklineChart } from "@/components/dashboard/RiskSparklineChart";
import { RecentBlockedFeed } from "@/components/dashboard/RecentBlockedFeed";
import type { Event, Stats } from "@/types";

const EMPTY_STATS: Stats = {
  total_events: 0,
  blocked_events: 0,
  reviewed_events: 0,
  allowed_events: 0,
  active_sessions: 0,
  avg_risk_score: 0,
};

export default async function DashboardPage() {
  let stats = EMPTY_STATS;
  let events: Event[] = [];
  let blockedEvents: Event[] = [];
  let riskThreshold = 75;
  let reviewThreshold = 60;
  let apiError = false;

  try {
    const [statsData, eventsData, blockedData, policy] = await Promise.all([
      getStats(),
      getEvents({ limit: 100 }),
      getEvents({ decision: "block", limit: 8 }),
      getPolicy(),
    ]);
    stats = statsData;
    events = eventsData;
    blockedEvents = blockedData;
    riskThreshold = Math.round(policy.risk_threshold * 100);
    reviewThreshold = Math.round(policy.review_threshold * 100);
  } catch {
    apiError = true;
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-sm text-gray-500 mt-1">
          Real-time AI agent security monitoring
        </p>
      </div>

      {apiError && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-4 text-sm text-yellow-800">
          API unavailable — start the AgentGuard API server with{" "}
          <code className="font-mono bg-yellow-100 px-1 rounded">uvicorn api.main:app --reload</code>
        </div>
      )}

      <StatCards stats={stats} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <RiskSparklineChart
            events={events}
            riskThreshold={riskThreshold}
            reviewThreshold={reviewThreshold}
          />
        </div>
        <div>
          <RecentBlockedFeed events={blockedEvents} />
        </div>
      </div>
    </div>
  );
}
