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
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-[#E6EDF3] tracking-tight">Dashboard</h1>
          <p className="text-sm mt-0.5" style={{ color: "#484F58" }}>
            Real-time AI agent security monitoring
          </p>
        </div>
        <div
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs"
          style={{ background: "rgba(63,185,80,0.08)", border: "1px solid rgba(63,185,80,0.15)", color: "#3FB950" }}
        >
          <span className="w-1.5 h-1.5 rounded-full shrink-0 pulse" style={{ background: "#3FB950", boxShadow: "0 0 4px rgba(63,185,80,0.8)" }} />
          <span className="font-mono">Monitoring Active</span>
        </div>
      </div>

      {apiError && (
        <div className="bg-[#E88C30]/8 border border-[#E88C30]/20 rounded-xl p-4 text-sm text-[#E88C30]">
          API unavailable — start the AgentGuard API server with{" "}
          <code className="font-mono bg-[#E88C30]/10 px-1 rounded">uvicorn api.main:app --reload</code>
        </div>
      )}

      <StatCards stats={stats} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
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
