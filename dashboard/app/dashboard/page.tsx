import { getEvents, getPolicy, getStats } from "@/lib/api";
import { StatCards } from "@/components/dashboard/StatCards";
import { RiskSparklineChart } from "@/components/dashboard/RiskSparklineChart";
import { RecentBlockedFeed } from "@/components/dashboard/RecentBlockedFeed";
import { MonitoringBadge } from "@/components/dashboard/MonitoringBadge";
import { WidgetError } from "@/components/ui/WidgetError";
import { AutoRefresh } from "@/components/ui/AutoRefresh";
import { DASHBOARD_POLL_INTERVAL_MS } from "@/lib/constants";
import { eventsUrl } from "@/lib/urls";
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
  const [statsR, eventsR, blockedR, policyR] = await Promise.allSettled([
    getStats(),
    getEvents({ limit: 100 }),
    getEvents({ decision: "block", limit: 8 }),
    getPolicy(),
  ]);

  const stats: Stats = statsR.status === "fulfilled" ? statsR.value : EMPTY_STATS;
  const statsError = statsR.status === "rejected";

  const events: Event[] = eventsR.status === "fulfilled" ? eventsR.value : [];
  const eventsError = eventsR.status === "rejected";

  const blockedEvents: Event[] = blockedR.status === "fulfilled" ? blockedR.value : [];
  const blockedError = blockedR.status === "rejected";

  const riskThreshold = policyR.status === "fulfilled" ? Math.round(policyR.value.risk_threshold * 100) : 75;
  const reviewThreshold = policyR.status === "fulfilled" ? Math.round(policyR.value.review_threshold * 100) : 60;

  // Only a true total outage (every call failed) gets the page-wide banner —
  // a single widget failing degrades just that widget instead.
  const totalOutage = statsError && eventsError && blockedError;

  return (
    <div className="space-y-6">
      <AutoRefresh intervalMs={DASHBOARD_POLL_INTERVAL_MS} />
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold text-[#E6EDF3] tracking-tight">Dashboard</h1>
          <p className="text-sm mt-0.5" style={{ color: "#484F58" }}>
            Real-time AI agent security monitoring
          </p>
        </div>
        <MonitoringBadge />
      </div>

      {totalOutage && (
        <div className="bg-[#E88C30]/8 border border-[#E88C30]/20 rounded-xl p-4 text-sm text-[#E88C30]">
          API unavailable — start the AgentGuard API server with{" "}
          <code className="font-mono bg-[#E88C30]/10 px-1 rounded">uvicorn api.main:app --reload</code>
        </div>
      )}

      {statsError ? (
        <WidgetError message="Stats unavailable" />
      ) : (
        <StatCards stats={stats} blockedHref={eventsUrl({ decision: "block" })} />
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          {eventsError ? (
            <WidgetError message="Risk timeline unavailable" />
          ) : (
            <RiskSparklineChart
              events={events}
              riskThreshold={riskThreshold}
              reviewThreshold={reviewThreshold}
              totalEvents={stats.total_events}
            />
          )}
        </div>
        <div>
          {blockedError ? <WidgetError message="Recent blocks unavailable" /> : <RecentBlockedFeed events={blockedEvents} />}
        </div>
      </div>
    </div>
  );
}
