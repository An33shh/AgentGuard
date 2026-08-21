import { getEvent, getInsights } from "@/lib/api";
import { InsightRow } from "@/components/insights/InsightRow";
import { SeedDemoButton } from "@/components/ui/SeedDemoButton";
import type { Event, Insight, RiskLevel } from "@/types";

const SEVERITY_RANK: Record<RiskLevel, number> = { critical: 4, high: 3, medium: 2, low: 1 };

// severity is model-generated on the backend — guard against an off-enum
// value silently scrambling the sort instead of throwing (RiskLevel is a
// frontend-asserted type, not a backend-enforced guarantee).
function severityRank(severity: RiskLevel): number {
  return SEVERITY_RANK[severity] ?? 0;
}

function rankInsights(insights: Insight[]): Insight[] {
  return [...insights].sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity) || a.false_positive_likelihood - b.false_positive_likelihood
  );
}

// Real concurrency cap, not just a comment claiming one — 50 insights
// fanning out to 50 simultaneous getEvent() calls is unnecessary load on
// every render of this page.
const EVENT_FETCH_CONCURRENCY = 8;

async function fetchEventsBounded(eventIds: string[]): Promise<(Event | null)[]> {
  const results: (Event | null)[] = new Array(eventIds.length).fill(null);
  for (let i = 0; i < eventIds.length; i += EVENT_FETCH_CONCURRENCY) {
    const chunk = eventIds.slice(i, i + EVENT_FETCH_CONCURRENCY);
    const chunkResults = await Promise.all(chunk.map((id) => getEvent(id).catch(() => null)));
    chunkResults.forEach((r, j) => {
      results[i + j] = r;
    });
  }
  return results;
}

export default async function InsightsPage() {
  let insights: Insight[] = [];
  let total = 0;
  let enrichmentEnabled = true;
  let apiError = false;

  try {
    const res = await getInsights(50);
    insights = res.insights;
    total = res.total;
    enrichmentEnabled = res.enrichment_enabled;
  } catch {
    apiError = true;
  }

  const ranked = rankInsights(insights);

  // Bounded parallel fan-out for row context (EVENT_FETCH_CONCURRENCY at a
  // time) — one failed getEvent degrades only that row (InsightRow renders
  // "Event details unavailable"), never the whole page.
  const events = await fetchEventsBounded(ranked.map((i) => i.event_id));
  const eventsById: Record<string, Event | null> = Object.fromEntries(
    ranked.map((i, idx) => [i.event_id, events[idx]])
  );

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-[#E6EDF3] tracking-tight">Insights</h1>
        <p className="text-sm text-[#484F58] mt-0.5">
          Claude-generated triage for flagged events, ranked by severity
        </p>
      </div>

      {apiError && (
        <div className="bg-[#E88C30]/8 border border-[#E88C30]/20 rounded-xl p-4 text-sm text-[#E88C30]">
          API unavailable — start the API server first.
        </div>
      )}

      {!apiError && !enrichmentEnabled && (
        <div className="bg-[#0C1220] border border-[#1C2844] rounded-xl p-12 text-center space-y-2">
          <p className="text-[#484F58] text-sm">Enrichment is not enabled.</p>
          <p className="text-[#3A4A5C] text-xs font-mono">
            Set ANTHROPIC_API_KEY and run{" "}
            <code className="bg-[#101828] px-1 rounded">python -m agentguard.integrations.enrichment_worker</code>
          </p>
        </div>
      )}

      {!apiError && enrichmentEnabled && ranked.length === 0 && (
        <div className="bg-[#0C1220] border border-[#1C2844] rounded-xl p-12 text-center space-y-4">
          <p className="text-[#484F58] text-sm">
            No insights yet. Enrichment runs on blocked/reviewed events as they occur.
          </p>
          <SeedDemoButton className="inline-block" />
        </div>
      )}

      {ranked.length > 0 && (
        <>
          <p className="text-xs text-[#484F58]">
            Showing {ranked.length} of {total} recent insight{total === 1 ? "" : "s"}
          </p>
          <div className="space-y-3">
            {ranked.map((insight) => (
              <InsightRow key={insight.event_id} insight={insight} event={eventsById[insight.event_id] ?? null} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}
