import type { EventsFilter } from "@/lib/api";

// Centralizes URL construction/parsing for the events filter query-param
// vocabulary so it never drifts out of sync with EventsFilter. Pure
// functions — no hooks — so they're usable both server-side (Next 15's
// async `searchParams` page prop, wrapped in a plain URLSearchParams) and
// client-side (useSearchParams()).

const FILTER_KEYS = [
  "session_id",
  "agent_id",
  "decision",
  "min_risk",
  "max_risk",
  "since",
  "until",
] as const;

export function parseEventsSearchParams(searchParams: URLSearchParams): EventsFilter {
  const filter: EventsFilter = {};
  const sessionId = searchParams.get("session_id");
  if (sessionId) filter.session_id = sessionId;
  const agentId = searchParams.get("agent_id");
  if (agentId) filter.agent_id = agentId;
  const decision = searchParams.get("decision");
  if (decision === "allow" || decision === "block" || decision === "review") {
    filter.decision = decision;
  }
  const minRisk = searchParams.get("min_risk");
  if (minRisk !== null && !Number.isNaN(Number(minRisk))) filter.min_risk = Number(minRisk);
  const maxRisk = searchParams.get("max_risk");
  if (maxRisk !== null && !Number.isNaN(Number(maxRisk))) filter.max_risk = Number(maxRisk);
  const since = searchParams.get("since");
  if (since) filter.since = since;
  const until = searchParams.get("until");
  if (until) filter.until = until;
  return filter;
}

export function eventsUrl(filter: Partial<EventsFilter>): string {
  const params = new URLSearchParams();
  Object.entries(filter).forEach(([k, v]) => {
    if (v !== undefined && v !== "") params.set(k, String(v));
  });
  const qs = params.toString();
  return `/events${qs ? `?${qs}` : ""}`;
}

export function timelineUrl(sessionId: string): string {
  return `/timeline?session_id=${encodeURIComponent(sessionId)}`;
}

export { FILTER_KEYS };
