// Typed API client for AgentGuard FastAPI backend

import type { AgentGraphData, AgentProfile, Decision, Event, Insight, PolicyConfig, SessionSummary, Stats, TimelineSummary } from "@/types";

// Server Components (the async page.tsx files) run inside the dashboard
// container itself and must reach the API via its Docker service name.
// "use client" components run in the browser and must use the
// browser-reachable, NEXT_PUBLIC_-inlined URL instead — the two are not
// interchangeable in a containerized deployment.
const API_BASE =
  typeof window === "undefined"
    ? process.env.API_INTERNAL_URL || process.env.NEXT_PUBLIC_API_URL || "http://localhost:8747"
    : process.env.NEXT_PUBLIC_API_URL || "http://localhost:8747";

export interface ApiErrorBody {
  error_code: string;
  message: string;
}

// The backend's global exception handler (api/main.py) normalizes EVERY
// HTTPException — even ones raised with a plain string `detail` — into
// {error_code, message} JSON, on every route, always. Callers can rely on
// this shape to distinguish e.g. a real 404 (errorCode === "NOT_FOUND")
// from an outage, instead of every failure looking the same.
export class ApiError extends Error {
  status: number;
  errorCode: string;
  constructor(status: number, body: ApiErrorBody) {
    super(body.message);
    this.name = "ApiError";
    this.status = status;
    this.errorCode = body.error_code;
  }
}

async function fetchAPI<T>(path: string, init?: RequestInit): Promise<T> {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
    // Disable Next.js cache for live data
    cache: "no-store",
  });
  if (!res.ok) {
    let body: ApiErrorBody;
    try {
      const parsed = await res.json();
      body =
        parsed && typeof parsed === "object" && "error_code" in parsed
          ? (parsed as ApiErrorBody)
          : { error_code: "INTERNAL_ERROR", message: typeof parsed === "string" ? parsed : JSON.stringify(parsed) };
    } catch {
      body = { error_code: "INTERNAL_ERROR", message: res.statusText || `HTTP ${res.status}` };
    }
    throw new ApiError(res.status, body);
  }
  return res.json();
}

// ── Events ─────────────────────────────────────────────

export interface EventsFilter {
  session_id?: string;
  agent_id?: string;
  decision?: Decision;
  min_risk?: number;
  max_risk?: number;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

export async function getEvents(filter: EventsFilter = {}): Promise<Event[]> {
  const params = new URLSearchParams();
  if (filter.session_id) params.set("session_id", filter.session_id);
  if (filter.agent_id) params.set("agent_id", filter.agent_id);
  if (filter.decision) params.set("decision", filter.decision);
  if (filter.min_risk !== undefined) params.set("min_risk", String(filter.min_risk));
  if (filter.max_risk !== undefined) params.set("max_risk", String(filter.max_risk));
  if (filter.since) params.set("since", filter.since);
  if (filter.until) params.set("until", filter.until);
  if (filter.limit !== undefined) params.set("limit", String(filter.limit));
  if (filter.offset !== undefined) params.set("offset", String(filter.offset));

  const qs = params.toString();
  return fetchAPI<Event[]>(`/api/v1/events${qs ? `?${qs}` : ""}`);
}

export async function getEvent(eventId: string): Promise<Event> {
  return fetchAPI<Event>(`/api/v1/events/${eventId}`);
}

export async function searchEvents(
  query: string,
  filter: Omit<EventsFilter, "limit" | "offset"> = {},
  limit = 20
): Promise<Event[]> {
  return fetchAPI<Event[]>("/api/v1/events/search", {
    method: "POST",
    body: JSON.stringify({ query, limit, ...filter }),
  });
}

// ── Timeline ───────────────────────────────────────────

export async function getTimeline(sessionId: string): Promise<Event[]> {
  return fetchAPI<Event[]>(`/api/v1/timeline?session_id=${encodeURIComponent(sessionId)}`);
}

export async function getTimelineSummary(sessionId: string): Promise<TimelineSummary> {
  return fetchAPI<TimelineSummary>(
    `/api/v1/timeline/summary?session_id=${encodeURIComponent(sessionId)}`
  );
}

// ── Sessions ───────────────────────────────────────────

export async function getSessionSummaries(): Promise<SessionSummary[]> {
  return fetchAPI<SessionSummary[]>("/api/v1/sessions/summary");
}

// ── Stats ──────────────────────────────────────────────

export async function getStats(): Promise<Stats> {
  return fetchAPI<Stats>("/api/v1/stats");
}

// ── Policies ───────────────────────────────────────────

export async function getPolicy(): Promise<PolicyConfig> {
  return fetchAPI<PolicyConfig>("/api/v1/policies");
}

export async function validatePolicy(yaml: string): Promise<{ valid: boolean; [key: string]: unknown }> {
  return fetchAPI<{ valid: boolean }>("/api/v1/policies/validate", {
    method: "POST",
    body: JSON.stringify({ yaml }),
  });
}

export async function getRawPolicy(): Promise<{ yaml: string; path: string }> {
  return fetchAPI<{ yaml: string; path: string }>("/api/v1/policies/raw");
}

export async function savePolicy(yaml: string): Promise<{ saved: boolean; policy_name: string }> {
  return fetchAPI<{ saved: boolean; policy_name: string }>("/api/v1/policies/save", {
    method: "POST",
    body: JSON.stringify({ yaml }),
  });
}

export async function reloadPolicy(): Promise<{ reloaded: boolean; policy_name: string }> {
  return fetchAPI<{ reloaded: boolean; policy_name: string }>("/api/v1/policies/reload", {
    method: "POST",
  });
}

// ── Agents ─────────────────────────────────────────────

export async function getAgents(): Promise<{ agents: AgentProfile[]; total: number }> {
  return fetchAPI<{ agents: AgentProfile[]; total: number }>("/api/v1/agents");
}

export async function getAgent(agentId: string): Promise<AgentProfile> {
  return fetchAPI<AgentProfile>(`/api/v1/agents/${encodeURIComponent(agentId)}`);
}

export async function getAgentGraph(agentId: string): Promise<AgentGraphData> {
  return fetchAPI<AgentGraphData>(`/api/v1/agents/${encodeURIComponent(agentId)}/graph`);
}

// ── Health ─────────────────────────────────────────────

export async function getHealth(): Promise<{ status: string }> {
  return fetchAPI<{ status: string }>("/api/v1/health");
}

export interface ReadinessStatus {
  status: "healthy" | "degraded" | "unhealthy";
  components: Record<string, { status: string; [key: string]: unknown }>;
}

// Unlike getHealth() (liveness — always "healthy" as long as the API
// process itself is up), this actually checks DB/Redis/policy/analyzer —
// the real signal for "is monitoring actually working." Returns a 503 when
// unhealthy, which fetchAPI turns into a thrown ApiError; callers should
// catch and treat that the same as "unhealthy".
export async function getReadiness(): Promise<ReadinessStatus> {
  return fetchAPI<ReadinessStatus>("/api/v1/readiness");
}

// ── Insights ───────────────────────────────────────────

export interface InsightsResponse {
  insights: Insight[];
  total: number;
  enrichment_enabled: boolean;
}

export async function getInsights(limit = 50): Promise<InsightsResponse> {
  return fetchAPI<InsightsResponse>(`/api/v1/insights?limit=${limit}`);
}

// ── Demo ───────────────────────────────────────────────

export interface DemoSeedResult {
  seeded: number;
  blocked: number;
  reviewed: number;
  allowed: number;
  attack_session_id: string;
  baseline_session_id: string;
  results: unknown[];
}

export async function seedDemo(): Promise<DemoSeedResult> {
  return fetchAPI<DemoSeedResult>("/api/v1/demo/seed", { method: "POST" });
}
