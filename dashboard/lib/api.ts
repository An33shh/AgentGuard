// Typed API client for AgentGuard FastAPI backend

import type { AgentGraphData, AgentProfile, Decision, Event, PolicyConfig, Stats, TimelineSummary } from "@/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

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
    const text = await res.text();
    throw new Error(`API error ${res.status}: ${text}`);
  }
  return res.json();
}

// ── Events ─────────────────────────────────────────────

export interface EventsFilter {
  session_id?: string;
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

export async function getSessions(): Promise<string[]> {
  return fetchAPI<string[]>("/api/v1/sessions");
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
