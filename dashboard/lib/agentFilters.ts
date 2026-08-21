import type { AgentProfile } from "@/types";

export type AgentSort = "last_seen" | "risk" | "events";

/** Pure search+sort transform — never touches which agents exist, only
 * display order/inclusion of an already-computed list. Callers must apply
 * this only at render sites, never upstream of any security-relevant
 * count/alert computation. */
export function filterAndSortAgents(agents: AgentProfile[], query: string, sort: AgentSort): AgentProfile[] {
  const q = query.trim().toLowerCase();
  const filtered = q
    ? agents.filter(
        (a) => (a.display_name || "").toLowerCase().includes(q) || a.agent_goal.toLowerCase().includes(q)
      )
    : agents;

  const sorted = [...filtered];
  if (sort === "risk") {
    sorted.sort((a, b) => b.max_risk_score - a.max_risk_score);
  } else if (sort === "events") {
    sorted.sort((a, b) => b.total_events - a.total_events);
  } else {
    sorted.sort((a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime());
  }
  return sorted;
}
