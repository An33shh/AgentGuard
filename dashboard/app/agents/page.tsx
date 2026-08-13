import { getAgents } from "@/lib/api";
import { AgentCard } from "@/components/agents/AgentCard";
import { AgentsControls } from "@/components/agents/AgentsControls";
import { SeedDemoButton } from "@/components/ui/SeedDemoButton";
import { filterAndSortAgents, type AgentSort } from "@/lib/agentFilters";
import type { AgentProfile } from "@/types";

interface Props {
  searchParams: Promise<{ q?: string; sort?: string }>;
}

export default async function AgentsPage({ searchParams }: Props) {
  const sp = await searchParams;
  const q = sp.q ?? "";
  const sort: AgentSort = sp.sort === "risk" || sp.sort === "events" ? sp.sort : "last_seen";

  let agents: AgentProfile[] = [];
  let apiError = false;

  try {
    const res = await getAgents();
    agents = res.agents;
  } catch {
    apiError = true;
  }

  // Search/sort is a pure display transform applied ONLY at the .map()
  // render sites below — it must never feed the registered/unregistered
  // split, highRisk count, or alert-visibility logic, since a search query
  // shrinking unregistered.length could otherwise silently suppress a
  // security warning. See filterAndSortAgents's own doc comment.
  const registered = agents.filter((a) => a.is_registered);
  const unregistered = agents.filter((a) => !a.is_registered);
  const highRisk = agents.filter((a) => a.max_risk_score >= 0.75).length;

  const filteredRegistered = filterAndSortAgents(registered, q, sort);
  const filteredUnregistered = filterAndSortAgents(unregistered, q, sort);

  const hasRegistered = registered.length > 0;
  const hasUnregistered = unregistered.length > 0;

  // Loud "rogue agent" framing is only meaningful *relative* to a baseline
  // where registration is in use — some agents here ARE registered, so
  // unregistered traffic stands out against that. When NOTHING has ever
  // registered, the same data means "registration isn't configured yet",
  // not "something is wrong" — same underlying list, lower-urgency framing,
  // but still always surfaced (never silently hidden behind a neutral
  // message that omits the ABAC safety net that's already active).
  const showUnregisteredAlert = hasRegistered && hasUnregistered;      // red, "detected"
  const showUnregisteredAdvisory = !hasRegistered && hasUnregistered;  // amber, "not configured yet"
  const unregisteredAccent: "red" | "amber" | "none" = showUnregisteredAlert
    ? "red"
    : showUnregisteredAdvisory
      ? "amber"
      : "none";

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-xl font-semibold text-[#E6EDF3] tracking-tight">Agent Profiles</h1>
          <p className="text-sm text-[#484F58] mt-0.5">
            All agent identities observed by AgentGuard
          </p>
        </div>
        {agents.length > 0 && <AgentsControls />}
      </div>

      {apiError && (
        <div className="bg-[#D29922]/8 border border-[#D29922]/20 rounded-xl p-4 text-sm text-[#D29922]">
          API unavailable — start the API server first.
        </div>
      )}

      {agents.length > 0 && (
        <div className="grid grid-cols-3 gap-3">
          {(
            [
              { label: "Total Agents", value: agents.length, accent: "none" },
              { label: "High Risk", value: highRisk, accent: highRisk > 0 ? "red" : "none" },
              {
                label: hasRegistered ? "Unregistered Detections" : "Unregistered",
                value: unregistered.length,
                accent: unregisteredAccent,
              },
            ] as const
          ).map(({ label, value, accent }) => (
            <div
              key={label}
              className={`bg-[#0C1220] border rounded-xl p-4 ${
                accent === "red" ? "border-red-900/20" : accent === "amber" ? "border-[#D29922]/20" : "border-[#1C2844]"
              }`}
            >
              <p className="text-xs text-[#6E7D91] uppercase tracking-wider font-medium">{label}</p>
              <p
                className={`text-3xl font-bold mt-2 tabular-nums ${
                  accent === "red" ? "text-[#F85149]" : accent === "amber" ? "text-[#D29922]" : "text-[#E6EDF3]"
                }`}
              >
                {value}
              </p>
            </div>
          ))}
        </div>
      )}

      {agents.length === 0 && !apiError && (
        <div className="bg-[#0C1220] border border-[#1C2844] rounded-xl p-12 text-center space-y-4">
          <p className="text-[#484F58] text-sm">
            No agents observed yet.
          </p>
          <SeedDemoButton className="inline-block" />
          <p className="text-[#3A4A5C] text-xs font-mono">
            or run: python examples/demo_attack.py
          </p>
        </div>
      )}

      {registered.length > 0 && (
        <div className="space-y-3">
          {filteredRegistered.length === 0 && (
            <p className="text-xs text-[#484F58]">No registered agents match your search.</p>
          )}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {filteredRegistered.map((agent) => (
              <AgentCard key={agent.agent_id} agent={agent} />
            ))}
          </div>
        </div>
      )}

      {showUnregisteredAlert && (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <div className="h-px flex-1 bg-[#F85149]/15" />
            <span className="text-xs font-semibold text-[#F85149]/70 uppercase tracking-wider">
              Unregistered Activity Detected
            </span>
            <div className="h-px flex-1 bg-[#F85149]/15" />
          </div>
          <p className="text-xs text-[#484F58]">
            Actions from agents with no registered identity, alongside agents that ARE registered
            in this deployment. Indicates a rogue or misconfigured agent — sensitive tools are
            blocked by ABAC policy automatically.
          </p>
          {filteredUnregistered.length === 0 && (
            <p className="text-xs text-[#484F58]">No unregistered agents match your search.</p>
          )}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {filteredUnregistered.map((agent) => (
              <AgentCard key={agent.agent_id} agent={agent} />
            ))}
          </div>
        </div>
      )}

      {showUnregisteredAdvisory && (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <div className="h-px flex-1 bg-[#D29922]/15" />
            <span className="text-xs font-semibold text-[#D29922]/70 uppercase tracking-wider">
              No Registered Agents Yet
            </span>
            <div className="h-px flex-1 bg-[#D29922]/15" />
          </div>
          <p className="text-xs text-[#484F58]">
            No agent in this deployment has ever connected with an explicit{" "}
            <code className="font-mono bg-[#101828] px-1 rounded text-[#6E7D91]">agent_id</code>.
            All activity below is auto-detected from goal + framework and is automatically
            restricted from sensitive tools by ABAC policy. Normal for early development —
            configure explicit registration before production if you need looser per-agent
            tool access.
          </p>
          {filteredUnregistered.length === 0 && (
            <p className="text-xs text-[#484F58]">No unregistered agents match your search.</p>
          )}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {filteredUnregistered.map((agent) => (
              <AgentCard key={agent.agent_id} agent={agent} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
