import { getAgents } from "@/lib/api";
import { AgentCard } from "@/components/agents/AgentCard";
import type { AgentProfile } from "@/types";

export default async function AgentsPage() {
  let agents: AgentProfile[] = [];
  let apiError = false;

  try {
    const res = await getAgents();
    agents = res.agents;
  } catch {
    apiError = true;
  }

  const registered = agents.filter((a) => a.is_registered);
  const unregistered = agents.filter((a) => !a.is_registered);
  const highRisk = agents.filter((a) => a.max_risk_score >= 0.75).length;
  const showUnregisteredAlert = registered.length > 0 && unregistered.length > 0;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold text-[#E6EDF3] tracking-tight">Agent Profiles</h1>
        <p className="text-sm text-[#484F58] mt-0.5">
          All agent identities observed by AgentGuard
        </p>
      </div>

      {apiError && (
        <div className="bg-[#D29922]/8 border border-[#D29922]/20 rounded-xl p-4 text-sm text-[#D29922]">
          API unavailable — start the API server first.
        </div>
      )}

      {agents.length > 0 && (
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "Total Agents", value: agents.length, accent: false },
            { label: "High Risk", value: highRisk, accent: highRisk > 0 },
            {
              label: registered.length > 0 ? "Unregistered Detections" : "Unregistered",
              value: unregistered.length,
              accent: showUnregisteredAlert,
            },
          ].map(({ label, value, accent }) => (
            <div key={label} className={`bg-[#0C1220] border rounded-xl p-4 ${accent ? "border-red-900/20" : "border-[#1C2844]"}`}>
              <p className="text-xs text-[#6E7D91] uppercase tracking-wider font-medium">{label}</p>
              <p className={`text-3xl font-bold mt-2 tabular-nums ${accent ? "text-[#F85149]" : "text-[#E6EDF3]"}`}>
                {value}
              </p>
            </div>
          ))}
        </div>
      )}

      {agents.length === 0 && !apiError && (
        <div className="bg-[#0C1220] border border-[#1C2844] rounded-xl p-12 text-center">
          <p className="text-[#484F58] text-sm">
            No agents observed yet. Run the demo to generate agent activity.
          </p>
          <p className="text-[#3A4A5C] text-xs mt-2 font-mono">
            python examples/demo_attack.py
          </p>
        </div>
      )}

      {registered.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {registered.map((agent) => (
            <AgentCard key={agent.agent_id} agent={agent} />
          ))}
        </div>
      )}

      {unregistered.length > 0 && showUnregisteredAlert && (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <div className="h-px flex-1 bg-[#F85149]/15" />
            <span className="text-xs font-semibold text-[#F85149]/70 uppercase tracking-wider">
              Unregistered Activity Detected
            </span>
            <div className="h-px flex-1 bg-[#F85149]/15" />
          </div>
          <p className="text-xs text-[#484F58]">
            Actions from agents with no registered identity. Indicates a rogue or misconfigured
            agent — sensitive tools are blocked by ABAC policy automatically.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {unregistered.map((agent) => (
              <AgentCard key={agent.agent_id} agent={agent} />
            ))}
          </div>
        </div>
      )}

      {unregistered.length > 0 && !showUnregisteredAlert && (
        <div className="space-y-3">
          <p className="text-xs text-[#3A4A5C]">
            No registered agents configured. In production, agents connect with an explicit{" "}
            <code className="font-mono bg-[#101828] px-1 rounded text-[#6E7D91]">agent_id</code>.
            These were auto-detected from their goal and framework.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {unregistered.map((agent) => (
              <AgentCard key={agent.agent_id} agent={agent} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
