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

  const registered = agents.filter((a) => a.is_registered).length;
  const autoDetected = agents.filter((a) => !a.is_registered).length;
  const highRisk = agents.filter((a) => a.max_risk_score >= 0.75).length;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Agent Profiles</h1>
        <p className="text-sm text-gray-500 mt-1">
          Persistent identity profiles for every agent observed by AgentGuard
        </p>
      </div>

      {apiError && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-4 text-sm text-yellow-800">
          API unavailable — start the API server first.
        </div>
      )}

      {/* Summary stats */}
      {agents.length > 0 && (
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: "Total Agents", value: agents.length },
            { label: "Registered", value: registered },
            { label: "Auto-detected", value: autoDetected },
            { label: "High Risk", value: highRisk, danger: highRisk > 0 },
          ].map(({ label, value, danger }) => (
            <div key={label} className="bg-white border border-gray-200 rounded-xl p-4">
              <p className="text-xs text-gray-500">{label}</p>
              <p className={`text-2xl font-bold mt-1 ${danger ? "text-red-600" : "text-gray-900"}`}>
                {value}
              </p>
            </div>
          ))}
        </div>
      )}

      {/* Agent grid */}
      {agents.length === 0 && !apiError ? (
        <div className="bg-white border border-gray-200 rounded-xl p-12 text-center">
          <p className="text-gray-400 text-sm">
            No agents observed yet. Run the demo to generate agent activity.
          </p>
          <p className="text-gray-300 text-xs mt-2 font-mono">
            python examples/demo_attack.py
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {agents.map((agent) => (
            <AgentCard key={agent.agent_id} agent={agent} />
          ))}
        </div>
      )}
    </div>
  );
}
