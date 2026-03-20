import { ProvenanceTag, ProvenanceSourceType } from "@/types";

const SOURCE_TYPE_STYLES: Record<ProvenanceSourceType, { badge: string; label: string }> = {
  user_instruction: { badge: "bg-indigo-500/10 text-indigo-400 border-indigo-500/20",       label: "User" },
  tool_output:      { badge: "bg-[#D29922]/10 text-[#D29922] border-[#D29922]/20",           label: "Tool Output" },
  external_data:    { badge: "bg-[#F85149]/10 text-[#F85149] border-[#F85149]/20",            label: "External Data" },
  agent_generated:  { badge: "bg-purple-500/10 text-purple-400 border-purple-500/20",         label: "Agent" },
  system:           { badge: "bg-[#101828] text-[#6E7D91] border-[#243354]",                  label: "System" },
};

const THREAT_SOURCE_TYPES: ProvenanceSourceType[] = ["external_data", "tool_output"];

export function ProvenancePanel({ tags }: { tags: ProvenanceTag[] }) {
  const hasThreatSource = tags.some((t) =>
    THREAT_SOURCE_TYPES.includes(t.source_type as ProvenanceSourceType)
  );

  return (
    <div className="bg-[#0C1220] rounded-xl border border-[#1C2844] p-6">
      <div className="flex items-center justify-between mb-5">
        <h2 className="text-xs font-semibold text-[#6E7D91] uppercase tracking-wider">
          Data Provenance
        </h2>
        {hasThreatSource && (
          <span className="text-xs font-medium bg-[#D29922]/10 text-[#D29922] border border-[#D29922]/20 px-2.5 py-1 rounded-full">
            Untrusted Source
          </span>
        )}
      </div>

      <div className="space-y-3">
        {tags.map((tag, i) => {
          const style = SOURCE_TYPE_STYLES[tag.source_type as ProvenanceSourceType] ?? SOURCE_TYPE_STYLES.system;
          return (
            <div key={i} className="flex items-start gap-3">
              <span
                className={`text-xs font-medium px-2 py-0.5 rounded border ${style.badge} whitespace-nowrap shrink-0`}
                title={tag.source_type}
              >
                {style.label}
              </span>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-[#A0AEBB]">{tag.label}</p>
                {tag.value && (
                  <p className="text-xs text-[#484F58] font-mono truncate mt-0.5">{tag.value}</p>
                )}
                {tag.inherited_from && (
                  <p className="text-xs text-[#484F58] mt-0.5">
                    Propagated from{" "}
                    <a href={`/events/${tag.inherited_from}`} className="font-mono text-indigo-400 hover:text-indigo-300 transition-colors">
                      {tag.inherited_from.slice(0, 8)}…
                    </a>
                  </p>
                )}
              </div>
            </div>
          );
        })}
      </div>

      <p className="text-xs text-[#3A4A5C] mt-5 pt-4 border-t border-[#1C2844]">
        MITRE ATLAS AML.T0054 — Prompt Injection via Tool Outputs
      </p>
    </div>
  );
}
