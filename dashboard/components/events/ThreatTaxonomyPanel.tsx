import { Event } from "@/types";

const ATLAS_BASE_URL = "https://atlas.mitre.org/techniques/";

const OWASP_NAMES: Record<string, string> = {
  AA01: "Prompt Injection & Goal Hijacking",
  AA02: "Insecure Tool Execution",
  AA03: "Sensitive Data Exfiltration",
  AA04: "Uncontrolled Autonomous Action",
  AA05: "Memory & Context Poisoning",
  AA06: "Privilege Escalation",
  AA07: "Supply Chain & Plugin Risks",
  AA08: "Lateral Movement",
  AA09: "Denial of Service & Resource Abuse",
  AA10: "Insufficient Logging & Monitoring",
};

const OWASP_STYLES: Record<string, string> = {
  AA01: "bg-[#F85149]/10 text-[#F85149] border-[#F85149]/20",
  AA02: "bg-[#F85149]/10 text-[#F85149] border-[#F85149]/20",
  AA03: "bg-[#D29922]/10 text-[#D29922] border-[#D29922]/20",
  AA04: "bg-[#D29922]/10 text-[#D29922] border-[#D29922]/20",
  AA05: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  AA06: "bg-[#F85149]/10 text-[#F85149] border-[#F85149]/20",
  AA07: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  AA08: "bg-[#D29922]/10 text-[#D29922] border-[#D29922]/20",
  AA09: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  AA10: "bg-[#101828] text-[#6E7D91] border-[#243354]",
};

export function ThreatTaxonomyPanel({ event }: { event: Event }) {
  const atlasIds = Array.from(new Set([
    ...(event.policy_violation?.mitre_atlas_ids ?? []),
    ...(event.assessment.attack_taxonomy?.mitre_atlas_ids ?? []),
  ]));

  const owaspCats = Array.from(new Set([
    ...(event.policy_violation?.owasp_categories ?? []),
    ...(event.assessment.attack_taxonomy?.owasp_categories ?? []),
  ]));

  if (atlasIds.length === 0 && owaspCats.length === 0) return null;

  const { attack_pattern, confidence } = event.assessment.attack_taxonomy ?? {};

  return (
    <div className="bg-[#0C1220] rounded-xl border border-[#1C2844] p-6">
      <div className="flex items-center justify-between mb-5">
        <h2 className="text-xs font-semibold text-[#6E7D91] uppercase tracking-wider">
          Threat Intelligence
        </h2>
        {attack_pattern && attack_pattern !== "none" && (
          <span className="text-xs font-medium bg-[#F85149]/10 text-[#F85149] border border-[#F85149]/20 px-2.5 py-1 rounded-full">
            {attack_pattern.replace(/_/g, " ")}
            {confidence !== undefined && (
              <span className="text-[#F85149]/60 ml-1">· {Math.round(confidence * 100)}%</span>
            )}
          </span>
        )}
      </div>

      {atlasIds.length > 0 && (
        <div className="mb-5">
          <p className="text-xs font-medium text-[#484F58] uppercase tracking-wider mb-2.5">
            MITRE ATLAS
          </p>
          <div className="flex flex-wrap gap-2">
            {atlasIds.map((id) => (
              <a
                key={id}
                href={`${ATLAS_BASE_URL}${id}`}
                target="_blank"
                rel="noreferrer"
                className="text-xs font-mono font-medium bg-[#101828] text-indigo-400 border border-indigo-500/20 px-2.5 py-1 rounded hover:bg-indigo-500/10 hover:border-indigo-500/30 transition-colors"
              >
                {id} ↗
              </a>
            ))}
          </div>
        </div>
      )}

      {owaspCats.length > 0 && (
        <div>
          <p className="text-xs font-medium text-[#484F58] uppercase tracking-wider mb-2.5">
            OWASP Agentic AI Top 10
          </p>
          <div className="flex flex-wrap gap-2">
            {owaspCats.map((cat) => (
              <span
                key={cat}
                className={`text-xs font-medium px-2.5 py-1 rounded border ${OWASP_STYLES[cat] ?? "bg-[#101828] text-[#6E7D91] border-[#243354]"}`}
                title={OWASP_NAMES[cat] ?? cat}
              >
                {cat} — {OWASP_NAMES[cat] ?? "Unknown"}
              </span>
            ))}
          </div>
        </div>
      )}

      <p className="text-xs text-[#3A4A5C] mt-5 pt-4 border-t border-[#1C2844]">
        MITRE ATLAS · OWASP Agentic AI Top 10 (2025)
      </p>
    </div>
  );
}
