import { RISK_STYLES, type RiskLevel } from "@/types";

export function SeverityBadge({ severity }: { severity: RiskLevel }) {
  // severity is model-generated on the backend (tool-schema-constrained,
  // not a hard guarantee) — an off-enum value must degrade, not throw and
  // take down the whole insights page.
  const style = RISK_STYLES[severity] ?? RISK_STYLES.low;
  return (
    <span
      className="text-xs font-medium px-2 py-0.5 rounded uppercase tracking-wide"
      style={{ color: style.text, backgroundColor: style.bg, border: `1px solid ${style.border}` }}
    >
      {severity}
    </span>
  );
}
