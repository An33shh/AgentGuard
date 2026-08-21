"use client";

import { useEffect, useState } from "react";
import { getPolicy } from "@/lib/api";
import { Panel } from "@/components/ui/Panel";
import type { PolicyConfig } from "@/types";

function Tile({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="bg-[#0C1220] border border-[#1C2844] rounded-xl p-4">
      <p className="text-xs text-[#6E7D91] uppercase tracking-wider font-medium">{label}</p>
      <p className="text-2xl font-bold mt-2 tabular-nums text-[#E6EDF3]">{value}</p>
    </div>
  );
}

export function PolicySummary({ refreshKey }: { refreshKey: number }) {
  const [policy, setPolicy] = useState<PolicyConfig | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getPolicy()
      .then(setPolicy)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [refreshKey]);

  if (error) return null; // Non-critical — the editor below is the source of truth on failure
  if (!policy) return null;

  const hasAdvanced =
    policy.demotion.enabled ||
    policy.deny_unregistered_tools.length > 0 ||
    policy.deny_provenance_sources.length > 0 ||
    Object.keys(policy.rule_annotations).length > 0;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
        <Tile label="Block Threshold" value={`${Math.round(policy.risk_threshold * 100)}%`} />
        <Tile label="Review Threshold" value={`${Math.round(policy.review_threshold * 100)}%`} />
        <Tile label="Denied Tools" value={policy.deny_tools.length} />
        <Tile label="Denied Domains" value={policy.deny_domains.length} />
        <Tile label="Max Actions" value={policy.session_limits.max_actions} />
        <Tile label="Max Blocked" value={policy.session_limits.max_blocked} />
      </div>

      {hasAdvanced && (
        <Panel title="Advanced Rules">
          <div className="space-y-2 text-sm text-[#A0AEBB]">
            {policy.demotion.enabled && (
              <p>
                Session demotion enabled — after{" "}
                <span className="font-mono text-[#E6EDF3]">{policy.demotion.trigger_blocked_count}</span>{" "}
                blocked actions, thresholds tighten to{" "}
                <span className="font-mono text-[#E6EDF3]">
                  {Math.round(policy.demotion.demoted_risk_threshold * 100)}%
                </span>
                /
                <span className="font-mono text-[#E6EDF3]">
                  {Math.round(policy.demotion.demoted_review_threshold * 100)}%
                </span>
                .
              </p>
            )}
            {policy.deny_unregistered_tools.length > 0 && (
              <p>
                <span className="text-[#6E7D91]">Denied for unregistered agents:</span>{" "}
                <span className="font-mono text-[#E6EDF3]">{policy.deny_unregistered_tools.join(", ")}</span>
              </p>
            )}
            {policy.deny_provenance_sources.length > 0 && (
              <p>
                <span className="text-[#6E7D91]">Denied provenance sources:</span>{" "}
                <span className="font-mono text-[#E6EDF3]">{policy.deny_provenance_sources.join(", ")}</span>
              </p>
            )}
            {Object.keys(policy.rule_annotations).length > 0 && (
              <p>
                <span className="text-[#6E7D91]">Annotated rules:</span>{" "}
                <span className="font-mono text-[#E6EDF3]">
                  {Object.keys(policy.rule_annotations).join(", ")}
                </span>
              </p>
            )}
          </div>
        </Panel>
      )}
    </div>
  );
}
