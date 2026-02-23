"use client";

import { useEffect, useState } from "react";
import { getPolicy, reloadPolicy } from "@/lib/api";
import type { PolicyConfig } from "@/types";

function PolicySection({ title, items }: { title: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">{title}</h3>
      <ul className="space-y-1">
        {items.map((item) => (
          <li key={item} className="text-sm font-mono text-gray-700 bg-gray-50 px-3 py-1.5 rounded-lg">
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function PoliciesPage() {
  const [policy, setPolicy] = useState<PolicyConfig | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloading, setReloading] = useState(false);
  const [reloadMsg, setReloadMsg] = useState<string | null>(null);

  useEffect(() => {
    getPolicy()
      .then(setPolicy)
      .catch((e) => setError(e.message));
  }, []);

  async function handleReload() {
    setReloading(true);
    setReloadMsg(null);
    try {
      const result = await reloadPolicy();
      setReloadMsg(`Reloaded: ${result.policy_name}`);
      const fresh = await getPolicy();
      setPolicy(fresh);
    } catch (e: unknown) {
      setReloadMsg(`Error: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setReloading(false);
    }
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Policies</h1>
          <p className="text-sm text-gray-500 mt-1">Active security policy configuration</p>
        </div>
        <button
          onClick={handleReload}
          disabled={reloading}
          className="px-4 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700 disabled:opacity-50 transition-colors"
        >
          {reloading ? "Reloading…" : "Reload Policy"}
        </button>
      </div>

      {reloadMsg && (
        <div className={`text-sm px-4 py-3 rounded-lg ${reloadMsg.startsWith("Error") ? "bg-red-50 text-red-700" : "bg-green-50 text-green-700"}`}>
          {reloadMsg}
        </div>
      )}

      {error && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-4 text-sm text-yellow-800 flex items-center justify-between gap-4">
          <span>API unavailable: {error}</span>
          <button
            onClick={() => {
              setError(null);
              getPolicy().then(setPolicy).catch((e) => setError(e.message));
            }}
            className="shrink-0 px-3 py-1.5 bg-yellow-100 hover:bg-yellow-200 text-yellow-900 rounded-lg text-xs font-medium transition-colors"
          >
            Retry
          </button>
        </div>
      )}

      {policy && (
        <div className="space-y-4">
          {/* Summary */}
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
            <h2 className="text-base font-semibold text-gray-900 mb-4">
              {policy.name}
            </h2>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-gray-400 uppercase tracking-wide">Risk Threshold (BLOCK)</p>
                <p className="text-2xl font-bold text-red-600 mt-1">
                  {(policy.risk_threshold * 100).toFixed(0)}%
                </p>
              </div>
              <div>
                <p className="text-xs text-gray-400 uppercase tracking-wide">Review Threshold</p>
                <p className="text-2xl font-bold text-yellow-600 mt-1">
                  {(policy.review_threshold * 100).toFixed(0)}%
                </p>
              </div>
            </div>
          </div>

          {/* Rules */}
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6 space-y-5">
            <h2 className="text-base font-semibold text-gray-900">Rules</h2>

            <PolicySection title="Denied Tools" items={policy.deny_tools} />
            <PolicySection title="Denied Path Patterns" items={policy.deny_path_patterns} />
            <PolicySection title="Denied Domains" items={policy.deny_domains} />
            <PolicySection title="Review Tools" items={policy.review_tools} />
            {policy.allow_tools.length > 0 && (
              <PolicySection title="Allow Tools (Strict Mode)" items={policy.allow_tools} />
            )}
          </div>

          {/* Session Limits */}
          <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
            <h2 className="text-base font-semibold text-gray-900 mb-4">Session Limits</h2>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <p className="text-xs text-gray-400">Max Actions per Session</p>
                <p className="font-semibold text-gray-800">{policy.session_limits.max_actions}</p>
              </div>
              <div>
                <p className="text-xs text-gray-400">Max Blocked Actions</p>
                <p className="font-semibold text-gray-800">{policy.session_limits.max_blocked}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
