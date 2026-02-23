"use client";

import { useEffect, useState, useCallback } from "react";
import Editor from "@monaco-editor/react";
import { getRawPolicy, validatePolicy, savePolicy } from "@/lib/api";

type Status = { type: "success" | "error" | "info"; message: string } | null;

export default function PoliciesPage() {
  const [yaml, setYaml] = useState<string>("");
  const [filePath, setFilePath] = useState<string>("");
  const [status, setStatus] = useState<Status>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [validating, setValidating] = useState(false);

  useEffect(() => {
    getRawPolicy()
      .then(({ yaml: y, path }) => {
        setYaml(y);
        setFilePath(path);
      })
      .catch((e) => setStatus({ type: "error", message: e.message }))
      .finally(() => setLoading(false));
  }, []);

  const handleValidate = useCallback(async () => {
    setValidating(true);
    setStatus(null);
    try {
      const res = await validatePolicy(yaml);
      setStatus({
        type: "success",
        message: `Valid — "${res.policy_name}" · block threshold ${((res.risk_threshold as number) * 100).toFixed(0)}% · ${res.deny_tools_count} denied tools · ${res.deny_domains_count} denied domains`,
      });
    } catch (e: unknown) {
      setStatus({ type: "error", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setValidating(false);
    }
  }, [yaml]);

  const handleSave = useCallback(async () => {
    setSaving(true);
    setStatus(null);
    try {
      const res = await savePolicy(yaml);
      setStatus({ type: "success", message: `Saved and reloaded: "${res.policy_name}"` });
    } catch (e: unknown) {
      setStatus({ type: "error", message: e instanceof Error ? e.message : String(e) });
    } finally {
      setSaving(false);
    }
  }, [yaml]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Policies</h1>
          {filePath && (
            <p className="text-xs text-gray-400 font-mono mt-0.5">{filePath}</p>
          )}
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleValidate}
            disabled={validating || loading}
            className="px-4 py-2 text-sm font-medium text-indigo-700 bg-indigo-50 rounded-lg hover:bg-indigo-100 disabled:opacity-50 transition-colors"
          >
            {validating ? "Validating…" : "Validate"}
          </button>
          <button
            onClick={handleSave}
            disabled={saving || loading}
            className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 rounded-lg hover:bg-indigo-700 disabled:opacity-50 transition-colors"
          >
            {saving ? "Saving…" : "Save & Reload"}
          </button>
        </div>
      </div>

      {/* Status */}
      {status && (
        <div
          className={`text-sm px-4 py-3 rounded-lg ${
            status.type === "success"
              ? "bg-green-50 text-green-700"
              : "bg-red-50 text-red-700"
          }`}
        >
          {status.message}
        </div>
      )}

      {/* Editor */}
      <div className="rounded-xl overflow-hidden border border-gray-200">
        {loading ? (
          <div className="flex items-center justify-center h-[520px] text-sm text-gray-400">
            Loading policy…
          </div>
        ) : (
          <Editor
            height="calc(100vh - 220px)"
            defaultLanguage="yaml"
            value={yaml}
            onChange={(v) => setYaml(v ?? "")}
            theme="vs-dark"
            options={{
              fontSize: 13,
              fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
              minimap: { enabled: false },
              scrollBeyondLastLine: false,
              lineNumbers: "on",
              tabSize: 2,
              wordWrap: "on",
              padding: { top: 16, bottom: 16 },
            }}
          />
        )}
      </div>
    </div>
  );
}
