"use client";

import { useRouter } from "next/navigation";
import type { SessionSummary } from "@/types";

interface Props {
  sessions: SessionSummary[];
  activeSession: string;
}

export function SessionSelector({ sessions, activeSession }: Props) {
  const router = useRouter();

  return (
    <select
      value={activeSession}
      onChange={(e) => router.push(`/timeline?session_id=${e.target.value}`)}
      className="bg-[#141F33] border border-[#1C2844] rounded-lg px-3 py-2 text-sm text-[#A0AEBB] focus:outline-none focus:ring-1 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-colors"
    >
      {sessions.map((s) => {
        const goal = s.agent_goal.length > 40 ? s.agent_goal.slice(0, 40) + "…" : s.agent_goal;
        const suffix = s.blocked_events > 0 ? ` — ${s.blocked_events} blocked` : "";
        // Short id suffix so two sessions sharing the same goal (common —
        // the same agent re-run) stay distinguishable in a plain <option>,
        // which can't render a richer label.
        const idSuffix = s.session_id.slice(-6);
        return (
          <option key={s.session_id} value={s.session_id} className="bg-[#101828]">
            {goal}{suffix} · {s.total_events} events · {idSuffix}
          </option>
        );
      })}
    </select>
  );
}
