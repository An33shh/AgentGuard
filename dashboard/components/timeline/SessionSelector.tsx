"use client";

import { useRouter } from "next/navigation";

interface Props {
  sessions: string[];
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
      {sessions.map((s) => (
        <option key={s} value={s} className="bg-[#101828]">{s}</option>
      ))}
    </select>
  );
}
