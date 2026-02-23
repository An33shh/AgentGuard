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
      className="border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
    >
      {sessions.map((s) => (
        <option key={s} value={s}>{s}</option>
      ))}
    </select>
  );
}
