"use client";

import { useEffect, useState } from "react";
import { useQueryParam } from "@/lib/useQueryParam";
import type { AgentSort } from "@/lib/agentFilters";

const inputClass =
  "bg-[#141F33] border border-[#1C2844] rounded-lg px-3 py-2 text-sm text-[#A0AEBB] placeholder-[#3A4A5C] focus:outline-none focus:ring-1 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-colors";

export function AgentsControls() {
  const [q, setQ] = useQueryParam("q");
  const [sort, setSort] = useQueryParam("sort", "last_seen");

  // Local state is authoritative for the input's displayed value; the URL
  // (which drives a dynamic server-component refetch) only updates after a
  // debounce, matching EventTable's session_id filter pattern — otherwise
  // every keystroke round-trips through the server and fast typing drops
  // characters while waiting on the RSC payload to resolve.
  const [qInput, setQInput] = useState(q);
  useEffect(() => {
    const id = setTimeout(() => {
      if (qInput !== q) setQ(qInput);
    }, 400);
    return () => clearTimeout(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qInput]);

  return (
    <div className="flex flex-wrap gap-2 items-center">
      <input
        type="text"
        placeholder="Search by name or goal…"
        value={qInput}
        onChange={(e) => setQInput(e.target.value)}
        className={`${inputClass} w-64`}
      />
      <select
        value={sort}
        onChange={(e) => setSort(e.target.value as AgentSort)}
        className={inputClass}
      >
        <option value="last_seen">Sort: Last seen</option>
        <option value="risk">Sort: Highest risk</option>
        <option value="events">Sort: Most events</option>
      </select>
    </div>
  );
}
