"use client";

import { useCallback, useMemo } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import type { EventsFilter } from "@/lib/api";
import { FILTER_KEYS, parseEventsSearchParams } from "@/lib/urls";

/**
 * Batched multi-field URL filter state for the events filter bar —
 * session_id/agent_id/decision/min_risk/max_risk/since/until must land in
 * the URL as ONE atomic navigation, not one per field.
 */
export function useEventsFilterState() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  // Memoized on the URL string, not recomputed every render: an unstable
  // `filters` object identity here previously gave EventTable's loadMore
  // callback (deps include `filters`) a new identity on every re-render,
  // which tore down and recreated its IntersectionObserver on every
  // re-render too — and observing a sentinel that's currently in view
  // immediately re-fires the callback, so any unrelated state update (e.g.
  // typing in the session_id filter box) silently triggered an extra
  // pagination fetch independent of actual scroll position.
  const filters = useMemo(
    () => parseEventsSearchParams(searchParams),
    [searchParams]
  );

  const setFilters = useCallback(
    (next: Partial<EventsFilter>) => {
      const params = new URLSearchParams(searchParams.toString());
      for (const key of FILTER_KEYS) {
        if (!(key in next)) continue;
        const v = next[key];
        if (v === undefined || v === "") params.delete(key);
        else params.set(key, String(v));
      }
      router.replace(`${pathname}?${params.toString()}`, { scroll: false });
    },
    [searchParams, pathname, router]
  );

  return { filters, setFilters };
}
