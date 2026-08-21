"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

/**
 * Re-runs the enclosing Server Component's data fetch on an interval via
 * router.refresh() — pauses while the tab isn't visible so backgrounded
 * tabs don't keep polling. Renders nothing.
 *
 * Only suitable for pages with no client-owned state that would be
 * clobbered by a fresh server render (e.g. accumulated infinite-scroll
 * results) — see EventTable's own, different polling approach for why
 * that page can't just use this component.
 */
export function AutoRefresh({ intervalMs }: { intervalMs: number }) {
  const router = useRouter();

  useEffect(() => {
    const id = setInterval(() => {
      if (document.visibilityState === "visible") {
        router.refresh();
      }
    }, intervalMs);
    return () => clearInterval(id);
  }, [intervalMs, router]);

  return null;
}
