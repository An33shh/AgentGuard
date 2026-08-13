"use client";

import { useEffect, useState } from "react";
import { getReadiness } from "@/lib/api";
import { DASHBOARD_POLL_INTERVAL_MS } from "@/lib/constants";

export type HealthStatus = "healthy" | "degraded" | "down" | "checking";

// Module-level singleton: every mounted consumer (sidebar nav + dashboard
// badge are both mounted at once on /dashboard) shares ONE poll of
// GET /api/v1/readiness instead of each hook instance running its own
// interval — readiness does real DB/Redis/policy/analyzer checks, not a
// cheap ping, so N mounts must never mean N concurrent pollers.
let currentStatus: HealthStatus = "checking";
const subscribers = new Set<(status: HealthStatus) => void>();
let pollId: ReturnType<typeof setInterval> | null = null;
let activeIntervalMs: number | null = null;

async function checkHealth(): Promise<void> {
  let next: HealthStatus;
  try {
    const r = await getReadiness();
    next = r.status === "healthy" ? "healthy" : "degraded";
  } catch {
    next = "down";
  }
  currentStatus = next;
  subscribers.forEach((notify) => notify(next));
}

function startPolling(intervalMs: number): void {
  if (pollId !== null && activeIntervalMs === intervalMs) return;
  if (pollId !== null) clearInterval(pollId);
  activeIntervalMs = intervalMs;
  checkHealth();
  pollId = setInterval(() => {
    if (document.visibilityState === "visible") checkHealth();
  }, intervalMs);
}

function stopPolling(): void {
  if (pollId !== null) {
    clearInterval(pollId);
    pollId = null;
    activeIntervalMs = null;
  }
}

/**
 * Subscribes to a shared, module-level poll of GET /api/v1/readiness (real
 * DB/Redis/policy/analyzer checks, not just liveness) so status indicators
 * reflect whether monitoring is actually working, not just whether the
 * FastAPI process is up. Starts as "checking" (neutral) rather than
 * defaulting to "healthy" — the whole point is never falsely claiming
 * healthy before we've actually verified it, which is exactly the bug this
 * replaces (a hardcoded green dot).
 */
export function useHealthStatus(intervalMs: number = DASHBOARD_POLL_INTERVAL_MS): HealthStatus {
  const [status, setStatus] = useState<HealthStatus>(currentStatus);

  useEffect(() => {
    // No sync setStatus() here — useState(currentStatus) above already
    // captures the shared status as of this component's initial render;
    // subsequent updates arrive via the subscriber callback below.
    subscribers.add(setStatus);
    startPolling(intervalMs);

    return () => {
      subscribers.delete(setStatus);
      if (subscribers.size === 0) stopPolling();
    };
  }, [intervalMs]);

  return status;
}
