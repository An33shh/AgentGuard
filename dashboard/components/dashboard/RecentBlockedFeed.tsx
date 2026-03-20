"use client";

import Link from "next/link";
import type { Event } from "@/types";
import { getRiskLevel } from "@/types";
import { timeAgo } from "@/lib/utils";

function RiskBadge({ score }: { score: number }) {
  const level = getRiskLevel(score);
  const styles: Record<string, React.CSSProperties> = {
    low:      { background: "rgba(63,185,80,0.1)",  color: "#3FB950", border: "1px solid rgba(63,185,80,0.2)" },
    medium:   { background: "rgba(210,153,34,0.1)", color: "#D29922", border: "1px solid rgba(210,153,34,0.2)" },
    high:     { background: "rgba(248,81,73,0.1)",  color: "#F85149", border: "1px solid rgba(248,81,73,0.2)" },
    critical: { background: "rgba(248,81,73,0.15)", color: "#F85149", border: "1px solid rgba(248,81,73,0.35)", fontWeight: 600, boxShadow: "0 0 6px rgba(248,81,73,0.2)" },
  };
  return (
    <span
      className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-mono tabular-nums"
      style={styles[level]}
    >
      {(score * 100).toFixed(0)}%
    </span>
  );
}

export function RecentBlockedFeed({ events }: { events: Event[] }) {
  return (
    <div
      className="rounded-xl overflow-hidden h-full flex flex-col"
      style={{
        background: "linear-gradient(135deg, #101828 0%, #0C1220 100%)",
        border: "1px solid rgba(248,81,73,0.12)",
        boxShadow: "inset 0 1px 0 rgba(255,255,255,0.03)",
      }}
    >
      {/* Header */}
      <div
        className="px-5 py-3.5 flex items-center justify-between"
        style={{ borderBottom: "1px solid #1C2844" }}
      >
        <div className="flex items-center gap-2.5">
          <span
            className="w-1.5 h-1.5 rounded-full shrink-0 pulse"
            style={{ background: "#F85149", boxShadow: "0 0 5px rgba(248,81,73,0.7)" }}
          />
          <h3 className="text-sm font-medium text-[#E6EDF3]">Recent Blocks</h3>
        </div>
        {events.length > 0 && (
          <span
            className="text-xs font-mono px-1.5 py-0.5 rounded"
            style={{ background: "rgba(248,81,73,0.1)", color: "#F85149", border: "1px solid rgba(248,81,73,0.2)" }}
          >
            {events.length}
          </span>
        )}
      </div>

      {events.length === 0 ? (
        <div className="flex-1 flex items-center justify-center px-5 py-8 text-sm" style={{ color: "#484F58" }}>
          No blocked actions yet.
        </div>
      ) : (
        <ul className="flex-1 overflow-auto">
          {events.slice(0, 8).map((event, i) => (
            <li key={event.event_id} style={{ borderBottom: i < Math.min(events.length, 8) - 1 ? "1px solid #1C2844" : undefined }}>
              <Link
                href={`/events/${event.event_id}`}
                className="flex items-start gap-3 px-5 py-3 transition-colors"
                style={{ cursor: "pointer" }}
                onMouseEnter={(e) => (e.currentTarget.style.background = "rgba(248,81,73,0.04)")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="font-mono text-xs font-medium truncate" style={{ color: "#A0AEBB" }}>
                      {event.action.tool_name}
                    </span>
                    <RiskBadge score={event.assessment.risk_score} />
                  </div>
                  <p className="text-xs truncate leading-relaxed" style={{ color: "#484F58" }}>
                    {event.assessment.reason}
                  </p>
                </div>
                <span className="text-xs shrink-0 mt-0.5 tabular-nums font-mono" style={{ color: "#3A4A5C" }}>
                  {timeAgo(event.timestamp)}
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
