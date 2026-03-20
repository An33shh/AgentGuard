"use client";

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
  Area,
  AreaChart,
} from "recharts";
import type { Event } from "@/types";

interface ChartPoint {
  time: string;
  risk: number;
  decision: string;
}

function eventsToChartData(events: Event[]): ChartPoint[] {
  return events
    .slice()
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
    .map((e) => ({
      time: new Date(e.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      risk: Math.round(e.assessment.risk_score * 100),
      decision: e.decision,
    }));
}

const DOT_COLORS: Record<string, string> = {
  block: "#F85149",
  review: "#D29922",
  allow: "#3FB950",
};

interface CustomDotProps {
  cx?: number;
  cy?: number;
  payload?: ChartPoint;
}

function CustomDot({ cx = 0, cy = 0, payload }: CustomDotProps) {
  const color = DOT_COLORS[payload?.decision ?? "allow"] ?? "#6b7280";
  const isBlock = payload?.decision === "block";
  return (
    <circle
      cx={cx}
      cy={cy}
      r={isBlock ? 4 : 3}
      fill={color}
      stroke="#0C1220"
      strokeWidth={1.5}
      style={isBlock ? { filter: "drop-shadow(0 0 3px rgba(248,81,73,0.7))" } : undefined}
    />
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function CustomTooltip({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  const point: ChartPoint = payload[0].payload;
  const color = DOT_COLORS[point.decision] ?? "#8B949E";
  return (
    <div
      className="rounded-lg px-3 py-2 text-xs shadow-xl"
      style={{
        background: "#101828",
        border: "1px solid #243354",
        boxShadow: "0 8px 24px rgba(0,0,0,0.4)",
      }}
    >
      <p style={{ color: "#6E7D91" }} className="mb-1 font-mono">{point.time}</p>
      <p style={{ color }} className="font-semibold font-mono">
        {point.risk}% <span style={{ color: "#6E7D91" }}>·</span> {point.decision.toUpperCase()}
      </p>
    </div>
  );
}

interface RiskSparklineChartProps {
  events: Event[];
  riskThreshold?: number;
  reviewThreshold?: number;
}

export function RiskSparklineChart({
  events,
  riskThreshold = 75,
  reviewThreshold = 60,
}: RiskSparklineChartProps) {
  const data = eventsToChartData(events);

  return (
    <div
      className="rounded-xl p-5 h-full"
      style={{
        background: "linear-gradient(135deg, #101828 0%, #0C1220 100%)",
        border: "1px solid #1C2844",
        boxShadow: "inset 0 1px 0 rgba(255,255,255,0.03)",
      }}
    >
      <div className="flex items-center justify-between mb-5">
        <div>
          <h3 className="text-sm font-medium text-[#E6EDF3]">Risk Score Timeline</h3>
          <p className="text-xs mt-0.5" style={{ color: "#484F58" }}>
            {data.length} events monitored
          </p>
        </div>
        <div className="flex items-center gap-4 text-xs" style={{ color: "#484F58" }}>
          {[
            { color: "#F85149", label: "Block" },
            { color: "#D29922", label: "Review" },
            { color: "#3FB950", label: "Allow" },
          ].map(({ color, label }) => (
            <span key={label} className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full inline-block" style={{ background: color }} />
              {label}
            </span>
          ))}
        </div>
      </div>
      {data.length === 0 ? (
        <div className="h-48 flex items-center justify-center text-sm" style={{ color: "#484F58" }}>
          No data yet — run the demo to see events.
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
            <defs>
              <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#6366F1" stopOpacity={0.15} />
                <stop offset="95%" stopColor="#6366F1" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis
              dataKey="time"
              tick={{ fontSize: 11, fill: "#484F58", fontFamily: "var(--font-mono)" }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              domain={[0, 100]}
              tick={{ fontSize: 11, fill: "#484F58", fontFamily: "var(--font-mono)" }}
              axisLine={false}
              tickLine={false}
              tickFormatter={(v) => `${v}%`}
            />
            <Tooltip content={<CustomTooltip />} />
            <ReferenceLine y={riskThreshold} stroke="#F85149" strokeDasharray="3 3" strokeWidth={1} strokeOpacity={0.4} />
            <ReferenceLine y={reviewThreshold} stroke="#D29922" strokeDasharray="3 3" strokeWidth={1} strokeOpacity={0.4} />
            <Area
              type="monotone"
              dataKey="risk"
              stroke="#6366F1"
              strokeWidth={1.5}
              fill="url(#riskGradient)"
              dot={<CustomDot />}
              activeDot={{ r: 5, fill: "#6366F1", stroke: "#0C1220", strokeWidth: 2 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
