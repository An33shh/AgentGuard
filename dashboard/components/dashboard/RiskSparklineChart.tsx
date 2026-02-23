"use client";

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
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
  block: "#ef4444",
  review: "#eab308",
  allow: "#22c55e",
};

interface CustomDotProps {
  cx?: number;
  cy?: number;
  payload?: ChartPoint;
}

function CustomDot({ cx = 0, cy = 0, payload }: CustomDotProps) {
  const color = DOT_COLORS[payload?.decision ?? "allow"] ?? "#6b7280";
  return <circle cx={cx} cy={cy} r={4} fill={color} stroke="white" strokeWidth={1.5} />;
}

interface RiskSparklineChartProps {
  events: Event[];
  /** Risk threshold (0–100). Actions at or above this are blocked. Default: 75 */
  riskThreshold?: number;
  /** Review threshold (0–100). Actions at or above this are flagged. Default: 60 */
  reviewThreshold?: number;
}

export function RiskSparklineChart({
  events,
  riskThreshold = 75,
  reviewThreshold = 60,
}: RiskSparklineChartProps) {
  const data = eventsToChartData(events);

  return (
    <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-base font-semibold text-gray-900">Risk Score Timeline</h3>
        <div className="flex items-center gap-4 text-xs text-gray-500">
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500 inline-block" />Blocked</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-yellow-500 inline-block" />Review</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-green-500 inline-block" />Allowed</span>
        </div>
      </div>
      {data.length === 0 ? (
        <div className="h-48 flex items-center justify-center text-sm text-gray-400">
          No data yet. Run the demo to see events.
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={data} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
            <XAxis
              dataKey="time"
              tick={{ fontSize: 11, fill: "#9ca3af" }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              domain={[0, 100]}
              tick={{ fontSize: 11, fill: "#9ca3af" }}
              axisLine={false}
              tickLine={false}
              tickFormatter={(v) => `${v}%`}
            />
            <Tooltip
              formatter={(value) => [`${value}%`, "Risk"]}
              contentStyle={{ fontSize: 12, borderRadius: 8 }}
            />
            <ReferenceLine y={riskThreshold} stroke="#ef4444" strokeDasharray="4 2" strokeWidth={1} />
            <ReferenceLine y={reviewThreshold} stroke="#eab308" strokeDasharray="4 2" strokeWidth={1} />
            <Line
              type="monotone"
              dataKey="risk"
              stroke="#6366f1"
              strokeWidth={2}
              dot={<CustomDot />}
              activeDot={{ r: 6 }}
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
