"use client";

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from "recharts";

interface Props {
  trend: number[];
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function CustomTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null;
  const val: number = payload[0].value;
  const color = val >= 75 ? "#F85149" : val >= 50 ? "#D29922" : "#3FB950";
  return (
    <div
      className="rounded-lg px-3 py-2 text-xs shadow-xl"
      style={{ background: "#101828", border: "1px solid #243354" }}
    >
      <p style={{ color: "#6E7D91" }} className="mb-0.5 font-mono">Event {label}</p>
      <p style={{ color }} className="font-semibold font-mono">{val.toFixed(1)}%</p>
    </div>
  );
}

export function RiskTrendSparkline({ trend }: Props) {
  const data = trend.map((v, i) => ({
    index: i + 1,
    risk: parseFloat((v * 100).toFixed(1)),
  }));

  const max = Math.max(...trend);
  const strokeColor = max >= 0.75 ? "#F85149" : max >= 0.5 ? "#D29922" : "#3FB950";
  const gradientId = `trendGradient-${Math.random().toString(36).slice(2, 6)}`;

  return (
    <div
      className="rounded-xl p-5"
      style={{
        background: "linear-gradient(135deg, #101828 0%, #0C1220 100%)",
        border: "1px solid #1C2844",
        boxShadow: "inset 0 1px 0 rgba(255,255,255,0.03)",
      }}
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xs font-medium uppercase tracking-wider" style={{ color: "#6E7D91" }}>
          Risk Trend
        </h3>
        <span className="text-xs font-mono" style={{ color: "#484F58" }}>
          last {trend.length} events
        </span>
      </div>
      <ResponsiveContainer width="100%" height={80}>
        <AreaChart data={data} margin={{ top: 4, right: 4, left: -32, bottom: 0 }}>
          <defs>
            <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor={strokeColor} stopOpacity={0.2} />
              <stop offset="95%" stopColor={strokeColor} stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis
            dataKey="index"
            tick={{ fontSize: 10, fill: "#3A4A5C", fontFamily: "var(--font-mono)" }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            domain={[0, 100]}
            tick={{ fontSize: 10, fill: "#3A4A5C", fontFamily: "var(--font-mono)" }}
            axisLine={false}
            tickLine={false}
            tickFormatter={(v) => `${v}%`}
          />
          <Tooltip content={<CustomTooltip />} />
          <ReferenceLine y={75} stroke="#F85149" strokeDasharray="3 3" strokeWidth={1} strokeOpacity={0.35} />
          <Area
            type="monotone"
            dataKey="risk"
            stroke={strokeColor}
            strokeWidth={1.5}
            fill={`url(#${gradientId})`}
            dot={{ r: 3, fill: strokeColor, stroke: "#0C1220", strokeWidth: 1.5 }}
            activeDot={{ r: 4, fill: strokeColor, stroke: "#0C1220", strokeWidth: 2 }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
