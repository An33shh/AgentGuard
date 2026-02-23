"use client";

import dynamic from "next/dynamic";
import { useMemo, useCallback, useState, useEffect, useRef } from "react";
import { createPortal } from "react-dom";
import type { AgentGraphData, GraphNode } from "@/types";

// ── Palette ───────────────────────────────────────────────────────────────────

const NODE_COLORS: Record<string, string> = {
  agent:   "#818cf8",
  session: "#38bdf8",
  tool:    "#34d399",
  pattern: "#f87171",
};

const LINK_COLORS: Record<string, string> = {
  had_session:       "#475569",
  used_tool:         "#6366f1",
  exhibited_pattern: "#ef4444",
};

const PATTERN_DESCRIPTIONS: Record<string, string> = {
  prompt_injection:        "Malicious content in the agent's input tried to override its instructions.",
  credential_exfiltration: "The agent attempted to read credentials such as SSH keys, tokens, or .env files.",
  memory_poisoning:        "The agent attempted to write false or malicious data into its persistent memory.",
  goal_hijacking:          "The agent's original goal was redirected toward a different, malicious objective.",
  data_exfiltration:       "Sensitive data was about to be sent to an external endpoint outside the expected scope.",
  path_blacklist:          "Access to a file path explicitly blocked by the active security policy.",
  domain_blacklist:        "A network request to a domain flagged as suspicious or blocked by policy.",
};

const NODE_RADII: Record<string, number> = { agent: 22, session: 14, tool: 10, pattern: 10 };
const DIM_COLOR = "#0f172a";

// ── Canvas node rendering ─────────────────────────────────────────────────────
// Each node is drawn with: glow ring → filled circle → label below

type NodeCanvasObj = GraphNode & { x?: number; y?: number };

function drawNode(
  node: NodeCanvasObj,
  ctx: CanvasRenderingContext2D,
  globalScale: number,
  isHovered: boolean,
  isDimmed: boolean,
) {
  const x = node.x ?? 0;
  const y = node.y ?? 0;
  const r = (NODE_RADII[node.type] ?? 10) / globalScale;
  const color = isDimmed ? DIM_COLOR : (NODE_COLORS[node.type] ?? "#94a3b8");

  // Outer glow ring (only when not dimmed)
  if (!isDimmed) {
    const glowR = isHovered ? r * 2.8 : r * 2.2;
    const gradient = ctx.createRadialGradient(x, y, r * 0.5, x, y, glowR);
    gradient.addColorStop(0, color + "44");
    gradient.addColorStop(1, color + "00");
    ctx.beginPath();
    ctx.arc(x, y, glowR, 0, Math.PI * 2);
    ctx.fillStyle = gradient;
    ctx.fill();
  }

  // Node circle
  ctx.beginPath();
  ctx.arc(x, y, r, 0, Math.PI * 2);
  ctx.fillStyle = isDimmed ? DIM_COLOR : color + "33";
  ctx.fill();
  ctx.strokeStyle = isDimmed ? "#1e293b" : color;
  ctx.lineWidth = (isHovered ? 2.5 : 1.5) / globalScale;
  ctx.stroke();

  if (isDimmed) return;

  // Label — drawn below the circle, always readable
  const label = (node.label ?? node.id).slice(0, 26);
  const fontSize = Math.max(11 / globalScale, 3);
  ctx.font = `600 ${fontSize}px Inter, system-ui, sans-serif`;
  const labelY = y + r + fontSize * 1.1;
  const tw = ctx.measureText(label).width;
  const padX = fontSize * 0.5, padY = fontSize * 0.3;

  // Pill background for contrast
  ctx.fillStyle = "rgba(3,7,18,0.82)";
  ctx.beginPath();
  ctx.roundRect(x - tw / 2 - padX, labelY - fontSize * 0.7 - padY, tw + padX * 2, fontSize + padY * 2, fontSize * 0.5);
  ctx.fill();

  ctx.fillStyle = isHovered ? "#ffffff" : "#e2e8f0";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.fillText(label, x, labelY);
}

// ── Starfield (drawn once onto bg canvas) ─────────────────────────────────────

function drawStarfield(canvas: HTMLCanvasElement) {
  const ctx = canvas.getContext("2d");
  if (!ctx) return;
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#030712";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  for (let i = 0; i < 220; i++) {
    const x = Math.random() * canvas.width;
    const y = Math.random() * canvas.height;
    const r = 0.3 + Math.random() * 1.2;
    const alpha = 0.25 + Math.random() * 0.6;
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.fillStyle = `rgba(255,255,255,${alpha})`;
    ctx.fill();
  }
  // A handful of slightly larger bright stars
  for (let i = 0; i < 18; i++) {
    const x = Math.random() * canvas.width;
    const y = Math.random() * canvas.height;
    ctx.beginPath();
    ctx.arc(x, y, 1.5, 0, Math.PI * 2);
    ctx.fillStyle = "rgba(200,220,255,0.9)";
    ctx.fill();
  }
}

// ── Node info panel ───────────────────────────────────────────────────────────

function NodeInfoPanel({ node, onClose }: { node: NodeCanvasObj; onClose: () => void }) {
  const color = NODE_COLORS[node.type] ?? "#94a3b8";
  const TYPE_LABELS: Record<string, string> = {
    agent: "Agent", session: "Session", tool: "Tool", pattern: "Attack Pattern",
  };
  return (
    <div className="absolute bottom-10 right-4 z-20 w-72 bg-gray-900/95 backdrop-blur-md rounded-xl border border-gray-700 shadow-2xl p-4 text-sm">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs uppercase tracking-widest font-bold" style={{ color }}>
          {TYPE_LABELS[node.type] ?? node.type}
        </span>
        <button onClick={onClose} className="text-gray-600 hover:text-gray-300 transition-colors leading-none">✕</button>
      </div>

      <p className="font-semibold text-white mb-3 leading-snug">{node.label ?? node.id}</p>

      {node.type === "agent" && (
        <div className="space-y-2 text-xs text-gray-400">
          <p>The AI agent being monitored. All sessions, tools used, and attack patterns it triggered branch from this node.</p>
          <p className="font-mono text-gray-600 break-all">{node.agent_id}</p>
          <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-medium ${
            node.is_registered ? "bg-indigo-900/60 text-indigo-300" : "bg-gray-800 text-gray-500"
          }`}>
            {node.is_registered ? "Registered agent" : "Auto-detected"}
          </span>
        </div>
      )}

      {node.type === "session" && (
        <div className="space-y-2 text-xs text-gray-400">
          <p>A single task run by this agent. Multiple sessions show repeated or persistent activity over time.</p>
          <p className="font-mono text-gray-600 break-all">{node.session_id}</p>
          {node.timestamp && <p className="text-gray-600">{new Date(node.timestamp).toLocaleString()}</p>}
        </div>
      )}

      {node.type === "tool" && (
        <div className="space-y-2 text-xs text-gray-400">
          <p>A function or capability the agent attempted to call during its sessions.</p>
          {node.decision && (
            <span className={`inline-block px-2 py-0.5 rounded-full text-xs font-medium ${
              node.decision === "block"  ? "bg-red-900/50 text-red-400"    :
              node.decision === "allow"  ? "bg-green-900/50 text-green-400" :
                                           "bg-yellow-900/50 text-yellow-400"
            }`}>
              {node.decision.toUpperCase()}
            </span>
          )}
        </div>
      )}

      {node.type === "pattern" && (
        <div className="space-y-2 text-xs">
          <p className="text-red-400 font-semibold">Detected attack pattern</p>
          <p className="text-gray-400">
            {PATTERN_DESCRIPTIONS[node.indicator ?? ""] ?? "Suspicious behaviour flagged by AgentGuard."}
          </p>
        </div>
      )}

      <p className="text-gray-700 text-xs mt-3 italic">Click the same node again to dismiss.</p>
    </div>
  );
}

// ── ForceGraph2D dynamic import ───────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ForceGraph2D = dynamic(() => import("react-force-graph-2d") as Promise<{ default: React.ComponentType<any> }>, {
  ssr: false,
  loading: () => (
    <div className="flex items-center justify-center bg-[#030712] rounded-xl" style={{ height: 500 }}>
      <p className="text-gray-600 text-sm animate-pulse">Loading graph…</p>
    </div>
  ),
});

function ExpandIcon() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4" />
    </svg>
  );
}
function CollapseIcon() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 9L4 4m0 0h5m-5 0v5M15 9l5-5m0 0h-5m5 0v5M9 15l-5 5m0 0h5m-5 0v-5M15 15l5 5m0 0h-5m5 0v-5" />
    </svg>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export interface KnowledgeGraphProps {
  data: AgentGraphData;
  height?: number;
}

export function KnowledgeGraph({ data, height = 500 }: KnowledgeGraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const bgCanvasRef  = useRef<HTMLCanvasElement>(null);
  const [fullscreen, setFullscreen]     = useState(false);
  const [dims, setDims]                 = useState({ w: 0, h: height });
  const [mounted, setMounted]           = useState(false);
  const [hoveredId, setHoveredId]       = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<NodeCanvasObj | null>(null);

  useEffect(() => { setMounted(true); }, []);

  // Accurate width via ResizeObserver (fires after layout, not before)
  useEffect(() => {
    if (fullscreen) return;
    const el = containerRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([entry]) => {
      const w = Math.floor(entry.contentRect.width);
      if (w > 0) setDims((d) => ({ ...d, w }));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [fullscreen]);

  useEffect(() => {
    if (!fullscreen) return;
    const update = () => setDims({ w: window.innerWidth, h: window.innerHeight });
    update();
    window.addEventListener("resize", update);
    return () => window.removeEventListener("resize", update);
  }, [fullscreen]);

  useEffect(() => {
    if (!fullscreen) return;
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") setFullscreen(false); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [fullscreen]);

  // Draw starfield background whenever dims change
  useEffect(() => {
    const canvas = bgCanvasRef.current;
    if (!canvas || dims.w === 0) return;
    canvas.width  = dims.w;
    canvas.height = dims.h;
    drawStarfield(canvas);
  }, [dims]);

  const graphData = useMemo(() => ({
    nodes: data.nodes.map((n) => ({ ...n })),
    links: data.edges.map((e) => ({ ...e })),
  }), [data]);

  // Hover neighbourhood
  const connectedIds = useMemo<Set<string> | null>(() => {
    if (!hoveredId) return null;
    const ids = new Set([hoveredId]);
    graphData.links.forEach((link) => {
      const s = typeof link.source === "object" ? (link.source as { id: string }).id : String(link.source);
      const t = typeof link.target === "object" ? (link.target as { id: string }).id : String(link.target);
      if (s === hoveredId) ids.add(t);
      if (t === hoveredId) ids.add(s);
    });
    return ids;
  }, [hoveredId, graphData.links]);

  const nodeCanvasObject = useCallback((node: object, ctx: CanvasRenderingContext2D, globalScale: number) => {
    const n = node as NodeCanvasObj;
    const isHovered = n.id === hoveredId;
    const isDimmed  = connectedIds !== null && !connectedIds.has(n.id);
    drawNode(n, ctx, globalScale, isHovered, isDimmed);
  }, [hoveredId, connectedIds]);

  const linkColor = useCallback((link: object) => {
    const l = link as { type: string; source: unknown; target: unknown };
    const base = LINK_COLORS[l.type] ?? "#475569";
    if (!connectedIds) return base;
    const s = typeof l.source === "object" ? (l.source as { id: string }).id : String(l.source);
    const t = typeof l.target === "object" ? (l.target as { id: string }).id : String(l.target);
    return (connectedIds.has(s) && connectedIds.has(t)) ? base : "#0d1520";
  }, [connectedIds]);

  const linkWidth = useCallback((link: object) => {
    const l = link as { type: string; source: unknown; target: unknown };
    if (!connectedIds) return 1.5;
    const s = typeof l.source === "object" ? (l.source as { id: string }).id : String(l.source);
    const t = typeof l.target === "object" ? (l.target as { id: string }).id : String(l.target);
    return (connectedIds.has(s) && connectedIds.has(t)) ? 2.5 : 0.5;
  }, [connectedIds]);

  const handleNodeHover = useCallback((node: object | null) => {
    setHoveredId(node ? (node as NodeCanvasObj).id : null);
  }, []);

  const handleNodeClick = useCallback((node: object) => {
    const n = node as NodeCanvasObj;
    setSelectedNode((prev) => (prev?.id === n.id ? null : n));
  }, []);

  const content = (
    <div
      ref={containerRef}
      className={
        fullscreen
          ? "fixed inset-0 z-50"
          : "relative w-full rounded-xl overflow-hidden border border-gray-800"
      }
    >
      {data.nodes.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-64 bg-[#030712] gap-2 rounded-xl">
          <p className="text-gray-500 text-sm">No graph data yet.</p>
          <p className="text-gray-700 text-xs font-mono">python examples/demo_attack.py</p>
        </div>
      ) : (
        <>
          {/* Starfield background canvas */}
          <canvas
            ref={bgCanvasRef}
            className="absolute inset-0 pointer-events-none"
            style={{ width: dims.w, height: dims.h }}
          />

          {/* ── Top bar ── */}
          <div className="absolute top-0 left-0 right-0 z-10 flex items-center justify-between px-4 py-3">
            <div className="flex flex-wrap gap-2 pointer-events-none">
              {[
                { type: "agent",   label: "Agent",   desc: "The monitored AI agent"     },
                { type: "session", label: "Session",  desc: "A single task run"          },
                { type: "tool",    label: "Tool",     desc: "A function the agent called" },
                { type: "pattern", label: "Attack",   desc: "Detected attack pattern"    },
              ].map(({ type, label, desc }) => (
                <span
                  key={type}
                  className="text-xs px-2 py-0.5 rounded-full text-white/90 font-medium backdrop-blur-sm"
                  style={{ backgroundColor: `${NODE_COLORS[type]}22`, border: `1px solid ${NODE_COLORS[type]}55` }}
                  title={desc}
                >
                  {label}
                </span>
              ))}
            </div>
            <button
              onClick={() => setFullscreen((f) => !f)}
              className="text-gray-500 hover:text-white transition-colors p-1.5 rounded-lg hover:bg-white/10 backdrop-blur-sm"
              title={fullscreen ? "Exit fullscreen (Esc)" : "Expand to fullscreen"}
            >
              {fullscreen ? <CollapseIcon /> : <ExpandIcon />}
            </button>
          </div>

          {/* ── Interaction hint ── */}
          <div className="absolute top-12 right-4 z-10 text-right pointer-events-none select-none">
            <p className="text-xs text-gray-700">Scroll to zoom · Drag to pan</p>
            <p className="text-xs text-gray-700">Hover to highlight · Click to inspect</p>
          </div>

          {/* ── Node info panel ── */}
          {selectedNode && (
            <NodeInfoPanel node={selectedNode} onClose={() => setSelectedNode(null)} />
          )}

          {/* ── Stats ── */}
          <div className="absolute bottom-3 left-4 z-10 text-xs text-gray-700 pointer-events-none select-none">
            {data.nodes.length} nodes · {data.edges.length} edges
            {fullscreen && <span className="ml-3">· Esc to exit</span>}
          </div>

          {dims.w > 0 && (
            <ForceGraph2D
              graphData={graphData}
              width={dims.w}
              height={dims.h}
              backgroundColor="transparent"
              nodeCanvasObject={nodeCanvasObject}
              nodeCanvasObjectMode={() => "replace"}
              nodePointerAreaPaint={(node: object, color: string, ctx: CanvasRenderingContext2D) => {
                const n = node as NodeCanvasObj;
                const r = (NODE_RADII[n.type] ?? 10);
                ctx.beginPath();
                ctx.arc(n.x ?? 0, n.y ?? 0, r + 6, 0, Math.PI * 2);
                ctx.fillStyle = color;
                ctx.fill();
              }}
              linkColor={linkColor}
              linkWidth={linkWidth}
              linkDirectionalArrowLength={6}
              linkDirectionalArrowRelPos={1}
              linkDirectionalParticles={2}
              linkDirectionalParticleSpeed={0.004}
              linkDirectionalParticleColor={linkColor}
              onNodeHover={handleNodeHover}
              onNodeClick={handleNodeClick}
              cooldownTime={2500}
              d3AlphaDecay={0.02}
              d3VelocityDecay={0.3}
              enableNodeDrag
              enablePanInteraction
              enableZoomInteraction
            />
          )}
        </>
      )}
    </div>
  );

  return (fullscreen && mounted) ? createPortal(content, document.body) : content;
}
