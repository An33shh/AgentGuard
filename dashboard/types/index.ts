// TypeScript types mirroring Python AgentGuard models

export type ProvenanceSourceType =
  | "user_instruction"
  | "tool_output"
  | "external_data"
  | "agent_generated"
  | "system";

export interface ProvenanceTag {
  source_type: ProvenanceSourceType;
  label: string;
  value?: string;
  inherited_from?: string | null;
}

export type ActionType =
  | "tool_call"
  | "shell_command"
  | "file_read"
  | "file_write"
  | "http_request"
  | "memory_write"
  | "credential_access"
  | "unknown";

export type Decision = "allow" | "block" | "review";

export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface Action {
  action_id: string;
  type: ActionType;
  tool_name: string;
  parameters: Record<string, unknown>;
  raw_payload: Record<string, unknown>;
  timestamp: string;
}

export interface AttackTaxonomyAnnotation {
  attack_pattern: string;
  mitre_atlas_ids: string[];
  owasp_categories: string[];
  confidence: number;
}

export interface RiskAssessment {
  risk_score: number;
  reason: string;
  indicators: string[];
  is_goal_aligned: boolean;
  analyzer_model: string;
  latency_ms: number;
  attack_taxonomy: AttackTaxonomyAnnotation | null;
}

export interface PolicyViolation {
  rule_name: string;
  rule_type: string;
  detail: string;
  decision: Decision;
  mitre_atlas_ids: string[];
  owasp_categories: string[];
}

export interface Event {
  event_id: string;
  session_id: string;
  agent_goal: string;
  action: Action;
  assessment: RiskAssessment;
  decision: Decision;
  policy_violation: PolicyViolation | null;
  timestamp: string;
  provenance: ProvenanceTag[];
  framework: string;
}

export interface SessionSummary {
  session_id: string;
  agent_goal: string;
  framework: string;
  total_events: number;
  blocked_events: number;
  updated_at: string;
}

export interface TimelineSummary {
  session_id: string;
  total_events: number;
  blocked_events: number;
  reviewed_events: number;
  allowed_events: number;
  max_risk_score: number;
  avg_risk_score: number;
  start_time: string | null;
  end_time: string | null;
  attack_vectors: string[];
}

export interface Stats {
  total_events: number;
  blocked_events: number;
  reviewed_events: number;
  allowed_events: number;
  active_sessions: number;
  avg_risk_score: number;
}

export interface Insight {
  event_id: string;
  analysis: string;
  attack_patterns: string[];
  confidence: number;
  severity: RiskLevel;
  recommended_action: string;
  false_positive_likelihood: number;
  created_at: string;
}

export interface PolicyRuleAnnotation {
  mitre_atlas_ids: string[];
  owasp_categories: string[];
  notes: string;
}

export interface PolicyDemotionConfig {
  enabled: boolean;
  trigger_blocked_count: number;
  demoted_risk_threshold: number;
  demoted_review_threshold: number;
}

export interface PolicyConfig {
  name: string;
  risk_threshold: number;
  review_threshold: number;
  deny_tools: string[];
  deny_path_patterns: string[];
  deny_domains: string[];
  review_tools: string[];
  allow_tools: string[];
  session_limits: {
    max_actions: number;
    max_blocked: number;
  };
  deny_unregistered_tools: string[];
  deny_provenance_sources: string[];
  demotion: PolicyDemotionConfig;
  rule_annotations: Record<string, PolicyRuleAnnotation>;
}

export interface AgentProfile {
  agent_id: string;
  display_name: string;  // AI-generated concise name (e.g. "README Analyzer")
  agent_goal: string;    // Raw goal string (full context, used in detail views)
  is_registered: boolean;
  framework: string;
  first_seen: string;
  last_seen: string;
  total_sessions: number;
  total_events: number;
  blocked_events: number;
  reviewed_events: number;
  allowed_events: number;
  avg_risk_score: number;
  max_risk_score: number;
  attack_patterns: string[];
  tools_used: string[];
  risk_trend: number[];
}

export interface GraphNode {
  id: string;
  type: "agent" | "session" | "tool" | "pattern";
  label: string;
  // agent
  agent_id?: string;
  is_registered?: boolean;
  total_events?: number;
  avg_risk?: number;
  // session
  session_id?: string;
  timestamp?: string;
  // tool
  decision?: string;
  // pattern
  indicator?: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: "had_session" | "used_tool" | "exhibited_pattern";
  decision?: string;
  risk_score?: number;
}

export interface AgentGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export function getRiskLevel(score: number): RiskLevel {
  if (score < 0.3) return "low";
  if (score < 0.6) return "medium";
  if (score < 0.75) return "high";
  return "critical";
}

export function getRiskColor(level: RiskLevel): string {
  switch (level) {
    case "low": return "text-green-600";
    case "medium": return "text-yellow-600";
    case "high": return "text-orange-600";
    case "critical": return "text-red-600";
  }
}

export function getDecisionColor(decision: Decision): string {
  switch (decision) {
    case "allow": return "text-green-600 bg-green-50";
    case "block": return "text-red-600 bg-red-50";
    case "review": return "text-yellow-600 bg-yellow-50";
  }
}

// Canonical risk/severity color tokens for the dashboard's dark theme —
// new code should use this instead of hand-rolling its own {bg,border,text}
// record (several existing components predate this and aren't retrofitted
// here; that's a separate, unrequested cleanup).
export const RISK_STYLES: Record<RiskLevel, { text: string; bg: string; border: string }> = {
  low:      { text: "#3FB950", bg: "rgba(63,185,80,0.1)",  border: "rgba(63,185,80,0.2)" },
  medium:   { text: "#D29922", bg: "rgba(210,153,34,0.1)", border: "rgba(210,153,34,0.2)" },
  high:     { text: "#F85149", bg: "rgba(248,81,73,0.1)",  border: "rgba(248,81,73,0.2)" },
  critical: { text: "#F85149", bg: "rgba(248,81,73,0.15)", border: "rgba(248,81,73,0.35)" },
};
