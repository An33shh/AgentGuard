// TypeScript types mirroring Python AgentGuard models

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

export interface RiskAssessment {
  risk_score: number;
  reason: string;
  indicators: string[];
  is_goal_aligned: boolean;
  analyzer_model: string;
  latency_ms: number;
}

export interface PolicyViolation {
  rule_name: string;
  rule_type: string;
  detail: string;
  decision: Decision;
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
  provenance: Record<string, unknown>;
  framework: string;
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
