/**
 * AgentGuard ClawHub skill for OpenClaw.
 *
 * Install in OpenClaw:
 *   Place this file in your workspace skills directory, or publish to ClawHub.
 *   Set AGENTGUARD_API_URL and (if auth is enabled) AGENTGUARD_API_TOKEN
 *   in your OpenClaw environment.
 *
 * What it does:
 *   Wraps any tool call with a pre-flight check against AgentGuard's intent
 *   analyzer before OpenClaw executes it. If AgentGuard returns "block",
 *   the skill throws and OpenClaw never runs the original tool.
 *
 * Fails closed: if AgentGuard is unreachable or errors, the tool call is
 * blocked rather than silently allowed. AgentGuard's proxy sits inline in
 * the request path (every tool call passes through it), which puts it in
 * the same category as a WAF or an authorization layer, not a passive
 * monitoring system like a SIEM — AWS's own WAF/ALB integration defaults
 * to the same choice (an unreachable WAF is treated as if the request
 * were malicious), with fail-open available only as a deliberate, monitored
 * opt-in, never the default. If your threat model genuinely needs
 * availability over enforcement for this integration, override
 * FAIL_MODE below — but do it deliberately, not by deleting this comment.
 *
 * Long-term direction (not yet implemented here — tracked in
 * tasks/todo.md): per-tool-call risk tiering instead of one binary switch
 * for the whole skill, e.g. fail closed for shell/credential-shaped tool
 * calls and fail open for low-stakes reads. Needs a decision on where the
 * classification logic lives (duplicated in TS vs. sourced from
 * agentguard/analyzer/patterns.py) before it's worth building.
 *
 * Usage in OpenClaw config (workspace/skills/agentguard.ts):
 *   Import and call guardToolCall() from a custom skill that wraps your
 *   existing skill invocations, or use as OpenClaw middleware.
 */

const AGENTGUARD_API_URL =
  process.env.AGENTGUARD_API_URL ?? "http://localhost:8747";
const AGENTGUARD_API_TOKEN = process.env.AGENTGUARD_API_TOKEN ?? "";

// Set to "open" to allow tool calls through when AgentGuard is unreachable
// instead of blocking them. Fail-closed (the default) means an AgentGuard
// outage stops the agent; fail-open means it keeps running unmonitored
// until AgentGuard comes back. See the module comment above before flipping this.
const FAIL_MODE: "closed" | "open" = "closed";

interface InterceptRequest {
  tool_name: string;
  parameters: Record<string, unknown>;
  goal: string;
  session_id: string;
  framework: string;
}

interface InterceptResponse {
  decision: "allow" | "block" | "review";
  risk_score: number;
  reason: string;
  event_id: string;
  session_id: string;
  mitre_technique: string | null;
  owasp_category: string | null;
  policy_rule: string | null;
}

export class AgentGuardBlockedError extends Error {
  readonly decision: InterceptResponse;
  constructor(response: InterceptResponse) {
    super(
      `[AgentGuard] Tool blocked — ${response.reason} (risk: ${(response.risk_score * 100).toFixed(1)}%)`
    );
    this.name = "AgentGuardBlockedError";
    this.decision = response;
  }
}

/**
 * Thrown when AgentGuard can't be reached or errors, and FAIL_MODE is
 * "closed" (the default) — distinct from AgentGuardBlockedError so
 * operators can immediately tell "a tool call was judged dangerous" apart
 * from "AgentGuard itself is down," which need very different responses.
 */
export class AgentGuardUnavailableError extends Error {
  readonly cause: unknown;
  constructor(toolName: string, cause: unknown) {
    super(
      `[AgentGuard] Unreachable or erroring — failing closed for ${toolName}: ${String(cause)}`
    );
    this.name = "AgentGuardUnavailableError";
    this.cause = cause;
  }
}

/**
 * Pre-flight check before any tool call.
 *
 * @param toolName   OpenClaw skill identifier (e.g. "browser.navigate")
 * @param parameters Skill arguments
 * @param goal       Agent's declared purpose for this session
 * @param sessionId  Consistent ID across a single agent session
 * @returns          The intercept response (decision, risk score, reason)
 * @throws           AgentGuardBlockedError when decision === "block"
 * @throws           AgentGuardUnavailableError when AgentGuard is
 *                    unreachable/erroring and FAIL_MODE === "closed"
 */
export async function guardToolCall(
  toolName: string,
  parameters: Record<string, unknown>,
  goal: string,
  sessionId: string
): Promise<InterceptResponse> {
  const body: InterceptRequest = {
    tool_name: toolName,
    parameters,
    goal,
    session_id: sessionId,
    framework: "openclaw",
  };

  const headers: HeadersInit = { "Content-Type": "application/json" };
  if (AGENTGUARD_API_TOKEN) {
    headers["Authorization"] = `Bearer ${AGENTGUARD_API_TOKEN}`;
  }

  // Both a network-level failure (fetch() throwing — DNS, connection
  // refused, timeout) and an HTTP-level failure (fetch() resolving with a
  // non-ok status) mean the same thing to the caller — "AgentGuard could
  // not evaluate this call" — and must be handled identically. Splitting
  // them (letting one propagate as an uncaught exception while the other
  // was quietly turned into a synthetic "allow") was the original bug:
  // one path was accidentally fail-closed, the other deliberately
  // fail-open, with no single place documenting or controlling the choice.
  let res: Response;
  try {
    res = await fetch(`${AGENTGUARD_API_URL}/api/v1/intercept`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
  } catch (err) {
    return handleUnavailable(toolName, sessionId, err);
  }

  if (!res.ok) {
    return handleUnavailable(toolName, sessionId, `HTTP ${res.status}`);
  }

  const result: InterceptResponse = await res.json();

  if (result.decision === "block") {
    throw new AgentGuardBlockedError(result);
  }

  if (result.decision === "review") {
    console.warn(
      `[AgentGuard] Tool flagged for review: ${toolName} — ` +
        `risk ${(result.risk_score * 100).toFixed(1)}% — ${result.reason}`
    );
  }

  return result;
}

function handleUnavailable(
  toolName: string,
  sessionId: string,
  cause: unknown
): InterceptResponse {
  if (FAIL_MODE === "closed") {
    throw new AgentGuardUnavailableError(toolName, cause);
  }
  console.warn(
    `[AgentGuard] Unreachable (${String(cause)}) — FAIL_MODE is "open", allowing ${toolName} unmonitored`
  );
  return {
    decision: "allow",
    risk_score: 0,
    reason: `AgentGuard unreachable — failed open: ${String(cause)}`,
    event_id: "",
    session_id: sessionId,
    mitre_technique: null,
    owasp_category: null,
    policy_rule: null,
  };
}
