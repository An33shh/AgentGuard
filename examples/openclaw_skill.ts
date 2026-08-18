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
 * Fails closed by default when AgentGuard is unreachable, but not
 * blanket-closed: FAIL_MODE="tiered" (the default) classifies each pending
 * tool call locally against a conservative destructive/credential pattern
 * set and fails closed only for that high-stakes tier, failing open (with
 * a loud console warning) for everything else. This is the risk-tiered
 * design AgentGuard's proxy itself doesn't need (it's reachable, so it can
 * always ask the real analyzer) — it exists here specifically for the
 * window where AgentGuard is down and the skill has to decide on its own.
 * AgentGuard's proxy sits inline in the request path (every tool call
 * passes through it), which puts it in the same category as a WAF or an
 * authorization layer, not a passive monitoring system like a SIEM —
 * AWS's own WAF/ALB integration defaults to the analogous choice
 * (unreachable WAF = treat request as malicious) for exactly this reason.
 * FAIL_MODE="closed"/"open" remain available as deliberate, blanket
 * overrides for operators who want the simpler all-or-nothing behavior —
 * flip it deliberately, not by deleting this comment.
 *
 * The local classifier (isHighStakes, below) is a conservative SUBSET of
 * agentguard/analyzer/patterns.py's DESTRUCTIVE_SHELL/CREDENTIAL
 * categories, duplicated here rather than fetched at runtime — an
 * AgentGuard-unreachable code path can't depend on fetching anything from
 * AgentGuard. Keep it loosely in sync by hand: if patterns.py gains a new
 * DESTRUCTIVE_SHELL/CREDENTIAL pattern that materially changes what
 * "high-stakes" means, mirror it here too. This was weighed against
 * generating this list from patterns.py at build time — rejected for now
 * as unwarranted complexity for one example skill file with no existing
 * codegen pipeline; drift here only makes the outage fallback slightly
 * more permissive than production, never less safe than a full
 * FAIL_MODE="open" outage would already be.
 *
 * Usage in OpenClaw config (workspace/skills/agentguard.ts):
 *   Import and call guardToolCall() from a custom skill that wraps your
 *   existing skill invocations, or use as OpenClaw middleware.
 */

const AGENTGUARD_API_URL =
  process.env.AGENTGUARD_API_URL ?? "http://localhost:8747";
const AGENTGUARD_API_TOKEN = process.env.AGENTGUARD_API_TOKEN ?? "";

// "tiered" (default): fail closed for high-stakes calls (see
// isHighStakes), fail open for everything else, when AgentGuard is
// unreachable. "closed": fail closed for every call, no exceptions.
// "open": fail open for every call. See the module comment above.
type FailMode = "tiered" | "closed" | "open";
const FAIL_MODE: FailMode = "tiered";

/**
 * Conservative, LOCAL-ONLY classifier used exclusively during an
 * AgentGuard outage (handleUnavailable) to decide whether THIS tool call
 * is high-stakes enough to fail closed. Not a replacement for AgentGuard's
 * real analysis (LLM intent analysis, prompt-injection scanning, ABAC) —
 * those only run when AgentGuard is reachable, which is the normal case.
 */
const HIGH_STAKES_PATTERNS: RegExp[] = [
  // Destructive shell (mirrors DetectionCategory.DESTRUCTIVE_SHELL).
  // Lookaheads, not sequential groups — a combined single flag like "-rf"
  // must match both the recursive and force checks against the SAME
  // token; two sequential groups (an earlier draft of this pattern) miss
  // that case entirely, since both letters get consumed by the first
  // group and there's no second flag left for the second group to match.
  /(?<!-)\brm\s+(?=.*(?:-[a-zA-Z]*r[a-zA-Z]*\b|--recursive\b))(?=.*(?:-[a-zA-Z]*f[a-zA-Z]*\b|--force\b)).+/i,
  /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/, // fork bomb
  /(?:curl|wget)\s+.*\|\s*(?:sudo\s+)?(?:sh|bash|zsh)\b/i,
  /\bchmod\s+(?:-[a-zA-Z]+\s+)?[0-7]*777\b/,
  /\bdd\s+.*\bof=\/dev\//,
  /\bsudo\b/,
  // Credentials (mirrors DetectionCategory.CREDENTIAL)
  /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/,
  /\b(?:sk-ant-|sk-|ghp_|gho_|github_pat_|AKIA[0-9A-Z]{16})[A-Za-z0-9\-_]{10,}/,
  /(?:password|passwd|secret|api[_-]?key|token)\s*[=:]\s*['"]\S{8,}['"]/i,
  /\.ssh\/|\.aws\/credentials|\.netrc\b|id_rsa|id_ecdsa|id_dsa|\bshadow\b|\bsudoers\b/i,
];

function isHighStakes(
  toolName: string,
  parameters: Record<string, unknown>
): boolean {
  const haystack = [
    toolName,
    ...Object.values(parameters).map((v) =>
      typeof v === "string" ? v : JSON.stringify(v)
    ),
  ].join("\n");
  return HIGH_STAKES_PATTERNS.some((re) => re.test(haystack));
}

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
    return handleUnavailable(toolName, parameters, sessionId, err);
  }

  if (!res.ok) {
    return handleUnavailable(toolName, parameters, sessionId, `HTTP ${res.status}`);
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
  parameters: Record<string, unknown>,
  sessionId: string,
  cause: unknown
): InterceptResponse {
  const highStakes = FAIL_MODE === "tiered" && isHighStakes(toolName, parameters);

  if (FAIL_MODE === "closed" || highStakes) {
    throw new AgentGuardUnavailableError(toolName, cause);
  }

  const why =
    FAIL_MODE === "tiered"
      ? "tiered fail-mode judged this call low-stakes"
      : 'FAIL_MODE is "open"';
  console.warn(
    `[AgentGuard] Unreachable (${String(cause)}) — ${why}, allowing ${toolName} unmonitored`
  );
  return {
    decision: "allow",
    risk_score: 0,
    reason: `AgentGuard unreachable — failed open (${FAIL_MODE}): ${String(cause)}`,
    event_id: "",
    session_id: sessionId,
    mitre_technique: null,
    owasp_category: null,
    policy_rule: null,
  };
}
