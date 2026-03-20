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
 * Usage in OpenClaw config (workspace/skills/agentguard.ts):
 *   Import and call guardToolCall() from a custom skill that wraps your
 *   existing skill invocations, or use as OpenClaw middleware.
 */

const AGENTGUARD_API_URL =
  process.env.AGENTGUARD_API_URL ?? "http://localhost:8000";
const AGENTGUARD_API_TOKEN = process.env.AGENTGUARD_API_TOKEN ?? "";

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
 * Pre-flight check before any tool call.
 *
 * @param toolName   OpenClaw skill identifier (e.g. "browser.navigate")
 * @param parameters Skill arguments
 * @param goal       Agent's declared purpose for this session
 * @param sessionId  Consistent ID across a single agent session
 * @returns          The intercept response (decision, risk score, reason)
 * @throws           AgentGuardBlockedError when decision === "block"
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

  const res = await fetch(`${AGENTGUARD_API_URL}/api/v1/intercept`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    // Fail open — if AgentGuard is unreachable, log and allow.
    // Change to fail-closed by throwing here if your threat model requires it.
    console.warn(
      `[AgentGuard] API unreachable (${res.status}) — failing open for ${toolName}`
    );
    return {
      decision: "allow",
      risk_score: 0,
      reason: "AgentGuard unreachable — failed open",
      event_id: "",
      session_id: sessionId,
      mitre_technique: null,
      owasp_category: null,
      policy_rule: null,
    };
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

/**
 * Example: wrap an existing OpenClaw skill with AgentGuard.
 *
 * In your OpenClaw workspace skill file:
 *
 *   import { guardToolCall } from "./agentguard";
 *
 *   export const skill = {
 *     name: "file.read",
 *     description: "Read a file from the filesystem",
 *     async run({ path }: { path: string }, ctx: SkillContext) {
 *       await guardToolCall("file.read", { path }, ctx.agent.goal, ctx.session.id);
 *       return fs.readFileSync(path, "utf8");
 *     },
 *   };
 */
