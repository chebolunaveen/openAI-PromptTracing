import { randomUUID } from "node:crypto";
import express from "express";
import { z } from "zod";
import type { AgentRunResult, DocumentInput, ToolExecution, Trace, TraceEvent } from "@prompttrace/shared";
import type { AgentResult, AgentRunner } from "./agent.js";
import type { TraceStore } from "./trace-store.js";
import { activeToolPolicies, evaluateToolPolicies, scanDocument } from "@prompttrace/security-engine";
import { getReplayScenario, type ReplayMode, type ReplayScenarioName } from "./demo-scenarios.js";

const requestSchema = z.object({
  userRequest: z.string().min(1).max(8_000),
  document: z.object({
    id: z.string().min(1),
    title: z.string().min(1),
    content: z.string().min(1).max(100_000),
    source: z.enum(["user", "uploaded_document", "web", "rag", "tool_output"]).optional()
  }).optional()
});

const replaySchema = z.object({
  scenario: z.enum(["safe", "malicious"]),
  mode: z.enum(["protected", "vulnerable"])
});

const securityScanSchema = z.object({
  content: z.string().min(1).max(100_000),
  title: z.string().min(1).max(200).default("Scan-only input"),
  source: z.enum(["user", "uploaded_document", "web", "rag", "tool_output"]).default("user")
});

type RunInput = z.infer<typeof requestSchema>;

function materializeDocument(input: RunInput): DocumentInput {
  if (input.document) return input.document;

  return {
    id: `direct-${randomUUID()}`,
    title: "Direct user request",
    content: input.userRequest,
    source: "user"
  };
}

async function buildTrace(
  runner: AgentRunner,
  traceStore: TraceStore,
  input: RunInput,
  mode: ReplayMode = "protected",
  fixedAgentResult?: AgentResult
): Promise<AgentRunResult> {
  const { userRequest } = input;
  const document = materializeDocument(input);
  const traceId = randomUUID();
  const now = new Date().toISOString();
  const events: TraceEvent[] = [
    { id: randomUUID(), timestamp: now, type: "user_request", source: "user", summary: userRequest },
    { id: randomUUID(), timestamp: now, type: "document_received", source: document.source ?? "uploaded_document", summary: document.title }
  ];
  const security = scanDocument(document);
  events.push({
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    type: "security_scan_completed",
    source: document.source ?? "uploaded_document",
    summary: `Security scan completed: ${security.findings.length} finding(s), risk ${security.score}/100 (${security.level})`
  });

  const agentResult = fixedAgentResult ?? await runner.run(userRequest, document);
  events.push({ id: randomUUID(), timestamp: new Date().toISOString(), type: "agent_response", summary: agentResult.summary });
  const policyDecisions = mode === "vulnerable"
    ? agentResult.proposedToolCalls.map((toolCall) => ({
      toolCallId: toolCall.id,
      toolName: toolCall.name,
      decision: "allow" as const,
      reasons: ["Vulnerable replay mode skips PromptTrace policy enforcement."]
    }))
    : evaluateToolPolicies(agentResult.proposedToolCalls, security);

  for (const toolCall of agentResult.proposedToolCalls) {
    const decision = policyDecisions.find((item) => item.toolCallId === toolCall.id);
    events.push({ id: randomUUID(), timestamp: new Date().toISOString(), type: "tool_proposed", summary: `${toolCall.name} proposed; never executed by this demo` });
    events.push({
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      type: "tool_policy_evaluated",
      summary: `${toolCall.name}: ${decision?.decision ?? "block"} — ${(decision?.reasons ?? ["No policy decision found."]).join(" ")}`
    });
  }

  if (fixedAgentResult) {
    events.push({ id: randomUUID(), timestamp: new Date().toISOString(), type: "replay_completed", summary: `${mode} replay completed` });
  }

  const trace: Trace = { id: traceId, createdAt: now, events, security, policyDecisions, toolExecutions: [] };
  traceStore.save(trace);

  for (const toolCall of agentResult.proposedToolCalls) {
    const decision = policyDecisions.find((item) => item.toolCallId === toolCall.id);
    let execution: ToolExecution;
    if (mode === "protected" && decision?.decision === "allow" && toolCall.name === "get_trace_count") {
      execution = {
        toolCallId: toolCall.id,
        toolName: toolCall.name,
        status: "executed",
        result: `SQLite currently stores ${traceStore.count()} trace(s), including this trace.`
      };
    } else {
      execution = {
        toolCallId: toolCall.id,
        toolName: toolCall.name,
        status: "not_executed",
        result: decision?.decision === "block"
          ? "Blocked by PromptTrace policy."
          : decision?.decision === "require_approval"
            ? "Human approval is required before this tool can execute."
            : "No executable handler is configured for this tool."
      };
    }
    trace.toolExecutions.push(execution);
    events.push({
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      type: "tool_executed",
      summary: `${toolCall.name}: ${execution.status} — ${execution.result}`
    });
  }
  traceStore.save(trace);
  return { trace, summary: agentResult.summary, proposedToolCalls: agentResult.proposedToolCalls, policyDecisions, toolExecutions: trace.toolExecutions };
}

export function createApp(runner: AgentRunner, traceStore: TraceStore) {
  const app = express();
  app.use(express.json({ limit: "1mb" }));
  app.use((_request, response, next) => {
    response.setHeader("Access-Control-Allow-Origin", "http://localhost:3000");
    response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    response.setHeader("Access-Control-Allow-Headers", "Content-Type");
    next();
  });
  app.options(/.*/, (_request, response) => response.status(204).end());

  app.get("/health", (_request, response) => response.json({ status: "ok" }));
  app.get("/policies", (_request, response) => response.json({ policies: activeToolPolicies }));

  app.post("/security/scan", (request, response) => {
    const parsed = securityScanSchema.safeParse(request.body);
    if (!parsed.success) return response.status(400).json({ error: "Invalid scan request", details: parsed.error.flatten() });
    const assessment = scanDocument({ id: `scan-${randomUUID()}`, ...parsed.data });
    return response.status(200).json({ assessment });
  });

  app.get("/traces", (request, response) => {
    const requestedLimit = Number(request.query.limit ?? 50);
    const limit = Number.isFinite(requestedLimit) ? requestedLimit : 50;
    return response.json({ traces: traceStore.list(limit) });
  });

  app.get("/traces/:id", (request, response) => {
    const trace = traceStore.findById(request.params.id);
    if (!trace) {
      return response.status(404).json({ error: "Trace not found" });
    }
    return response.json({ trace });
  });

  app.post("/demo/replay", async (request, response) => {
    const parsed = replaySchema.safeParse(request.body);
    if (!parsed.success) return response.status(400).json({ error: "Invalid replay request" });

    const scenario = getReplayScenario(parsed.data.scenario as ReplayScenarioName);
    const input: RunInput = { userRequest: scenario.userRequest, document: scenario.document };
    const result = await buildTrace(runner, traceStore, input, parsed.data.mode as ReplayMode, scenario.agentResult);
    return response.status(200).json({ scenario: scenario.name, mode: parsed.data.mode, ...result });
  });

  app.post("/agent/run", async (request, response) => {
    const parsed = requestSchema.safeParse(request.body);
    if (!parsed.success) {
      return response.status(400).json({ error: "Invalid request", details: parsed.error.flatten() });
    }

    try {
      const result = await buildTrace(runner, traceStore, parsed.data);
      return response.status(200).json(result);
    } catch (error) {
      console.error("Agent request failed", error);
      return response.status(502).json({ error: "Agent request failed" });
    }
  });

  return app;
}
