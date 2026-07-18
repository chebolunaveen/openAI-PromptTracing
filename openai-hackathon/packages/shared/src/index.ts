export type SourceKind = "user" | "uploaded_document" | "web" | "rag" | "tool_output";

export interface DocumentInput {
  id: string;
  title: string;
  content: string;
  source?: SourceKind;
}

export interface ProposedToolCall {
  id: string;
  name: "read_document" | "draft_email" | "get_trace_count";
  arguments: Record<string, unknown>;
}

export interface ToolExecution {
  toolCallId: string;
  toolName: ProposedToolCall["name"];
  status: "executed" | "not_executed";
  result: string;
}

export interface ToolApproval {
  toolCallId: string;
  decision: "approved" | "rejected";
  decidedAt: string;
}

export type PolicyDecision = "allow" | "require_approval" | "block";

export interface ToolPolicyDecision {
  toolCallId: string;
  toolName: ProposedToolCall["name"];
  decision: PolicyDecision;
  reasons: string[];
}

export interface TraceEvent {
  id: string;
  timestamp: string;
  type: "user_request" | "document_received" | "security_scan_completed" | "agent_response" | "tool_proposed" | "tool_policy_evaluated" | "tool_executed" | "human_approval_decided" | "replay_completed";
  source?: SourceKind;
  summary: string;
}

export type FindingSeverity = "low" | "medium" | "high" | "critical";

export interface SecurityFinding {
  id: string;
  ruleId: string;
  severity: FindingSeverity;
  score: number;
  sourceId: string;
  sourceKind: SourceKind;
  evidence: string;
  explanation: string;
}

export interface SecurityAssessment {
  score: number;
  level: "low" | "medium" | "high" | "critical";
  recommendation: "allow_and_log" | "monitor" | "require_approval" | "block";
  findings: SecurityFinding[];
}

export interface Trace {
  id: string;
  createdAt: string;
  events: TraceEvent[];
  security: SecurityAssessment;
  proposedToolCalls: ProposedToolCall[];
  policyDecisions: ToolPolicyDecision[];
  toolExecutions: ToolExecution[];
  approvals: ToolApproval[];
}

export interface AgentRunResult {
  trace: Trace;
  summary: string;
  proposedToolCalls: ProposedToolCall[];
  policyDecisions: ToolPolicyDecision[];
  toolExecutions: ToolExecution[];
}
