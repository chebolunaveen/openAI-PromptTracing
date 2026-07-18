import { randomUUID } from "node:crypto";
import type { DocumentInput, ProposedToolCall, SecurityAssessment, SecurityFinding, ToolPolicyDecision } from "@prompttrace/shared";

interface DetectionRule {
  id: string;
  severity: SecurityFinding["severity"];
  score: number;
  explanation: string;
  pattern: RegExp;
}

const rules: DetectionRule[] = [
  {
    id: "PI-001",
    severity: "high",
    score: 35,
    explanation: "Attempts to override the agent's existing instructions.",
    pattern: /\b(ignore|disregard|forget|override)\b.{0,80}\b(previous|prior|system|all)\b.{0,80}\b(instructions?|rules?|prompts?)\b/i
  },
  {
    id: "PI-002",
    severity: "high",
    score: 30,
    explanation: "Attempts to obtain privileged instructions or system prompts.",
    pattern: /\b(reveal|show|print|extract|leak)\b.{0,80}\b(system prompt|system instruction|hidden instruction|developer message)/i
  },
  {
    id: "PI-003",
    severity: "critical",
    score: 35,
    explanation: "Requests secrets, credentials, or private data.",
    pattern: /(?:\b(api key|password|secret|credential|access token|private key)\b.{0,100}\b(send|share|reveal|email|upload|exfiltrate)\b|\b(send|share|reveal|email|upload|exfiltrate)\b.{0,100}\b(api key|password|secret|credential|access token|private key)\b)/i
  },
  {
    id: "PI-004",
    severity: "critical",
    score: 30,
    explanation: "Attempts an unauthorized outbound or data-exfiltration action.",
    pattern: /\b(email|send|upload|post|exfiltrate)\b.{0,100}\b(attacker|external|outside|@|http)/i
  },
  {
    id: "PI-005",
    severity: "medium",
    score: 20,
    explanation: "Uses coercive language intended to hide an unsafe action from the user.",
    pattern: /\b(do not tell|without (the )?user|silently|secretly|hide this)\b/i
  },
  {
    id: "PI-006",
    severity: "high",
    score: 30,
    explanation: "Attempts to impersonate a privileged role or replace the agent's authority.",
    pattern: /\b(you are now|act as|pretend to be|switch to|enter)\b.{0,80}\b(system|administrator|developer|root|unrestricted|jailbreak)\b/i
  },
  {
    id: "PI-007",
    severity: "high",
    score: 30,
    explanation: "Attempts to bypass or disable a safety control, policy, filter, or approval step.",
    pattern: /\b(bypass|disable|evade|circumvent)\b.{0,80}\b(guardrail|safety|policy|restriction|approval|filter)\b/i
  },
  {
    id: "PI-008",
    severity: "medium",
    score: 25,
    explanation: "Attempts to conceal instructions or commands through an encoding or obfuscation request.",
    pattern: /\b(decode|base64|rot13|obfuscated|encoded)\b.{0,100}\b(instruction|prompt|command|payload)\b/i
  },
  {
    id: "OP-001",
    severity: "critical",
    score: 80,
    explanation: "Requests a destructive operation against records, data, files, or database tables.",
    pattern: /\b(delete|erase|drop|truncate|wipe|clear)\b.{0,100}\b(all|record|records|trace|traces|data|database|table|tables|file|files)\b/i
  },
  {
    id: "OP-002",
    severity: "high",
    score: 60,
    explanation: "Requests a modification, replacement, or overwrite of stored records, traces, data, or tables.",
    pattern: /\b(override|update|modify|replace|change|write)\b.{0,100}\b(record|records|trace|traces|data|database|table|tables)\b/i
  }
];

export const activeToolPolicies = [
  {
    id: "TP-001",
    description: "Critical-risk untrusted content blocks every proposed tool call."
  },
  {
    id: "TP-002",
    description: "High-risk untrusted content requires human approval for every proposed tool call."
  },
  {
    id: "TP-003",
    description: "Email drafts to domains outside prompttrace.local require human approval."
  }
] as const;

export function normalizeUntrustedText(value: string): string {
  return value
    .normalize("NFKC")
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

function assessmentLevel(score: number): SecurityAssessment["level"] {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

function recommendation(score: number): SecurityAssessment["recommendation"] {
  if (score >= 80) return "block";
  if (score >= 60) return "require_approval";
  if (score >= 30) return "monitor";
  return "allow_and_log";
}

export function scanDocument(document: DocumentInput): SecurityAssessment {
  const content = normalizeUntrustedText(document.content);
  const findings: SecurityFinding[] = [];

  for (const rule of rules) {
    const match = content.match(rule.pattern);
    if (!match) continue;

    findings.push({
      id: randomUUID(),
      ruleId: rule.id,
      severity: rule.severity,
      score: rule.score,
      sourceId: document.id,
      sourceKind: document.source ?? "uploaded_document",
      evidence: match[0].slice(0, 240),
      explanation: rule.explanation
    });
  }

  const score = Math.min(100, findings.reduce((total, finding) => total + finding.score, 0));
  return { score, level: assessmentLevel(score), recommendation: recommendation(score), findings };
}

function stringArgument(toolCall: ProposedToolCall, name: string): string | undefined {
  const value = toolCall.arguments[name];
  return typeof value === "string" ? value.trim() : undefined;
}

/**
 * Policy decisions are deterministic and are deliberately separate from the
 * model's judgment. A future tool executor may only receive calls marked allow.
 */
export function evaluateToolPolicies(
  toolCalls: ProposedToolCall[],
  assessment: SecurityAssessment,
  internalEmailDomain = "prompttrace.local"
): ToolPolicyDecision[] {
  return toolCalls.map((toolCall) => {
    if (assessment.recommendation === "block") {
      return {
        toolCallId: toolCall.id,
        toolName: toolCall.name,
        decision: "block",
        reasons: [`Untrusted content has critical risk score ${assessment.score}/100.`]
      };
    }

    if (assessment.recommendation === "require_approval") {
      return {
        toolCallId: toolCall.id,
        toolName: toolCall.name,
        decision: "require_approval",
        reasons: [`Untrusted content has high risk score ${assessment.score}/100.`]
      };
    }

    if (toolCall.name === "draft_email") {
      const recipient = stringArgument(toolCall, "to");
      const isInternalRecipient = recipient?.toLowerCase().endsWith(`@${internalEmailDomain}`) ?? false;
      if (!isInternalRecipient) {
        return {
          toolCallId: toolCall.id,
          toolName: toolCall.name,
          decision: "require_approval",
          reasons: ["Outbound email recipients must use the internal prompttrace.local domain or receive human approval."]
        };
      }
    }

    return {
      toolCallId: toolCall.id,
      toolName: toolCall.name,
      decision: "allow",
      reasons: ["Tool call satisfies the current deterministic policy."]
    };
  });
}
