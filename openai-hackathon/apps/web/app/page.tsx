"use client";

import { useEffect, useState } from "react";

const apiBaseUrl = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:4000";

type Decision = { toolCallId: string; toolName: string; decision: "allow" | "require_approval" | "block"; reasons: string[] };
type Finding = { ruleId: string; severity: string; score: number; evidence: string; explanation: string };
type Execution = { toolCallId: string; toolName: string; status: "executed" | "not_executed"; result: string };
type Approval = { toolCallId: string; decision: "approved" | "rejected"; decidedAt: string };
type Trace = {
  id: string;
  createdAt: string;
  events: { id: string; timestamp: string; type: string; summary: string }[];
  security: { score: number; level: "low" | "medium" | "high" | "critical"; recommendation: string; findings: Finding[] };
  policyDecisions: Decision[];
  toolExecutions: Execution[];
  proposedToolCalls: { id: string; name: string }[];
  approvals: Approval[];
};

function normalizeTrace(trace: Partial<Trace>): Trace {
  return {
    id: trace.id ?? "legacy-trace",
    createdAt: trace.createdAt ?? new Date(0).toISOString(),
    events: trace.events ?? [],
    security: trace.security ?? {
      score: 0,
      level: "low",
      recommendation: "allow_and_log",
      findings: []
    },
    policyDecisions: trace.policyDecisions ?? [],
    toolExecutions: trace.toolExecutions ?? [],
    proposedToolCalls: trace.proposedToolCalls ?? [],
    approvals: trace.approvals ?? []
  };
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, { ...init, headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) } });
  if (!response.ok) throw new Error(`API request failed (${response.status})`);
  return response.json() as Promise<T>;
}

export default function HomePage() {
  const [traces, setTraces] = useState<Trace[]>([]);
  const [selected, setSelected] = useState<Trace | null>(null);
  const [message, setMessage] = useState("Connect the API on port 4000 to view traces.");

  const refresh = async () => {
    try {
      const result = await api<{ traces: Trace[] }>("/traces?limit=30");
      const normalizedTraces = result.traces.map(normalizeTrace);
      setTraces(normalizedTraces);
      if (!selected && normalizedTraces[0]) setSelected(normalizedTraces[0]);
      setMessage(result.traces.length ? `${result.traces.length} saved trace(s) loaded.` : "No traces yet. Run an agent request or replay a scenario.");
    } catch {
      setMessage("API unavailable. Start it with: npm.cmd run dev:api");
    }
  };

  useEffect(() => { void refresh(); }, []);

  const selectTrace = async (id: string) => {
    const result = await api<{ trace: Trace }>(`/traces/${id}`);
    setSelected(normalizeTrace(result.trace));
  };

  const replay = async (scenario: "safe" | "malicious", mode: "protected" | "vulnerable") => {
    try {
      const result = await api<{ trace: Trace }>("/demo/replay", { method: "POST", body: JSON.stringify({ scenario, mode }) });
      setSelected(normalizeTrace(result.trace));
      await refresh();
      setMessage(`${scenario} scenario replayed in ${mode} mode.`);
    } catch {
      setMessage("Replay failed. Confirm the API is running on port 4000.");
    }
  };

  const decideApproval = async (toolCallId: string, decision: "approved" | "rejected") => {
    if (!selected) return;
    try {
      const result = await api<{ trace: Trace }>(`/traces/${selected.id}/approvals`, { method: "POST", body: JSON.stringify({ toolCallId, decision }) });
      setSelected(normalizeTrace(result.trace));
      await refresh();
      setMessage(`Tool call ${decision}.`);
    } catch {
      setMessage("Approval request failed. The tool may already have a decision.");
    }
  };

  return (
    <main className="shell">
      <div className="eyebrow">PROMPTTRACE · AI AGENT SECURITY OBSERVABILITY</div>
      <h1>See what influenced an agent action.</h1>
      <p className="subtle">Trace untrusted documents, detection findings, proposed tools, and deterministic policy decisions. Tool calls are never executed by this demo.</p>

      <div className="controls"><button onClick={() => void refresh()}>Refresh traces</button></div>
      <div className="replay">
        <button onClick={() => void replay("safe", "protected")}>Replay safe scenario</button>
        <button onClick={() => void replay("malicious", "vulnerable")}>Replay malicious: vulnerable</button>
        <button onClick={() => void replay("malicious", "protected")}>Replay malicious: protected</button>
      </div>
      <p className="subtle">{message}</p>

      <section className="grid">
        <aside className="panel">
          <h2>Saved traces</h2>
          {traces.length === 0 ? <p className="empty">No traces available yet.</p> : traces.map((trace) => (
            <button className="trace" key={trace.id} onClick={() => void selectTrace(trace.id)}>
              <strong className={trace.security.level}>Risk {trace.security.score}/100 · {trace.security.level}</strong>
              <small>{new Date(trace.createdAt).toLocaleString()} · {trace.id.slice(0, 8)}</small>
            </button>
          ))}
        </aside>

        <section className="panel">
          {!selected ? <p className="empty">Choose a trace to inspect its security path.</p> : <TraceDetail trace={selected} onApproval={decideApproval} />}
        </section>
      </section>
    </main>
  );
}

function TraceDetail({ trace, onApproval }: { trace: Trace; onApproval: (toolCallId: string, decision: "approved" | "rejected") => void }) {
  return <>
    <h2>Attack trace</h2>
    <div className="risk"><div className={`score ${trace.security.level}`}>{trace.security.score}</div><div><strong className={trace.security.level}>{trace.security.level.toUpperCase()} RISK</strong><div className="subtle">Recommendation: <code>{trace.security.recommendation}</code></div></div></div>
    <div className="cards">
      <div className="card"><div className="label">Findings</div><strong>{trace.security.findings.length}</strong></div>
      <div className="card"><div className="label">Policy decisions</div><strong>{trace.policyDecisions.length}</strong></div>
      <div className="card"><div className="label">Tool executions</div><strong>{trace.toolExecutions.filter((item) => item.status === "executed").length}</strong></div>
      <div className="card"><div className="label">Trace ID</div><code>{trace.id.slice(0, 8)}</code></div>
    </div>
    <h3>Detection findings</h3>
    {trace.security.findings.length === 0 ? <p className="subtle">No suspicious patterns matched the current deterministic rules.</p> : <ul>{trace.security.findings.map((finding) => <li key={finding.ruleId}><strong>{finding.ruleId} · {finding.severity} · +{finding.score}</strong><br />{finding.explanation}<br /><code>{finding.evidence}</code></li>)}</ul>}
    <h3>Policy decisions</h3>
    {trace.policyDecisions.length === 0 ? <p className="subtle">The agent did not propose a tool action.</p> : <ul>{trace.policyDecisions.map((decision) => {
      const approval = trace.approvals.find((item) => item.toolCallId === decision.toolCallId);
      return <li key={decision.toolCallId}><strong className={decision.decision === "block" ? "critical" : decision.decision === "require_approval" ? "medium" : "low"}>{decision.toolName}: {decision.decision}</strong><br />{decision.reasons.join(" ")}
        {decision.decision === "require_approval" && !approval && <div className="controls"><button onClick={() => onApproval(decision.toolCallId, "approved")}>Approve</button><button onClick={() => onApproval(decision.toolCallId, "rejected")}>Reject</button></div>}
        {approval && <div className="subtle">Human decision: <strong>{approval.decision}</strong></div>}
      </li>;
    })}</ul>}
    <h3>Tool execution</h3>
    {trace.toolExecutions.length === 0 ? <p className="subtle">No tool execution was recorded.</p> : <ul>{trace.toolExecutions.map((execution) => <li key={execution.toolCallId}><strong className={execution.status === "executed" ? "low" : "medium"}>{execution.toolName}: {execution.status}</strong><br />{execution.result}</li>)}</ul>}
    <h3>Timeline</h3>
    <ul>{trace.events.map((event) => <li key={event.id}><strong>{event.type}</strong> — {event.summary}</li>)}</ul>
  </>;
}
