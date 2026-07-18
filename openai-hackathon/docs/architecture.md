# PromptTrace architecture

```text
User request + document
        |
        v
Normalize + deterministic injection scanner
        |
        v
OpenAI agent (proposes, never executes, tools)
        |
        v
Deterministic tool-policy engine
        |
        v
SQLite trace store --> Next.js dashboard / replay comparison
```

The document is explicitly marked untrusted in the agent instruction. The current policy blocks all proposed calls when the source has a critical risk score, and requires human approval for external email drafts.
