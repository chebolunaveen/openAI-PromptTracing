# Initial threat model

## Protected assets

- OpenAI API key
- Confidential documents
- Outbound actions such as email
- Agent instructions and tool permissions

## Implemented controls

- The API key is read only by `apps/api` from the environment.
- The browser receives no API key.
- Tool definitions allow the model to propose actions, but the service never executes them.
- Uploaded document text is labelled as untrusted data in the agent prompt.
- Deterministic detection rules record instruction-overrides, privileged-prompt requests, secret-exfiltration attempts, and covert-action language in the trace.
- Critical-risk content blocks every proposed tool call.
- High-risk content requires human approval for every proposed tool call.
- External email drafts require human approval.
- Completed traces persist in local SQLite storage.

## Deferred controls

- Authentication and rate limiting
