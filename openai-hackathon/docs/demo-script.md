# Demo script draft

1. Start the API (`npm.cmd run dev:api`) and dashboard (`npm.cmd run dev:web`).
2. Open `http://localhost:3000` and replay the safe protected scenario.
3. Replay the malicious scenario in vulnerable mode: the dangerous email proposal is marked `allow` only because enforcement is intentionally skipped for comparison.
4. Replay the malicious scenario in protected mode: the same dangerous email is marked `block` because the document has a critical risk score.
5. Open the trace timeline and show the source, matched rules, risk score, proposed action, and deterministic policy decision.
