import { createApp } from "./app.js";
import { OpenAIAgentRunner } from "./agent.js";
import { SqliteTraceStore } from "./trace-store.js";
import { loadApiEnvironment } from "./config.js";

loadApiEnvironment();

const apiKey = process.env.OPENAI_API_KEY;
if (!apiKey) {
  throw new Error("OPENAI_API_KEY is required. Copy .env.example to .env and set the server-side key.");
}

const port = Number(process.env.PORT ?? 4000);
const traceStore = new SqliteTraceStore();
const app = createApp(new OpenAIAgentRunner(apiKey, process.env.OPENAI_MODEL ?? "gpt-4.1-mini"), traceStore);
app.listen(port, () => console.log(`PromptTrace API listening on http://localhost:${port}`));
