import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { config } from "dotenv";

export function loadApiEnvironment(): void {
  const workspaceRoot = resolve(import.meta.dirname, "..", "..", "..");
  const envPath = resolve(workspaceRoot, ".env");

  if (existsSync(envPath)) {
    config({ path: envPath });
  } else {
    config();
  }
}
