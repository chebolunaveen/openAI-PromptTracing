import { describe, expect, it } from "vitest";
import { loadApiEnvironment } from "../src/config.js";

describe("loadApiEnvironment", () => {
  it("loads the repository root .env file", () => {
    delete process.env.OPENAI_API_KEY;

    loadApiEnvironment();

    expect(process.env.OPENAI_API_KEY).toBeTruthy();
    expect(process.env.OPENAI_API_KEY).toContain("sk-");
  });
});
