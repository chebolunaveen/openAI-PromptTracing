import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { Trace } from "@prompttrace/shared";

export interface TraceStore {
  save(trace: Trace): void;
  list(limit?: number): Trace[];
  findById(id: string): Trace | undefined;
  count(): number;
  close(): void;
}

interface TraceRow {
  trace_json: string;
}

export class SqliteTraceStore implements TraceStore {
  private readonly database: DatabaseSync;

  constructor(filename = process.env.TRACE_DB_PATH ?? ".data/prompttrace.db") {
    if (filename !== ":memory:") {
      mkdirSync(dirname(filename), { recursive: true });
    }

    this.database = new DatabaseSync(filename);
    this.database.exec("PRAGMA journal_mode = WAL;");
    this.database.exec(`
      CREATE TABLE IF NOT EXISTS traces (
        id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        trace_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS traces_created_at_index ON traces(created_at DESC);
    `);
  }

  save(trace: Trace): void {
    this.database
      .prepare(`INSERT INTO traces (id, created_at, trace_json) VALUES (?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET created_at = excluded.created_at, trace_json = excluded.trace_json`)
      .run(trace.id, trace.createdAt, JSON.stringify(trace));
  }

  list(limit = 50): Trace[] {
    const safeLimit = Math.min(Math.max(limit, 1), 100);
    const rows = this.database
      .prepare("SELECT trace_json FROM traces ORDER BY created_at DESC LIMIT ?")
      .all(safeLimit) as unknown as TraceRow[];
    return rows.map((row) => JSON.parse(row.trace_json) as Trace);
  }

  findById(id: string): Trace | undefined {
    const row = this.database
      .prepare("SELECT trace_json FROM traces WHERE id = ?")
      .get(id) as unknown as TraceRow | undefined;
    return row ? (JSON.parse(row.trace_json) as Trace) : undefined;
  }

  count(): number {
    const row = this.database.prepare("SELECT COUNT(*) AS count FROM traces").get() as { count: number };
    return row.count;
  }

  close(): void {
    this.database.close();
  }
}
