import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { run } from "../src/cli.js";
import { analyzeSources } from "../src/analyze.js";
import { FIXTURES, scan } from "./helpers.js";

const fx = (n: string) => join(FIXTURES, n);

describe("rls-open-check-ignore comment", () => {
  it("moves the ignored R2 out of findings and keeps the R1", async () => {
    const r = await scan("ignore-comment");
    expect(r.findings.map((f) => f.rule)).toEqual(["R1"]);
    expect(r.ignored.map((f) => f.rule)).toEqual(["R2"]);
  });
  it("does not count ignored findings for the exit code", async () => {
    const only = await run(["--fail-on", "low", fx("ignore-comment")]);
    expect(only.code).toBe(1); // the R1 still fails
    const sql = [
      "create table public.t (id int);",
      "alter table public.t enable row level security;",
      "-- rls-open-check-ignore R2",
      'create policy "p" on public.t for insert to anon with check (true);',
    ].join("\n");
    const r = await analyzeSources([{ file: "a.sql", sql }]);
    expect(r.findings).toEqual([]);
    expect(r.ignored).toHaveLength(1);
  });
  it("shows the ignored count in the text summary", async () => {
    const r = await run([fx("ignore-comment")]);
    expect(r.stdout).toContain("1 finding(s) ignored by comment");
    expect(r.stdout).toContain("1 finding(s)");
    expect(r.stdout).not.toContain("R2  public.posts");
  });
  it("omits the ignored line when nothing is ignored", async () => {
    const r = await run([fx("r1-bad")]);
    expect(r.stdout).not.toContain("ignored by comment");
  });
  it("adds an ignored array to JSON", async () => {
    const j = JSON.parse((await run(["--json", fx("ignore-comment")])).stdout);
    expect(j.findings.map((f: { rule: string }) => f.rule)).toEqual(["R1"]);
    expect(j.ignored.map((f: { rule: string }) => f.rule)).toEqual(["R2"]);
    expect(j.summary).toEqual({ low: 0, medium: 0, high: 0, critical: 1 });
    const none = JSON.parse((await run(["--json", fx("r1-good")])).stdout);
    expect(none.ignored).toEqual([]);
  });
  it("marks ignored findings in SARIF with an inSource suppression", async () => {
    const log = JSON.parse((await run(["--format", "sarif", fx("ignore-comment")])).stdout);
    const results = log.runs[0].results;
    const r1 = results.find((x: { ruleId: string }) => x.ruleId === "R1");
    const r2 = results.find((x: { ruleId: string }) => x.ruleId === "R2");
    expect(r1.suppressions).toBeUndefined();
    expect(r2.suppressions).toEqual([{ kind: "inSource", justification: expect.any(String) }]);
  });
  it("accepts several comma separated rule ids", async () => {
    const sql = [
      "-- rls-open-check-ignore R1, R7",
      "create table public.t (id int);",
    ].join("\n");
    const r = await analyzeSources([{ file: "a.sql", sql }]);
    expect(r.findings.filter((f) => f.rule === "R1")).toEqual([]);
    expect(r.ignored.map((f) => f.rule)).toContain("R1");
  });
  it("only applies to the line directly above, and only to listed rules", async () => {
    const far = "-- rls-open-check-ignore R1\n\ncreate table public.t (id int);";
    expect((await analyzeSources([{ file: "a.sql", sql: far }])).findings.map((f) => f.rule)).toContain("R1");
    const other = "-- rls-open-check-ignore R2\ncreate table public.t (id int);";
    expect((await analyzeSources([{ file: "a.sql", sql: other }])).findings.map((f) => f.rule)).toContain("R1");
  });
});
