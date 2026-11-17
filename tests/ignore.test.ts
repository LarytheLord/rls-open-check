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
  it("exits 0 through the CLI when the only finding is ignored", async () => {
    const r = await run(["--fail-on", "low", fx("ignore-comment-clean")]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("0 finding(s)");
    expect(r.stdout).toContain("1 finding(s) ignored by comment");
    expect(r.stdout).toContain('No findings at or above "low".');
  });
  it("still exits 1 on the unignored R1 through the CLI", async () => {
    expect((await run(["--fail-on", "low", fx("ignore-comment")])).code).toBe(1);
  });
  it("--strict with a parse warning still exits 1 when everything else is ignored", async () => {
    const r = await run(["--strict", "--fail-on", "low", fx("ignore-comment-clean"), fx("strict-parse-error")]);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("1 finding(s) ignored by comment");
    expect(r.stdout).toContain("--strict is set: failing.");
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
  it("accepts lowercase and odd spacing in a comma separated list (R4 and R7 on one GRANT)", async () => {
    const sql = [
      "create table public.t (id int);",
      "-- rls-open-check-ignore r4 ,  R7",
      "grant select on public.t to anon;",
    ].join("\n");
    const r = await analyzeSources([{ file: "a.sql", sql }]);
    expect(r.findings.map((f) => f.rule)).toEqual(["R1"]);
    expect(r.ignored.map((f) => f.rule).sort()).toEqual(["R4", "R7"]);
  });
  it("accepts a lowercase id with odd spacing for R1", async () => {
    const sql = "-- rls-open-check-ignore r1 ,  R7\ncreate table public.t (id int);";
    const r = await analyzeSources([{ file: "a.sql", sql }]);
    expect(r.findings.map((f) => f.rule)).toEqual([]);
    expect(r.ignored.map((f) => f.rule)).toEqual(["R1"]);
  });
  it("accepts a trailing reason after the ids", async () => {
    const sql = [
      "create table public.t (id int);",
      "alter table public.t enable row level security;",
      "-- rls-open-check-ignore R2 -- public docs table",
      'create policy "p" on public.t for insert to anon with check (true);',
    ].join("\n");
    const r = await analyzeSources([{ file: "a.sql", sql }]);
    expect(r.findings).toEqual([]);
    expect(r.ignored.map((f) => f.rule)).toEqual(["R2"]);
  });
  it("ignores a multi-line statement, with LF and CRLF", async () => {
    const lines = [
      "create table public.t (id int);",
      "alter table public.t enable row level security;",
      "-- rls-open-check-ignore R2",
      'create policy "p"',
      "  on public.t",
      "  for insert to anon",
      "  with check (true);",
    ];
    for (const nl of ["\n", "\r\n"]) {
      const r = await analyzeSources([{ file: "a.sql", sql: lines.join(nl) }]);
      expect(r.findings).toEqual([]);
      expect(r.ignored.map((f) => f.rule)).toEqual(["R2"]);
    }
  });
  it("does not leak an ignore from one file to another at the same line", async () => {
    const policy = (t: string) => `create table public.${t} (id int);\nalter table public.${t} enable row level security;\n`;
    const post = (t: string) => `create policy "p" on public.${t} for insert to anon with check (true);`;
    const a = policy("a") + "-- rls-open-check-ignore R2\n" + post("a");
    const b = policy("b") + "-- just a note\n" + post("b");
    const r = await analyzeSources([
      { file: "a.sql", sql: a },
      { file: "b.sql", sql: b },
    ]);
    expect(r.ignored.map((f) => `${f.file}:${f.rule}`)).toEqual(["a.sql:R2"]);
    expect(r.findings.map((f) => `${f.file}:${f.rule}`)).toEqual(["b.sql:R2"]);
  });
  it("reports R7 at the GRANT, so a comment above CREATE TABLE does not silence it", async () => {
    const sql = [
      "-- rls-open-check-ignore R7",
      "create table public.t (id int);",
      "alter table public.t enable row level security;",
      "grant select on public.t to anon;",
    ].join("\n");
    const r = await analyzeSources([{ file: "a.sql", sql }]);
    expect(r.findings.map((f) => f.rule)).toEqual(["R7"]);
  });
  it("loses the ignore when a later ALTER POLICY moves the finding", async () => {
    const sql = [
      "create table public.t (id int);",
      "alter table public.t enable row level security;",
      "-- rls-open-check-ignore R2",
      'create policy "p" on public.t for insert to anon with check (true);',
      'alter policy "p" on public.t with check (true);',
    ].join("\n");
    const r = await analyzeSources([{ file: "a.sql", sql }]);
    expect(r.findings.map((f) => f.rule)).toEqual(["R2"]);
    expect(r.findings[0].line).toBe(5);
  });
  it("only applies to the line directly above, and only to listed rules", async () => {
    const far = "-- rls-open-check-ignore R1\n\ncreate table public.t (id int);";
    expect((await analyzeSources([{ file: "a.sql", sql: far }])).findings.map((f) => f.rule)).toContain("R1");
    const other = "-- rls-open-check-ignore R2\ncreate table public.t (id int);";
    expect((await analyzeSources([{ file: "a.sql", sql: other }])).findings.map((f) => f.rule)).toContain("R1");
  });
  const base = [
    "create table public.t (id int);",
    "alter table public.t enable row level security;",
  ];
  const stillReported = async (comment: string) => {
    const sql = [...base, comment, 'create policy "p" on public.t for insert to anon with check (true);'].join("\n");
    const r = await analyzeSources([{ file: "a.sql", sql }]);
    expect(r.findings.map((f) => f.rule)).toEqual(["R2"]);
    expect(r.ignored).toEqual([]);
  };
  it("does not accept a block comment", () => stillReported("/* rls-open-check-ignore R2 */"));
  it("does not accept trailing text that is not a -- reason", () => stillReported("-- rls-open-check-ignore R2 because x"));
  it("does not accept space separated ids", () => stillReported("-- rls-open-check-ignore R2 R3"));
  it("does not accept a comment after code on the same line", () =>
    stillReported("select 1; -- rls-open-check-ignore R2"));
});
