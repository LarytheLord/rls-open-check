import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { run } from "../src/cli.js";
import { FIXTURES } from "./helpers.js";

const fx = (n: string) => join(FIXTURES, n);

describe("cli", () => {
  it("exits 1 and prints text when findings reach the default --fail-on high", async () => {
    const r = await run([fx("r1-bad")]);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("[critical] R1  public.todos");
    expect(r.stdout).toContain("Fix:");
  });
  it("exits 0 on a clean directory", async () => {
    const r = await run([fx("r1-good")]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("0 finding(s)");
  });
  it("exits 0 on invalid SQL without --strict", async () => {
    const r = await run([fx("strict-parse-error")]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("Could not parse statement, skipped:");
    expect(r.stdout).not.toContain("statement(s) skipped.");
  });
  it("exits 1 on invalid SQL with --strict", async () => {
    const r = await run(["--strict", fx("strict-parse-error")]);
    expect(r.code).toBe(1);
    expect(r.stdout).toContain("Could not parse statement, skipped:");
    expect(r.stdout).toContain("0 finding(s)");
    expect(r.stdout).toContain("2 statement(s) skipped.");
    expect(r.stdout).toContain("2 statement(s) could not be parsed and --strict is set: failing.");
  });
  it("exits 0 on valid SQL with --strict", async () => {
    const r = await run(["--strict", fx("r1-good")]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain("0 finding(s)");
    expect(r.stdout).toContain("0 statement(s) skipped.");
  });
  it("respects --fail-on: a medium finding passes at high and fails at medium", async () => {
    expect((await run([fx("r5-bad")])).code).toBe(0);
    expect((await run(["--fail-on", "medium", fx("r5-bad")])).code).toBe(1);
    expect((await run([`--fail-on=low`, fx("r5-bad")])).code).toBe(1);
  });
  it("prints valid JSON with --json", async () => {
    const r = await run(["--json", fx("mixed-app")]);
    const j = JSON.parse(r.stdout);
    expect(j.findings).toHaveLength(4);
    expect(j.summary).toEqual({ low: 0, medium: 2, high: 0, critical: 2 });
    expect(j.findings[0]).toMatchObject({ rule: "R1", severity: "critical" });
    expect(j.findings[0].fix).toBeTruthy();
    expect(r.code).toBe(1);
  });
  it("returns 2 for bad usage and missing paths", async () => {
    expect((await run(["--fail-on", "nope"])).code).toBe(2);
    expect((await run(["--bogus"])).code).toBe(2);
    expect((await run([fx("does-not-exist")])).code).toBe(2);
  });
  it("output is plain ASCII", async () => {
    for (const n of ["mixed-app", "parse-error", "r2-bad-anon"]) {
      const r = await run([fx(n)]);
      expect(/^[\x00-\x7f]*$/.test(r.stdout)).toBe(true);
    }
  });
});
