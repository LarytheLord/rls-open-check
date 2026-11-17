import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { run } from "../src/cli.js";
import { RULES, ruleDocsUrl } from "../src/rules.js";
import { FIXTURES } from "./helpers.js";

const fx = (n: string) => join(FIXTURES, n);
const BASE = "https://github.com/LarytheLord/rls-open-check#";

describe("rule docs links", () => {
  it("builds the url from the rule id", () => {
    expect(ruleDocsUrl("R1")).toBe(BASE + "r1");
    expect(ruleDocsUrl("R9")).toBe(BASE + "r9");
  });
  it("SARIF rules carry helpUri", async () => {
    const log = JSON.parse((await run(["--format", "sarif", fx("r1-good")])).stdout);
    const rules = log.runs[0].tool.driver.rules;
    expect(rules).toHaveLength(RULES.length);
    for (const r of rules) expect(r.helpUri).toBe(BASE + r.id.toLowerCase());
  });
  it("text output lists each fired rule's docs link once", async () => {
    const r = await run([fx("mixed-app")]);
    for (const id of ["R1", "R2", "R5", "R9"]) {
      const line = `Docs: ${BASE}${id.toLowerCase()}`;
      expect(r.stdout.split("\n").filter((l) => l === line)).toHaveLength(1);
    }
    expect(r.stdout).not.toContain(BASE + "r3");
  });
  it("prints one docs line for a rule that fires several times", async () => {
    const r = await run([fx("r6-bad")]);
    const n = r.stdout.split("\n").filter((l) => l.startsWith("Docs:")).length;
    const fired = new Set(r.stdout.match(/\] (R\d+) /g)).size;
    expect(n).toBe(fired);
  });
  it("prints no docs line when nothing fired", async () => {
    expect((await run([fx("r1-good")])).stdout).not.toContain("Docs:");
  });
  it("does not link to a commercial site", async () => {
    const r = await run([fx("mixed-app")]);
    expect(r.stdout).not.toMatch(/guilds\.work/);
  });
});
