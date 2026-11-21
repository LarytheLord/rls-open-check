import { readFileSync } from "node:fs";
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
    expect(ruleDocsUrl("R12")).toBe(BASE + "r12");
  });
  it("SARIF rules carry helpUri", async () => {
    const log = JSON.parse((await run(["--format", "sarif", fx("r1-good")])).stdout);
    const rules = log.runs[0].tool.driver.rules;
    expect(rules).toHaveLength(RULES.length);
    for (const r of rules) expect(r.helpUri).toBe(BASE + r.id.toLowerCase());
  });
  it("each rule has exactly one README heading, so its anchor resolves", () => {
    const lines = readFileSync(join(import.meta.dirname, "..", "README.md"), "utf8").split("\n");
    for (const { id } of RULES) expect(lines.filter((l) => l === "### " + id)).toHaveLength(1);
  });
  it("text output lists each fired rule's docs link once and no other", async () => {
    const r = await run([fx("mixed-app")]);
    const fired = new Set([...r.stdout.matchAll(/\] (R\d+) /g)].map((m) => m[1]));
    expect(fired.size).toBeGreaterThan(1);
    const docs = r.stdout.split("\n").filter((l) => l.startsWith("Docs:"));
    expect(docs.sort()).toEqual([...fired].map((id) => `Docs: ${BASE}${id.toLowerCase()}`).sort());
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
  it("only links to the project README anchors", async () => {
    const text = (await run([fx("mixed-app")])).stdout;
    const sarif = (await run(["--format", "sarif", fx("mixed-app")])).stdout;
    for (const out of [text, sarif]) {
      const urls = (out.match(/https?:\/\/[^\s"]+/g) ?? []).filter((u) => !u.includes("sarif-schema"));
      expect(urls.length).toBeGreaterThan(0);
      for (const u of urls) expect(u.startsWith(BASE)).toBe(true);
    }
  });
  it("keeps Docs lines out of JSON output", async () => {
    expect((await run(["--format", "json", fx("mixed-app")])).stdout).not.toContain("Docs:");
  });
});
