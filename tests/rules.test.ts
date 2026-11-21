import { describe, expect, it } from "vitest";
import { only, rules, scan } from "./helpers.js";
import { analyzeSources } from "../src/analyze.js";

describe("R1 table without RLS", () => {
  it("flags a public table that never enables RLS", async () => {
    const r = await scan("r1-bad");
    expect(rules(r.findings)).toEqual(["R1"]);
    expect(r.findings[0].object).toBe("public.todos");
    expect(r.findings[0].severity).toBe("critical");
    expect(r.findings[0].line).toBe(1);
  });
  it("does not flag tables with RLS, other schemas or temp tables", async () => {
    expect((await scan("r1-good")).findings).toEqual([]);
  });
  it("does not flag when RLS is enabled in a later migration", async () => {
    expect((await scan("r1-enabled-later")).findings).toEqual([]);
  });
});

describe("R2 open policy for anon or public", () => {
  it("flags every write command granted to anon", async () => {
    const r = await scan("r2-bad-anon");
    const f = only(r.findings, "R2");
    expect(f.map((x) => x.object)).toEqual([
      "public.posts.anyone writes",
      "public.posts.anyone edits",
      "public.posts.anyone deletes",
      "public.posts.anyone all",
    ]);
    expect(f.every((x) => x.severity === "critical")).toBe(true);
    expect(r.findings).toHaveLength(4);
  });
  it("treats a missing TO clause, TO public and 1=1 as open", async () => {
    const f = only((await scan("r2-bad-public-default")).findings, "R2");
    expect(f.map((x) => x.object)).toEqual([
      "public.notes.read all",
      "public.notes.explicit public",
      "public.notes.tautology",
    ]);
  });
  it("rates a SELECT-only open policy high, not critical", async () => {
    const f = only((await scan("r2-select-only")).findings, "R2");
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("high");
  });
  it("does not flag real conditions, authenticated reads or restrictive policies", async () => {
    // The only finding is R10 for "auth read" (authenticated SELECT USING (true)); no R2 or R3.
    expect(rules((await scan("r2-good")).findings)).toEqual(["R10"]);
  });
});

describe("R3 authenticated can change anyone's rows", () => {
  it("flags USING (true) for UPDATE, DELETE and ALL", async () => {
    const r = await scan("r3-bad");
    expect(rules(r.findings)).toEqual(["R3", "R3", "R3"]);
    expect(r.findings[0].severity).toBe("high");
  });
  it("does not flag owner checks", async () => {
    expect((await scan("r3-good")).findings).toEqual([]);
  });
  it("flags WITH CHECK (true) on INSERT and ALL for authenticated", async () => {
    const f = only((await scan("r3-insert-bad")).findings, "R3");
    expect(f.map((x) => x.object)).toEqual([
      "public.comments.any user inserts",
      "public.comments.any user all",
    ]);
    expect(f.every((x) => x.severity === "high")).toBe(true);
    expect(f[0].message).toContain("insert");
    expect(f[0].fix).toContain("WITH CHECK");
  });
  it("does not flag owner checks on INSERT, restrictive policies or SELECT", async () => {
    // The only finding is R10 for "read all"; no R3.
    expect(rules((await scan("r3-insert-good")).findings)).toEqual(["R10"]);
  });
});

describe("R8 policy reads user-editable metadata (splinter 0015)", () => {
  it("flags user_metadata and raw_user_meta_data in USING and WITH CHECK", async () => {
    const r = await scan("r8-bad");
    const f = only(r.findings, "R8");
    expect(f.map((x) => x.object)).toEqual([
      "public.reports.jwt arrow",
      "public.reports.jwt path",
      "public.reports.users table",
      "public.reports.check side",
      "public.reports.narrow",
    ]);
    expect(f.every((x) => x.severity === "high")).toBe(true);
    expect(f[0].fix).toContain("app_metadata");
    expect(f[0].line).toBe(3);
  });
  it("does not flag app_metadata, your own tables or user_metadata outside a policy", async () => {
    expect((await scan("r8-good")).findings).toEqual([]);
  });
  it("a later ALTER POLICY or DROP POLICY removes the finding", async () => {
    const base =
      "create table public.t (id int, uid uuid); alter table public.t enable row level security;" +
      "create policy p on public.t for select to authenticated using (auth.jwt() -> 'user_metadata' ->> 'x' = '1');";
    const bad = await analyzeSources([{ file: "a.sql", sql: base }]);
    expect(rules(bad.findings)).toEqual(["R8"]);
    const fixed = await analyzeSources([
      { file: "a.sql", sql: base },
      { file: "b.sql", sql: "alter policy p on public.t using (auth.uid() = uid);" },
    ]);
    expect(fixed.findings).toEqual([]);
    const dropped = await analyzeSources([
      { file: "a.sql", sql: base },
      { file: "b.sql", sql: "drop policy p on public.t;" },
    ]);
    expect(dropped.findings).toEqual([]);
  });
});

describe("R4 grant to anon on a table without RLS", () => {
  it("flags explicit and ALL TABLES grants", async () => {
    const f = only((await scan("r4-bad")).findings, "R4");
    expect(f.map((x) => x.object).sort()).toEqual(["public.events", "public.logs"]);
    expect(f.find((x) => x.object === "public.logs")?.line).toBe(3);
  });
  it("does not flag grants on tables that have RLS", async () => {
    // the grant has no policy, so R7 (low) applies; this test is about R4
    expect(only((await scan("r4-good")).findings, "R4")).toEqual([]);
  });
  it("does not flag grants that were revoked", async () => {
    expect((await scan("r4-revoked")).findings).toEqual([]);
  });
});

describe("R5 SECURITY DEFINER without search_path", () => {
  it("flags functions with and without a schema prefix", async () => {
    const f = only((await scan("r5-bad")).findings, "R5");
    expect(f.map((x) => x.object)).toEqual(["public.get_secret()", "public.increment(int4)"]);
  });
  it("does not flag search_path, invoker functions or other schemas", async () => {
    expect((await scan("r5-good")).findings).toEqual([]);
  });
});

describe("R9 SECURITY DEFINER function executable by anon or authenticated (splinter 0028, 0029)", () => {
  it("flags the PUBLIC default, an explicit grant and a revoke that misses PUBLIC", async () => {
    const f = only((await scan("r9-bad")).findings, "R9");
    expect(f.map((x) => x.object)).toEqual([
      "public.open_default()",
      "public.auth_only(int4)",
      "public.anon_only()",
      "public.still_open()",
    ]);
    expect(f.every((x) => x.severity === "medium")).toBe(true);
    expect(f[0].message).toContain("anon and authenticated");
    expect(f[1].message).toContain("authenticated");
    expect(f[1].message).not.toContain("anon");
    expect(f[2].message).toContain("anon");
    expect(f[2].message).not.toContain("authenticated");
    expect(f[0].fix).toContain("REVOKE EXECUTE ON FUNCTION public.open_default()");
    expect(f[0].line).toBe(2);
  });
  it("does not flag revoked, service_role only, other schema, invoker or trigger functions", async () => {
    expect((await scan("r9-good")).findings).toEqual([]);
  });
  it("co-occurs with R5 on the same function (different rule ids)", async () => {
    const r = await analyzeSources([
      { file: "a.sql", sql: "create function public.f() returns int language sql security definer as $$ select 1 $$;" },
    ]);
    expect(rules(r.findings)).toEqual(["R5", "R9"]);
  });
  const mk = "create function public.f() returns int language sql security definer set search_path = '' as $$ select 1 $$;";
  it("a later REVOKE FROM PUBLIC removes the finding, a later GRANT brings it back", async () => {
    expect(rules((await analyzeSources([{ file: "a.sql", sql: mk }])).findings)).toEqual(["R9"]);
    const revoked = await analyzeSources([
      { file: "a.sql", sql: mk },
      { file: "b.sql", sql: "revoke execute on function public.f() from public;" },
    ]);
    expect(revoked.findings).toEqual([]);
    const regranted = await analyzeSources([
      { file: "a.sql", sql: mk },
      { file: "b.sql", sql: "revoke execute on function public.f() from public;" },
      { file: "c.sql", sql: "grant execute on function public.f() to anon;" },
    ]);
    expect(rules(regranted.findings)).toEqual(["R9"]);
  });
  it("handles ON ALL FUNCTIONS IN SCHEMA and ALL privileges", async () => {
    const r = await analyzeSources([
      { file: "a.sql", sql: mk + "create function public.g() returns int language sql security definer set search_path = '' as $$ select 1 $$;" },
      { file: "b.sql", sql: "revoke all on all functions in schema public from public;" },
      { file: "c.sql", sql: "grant all on function public.g() to authenticated;" },
    ]);
    expect(only(r.findings, "R9").map((x) => x.object)).toEqual(["public.g()"]);
  });
  it("follows ALTER DEFAULT PRIVILEGES for functions created later", async () => {
    const locked = await analyzeSources([
      { file: "a.sql", sql: "alter default privileges in schema public revoke execute on functions from public;" },
      { file: "b.sql", sql: mk },
    ]);
    expect(locked.findings).toEqual([]);
    const granted = await analyzeSources([
      { file: "a.sql", sql: "alter default privileges in schema public revoke execute on functions from public;" },
      { file: "b.sql", sql: "alter default privileges in schema public grant execute on functions to anon;" },
      { file: "c.sql", sql: mk },
    ]);
    expect(rules(granted.findings)).toEqual(["R9"]);
  });
  it("CREATE OR REPLACE keeps the existing privileges", async () => {
    const r = await analyzeSources([
      { file: "a.sql", sql: mk + "revoke execute on function public.f() from public;" },
      { file: "b.sql", sql: mk.replace("create function", "create or replace function") },
    ]);
    expect(r.findings).toEqual([]);
  });
  it("ALTER FUNCTION ... SECURITY DEFINER later makes it a finding, DROP FUNCTION clears it", async () => {
    const inv = "create function public.f() returns int language sql as $$ select 1 $$;";
    const a = await analyzeSources([
      { file: "a.sql", sql: inv },
      { file: "b.sql", sql: "alter function public.f() security definer;" },
    ]);
    expect(rules(a.findings)).toEqual(["R5", "R9"]);
    const d = await analyzeSources([
      { file: "a.sql", sql: mk },
      { file: "b.sql", sql: "drop function public.f();" },
    ]);
    expect(d.findings).toEqual([]);
  });
});

describe("R6 RLS disabled later", () => {
  it("flags DISABLE ROW LEVEL SECURITY in a later migration", async () => {
    const r = await scan("r6-bad");
    expect(rules(r.findings)).toEqual(["R6"]);
    expect(r.findings[0].file).toMatch(/002_disable\.sql$/);
    expect(r.findings[0].line).toBe(1);
  });
  it("clears the finding when RLS is enabled again", async () => {
    expect((await scan("r6-reenabled")).findings).toEqual([]);
  });
});

describe("migration ordering", () => {
  it("DROP POLICY removes an earlier finding", async () => {
    expect((await scan("order-drop-policy")).findings).toEqual([]);
  });
  it("ALTER POLICY that fixes the condition removes the finding", async () => {
    expect((await scan("order-alter-policy")).findings).toEqual([]);
  });
  it("DROP TABLE removes the table, its policies and grants", async () => {
    expect((await scan("order-drop-table")).findings).toEqual([]);
  });
  it("CREATE OR REPLACE, ALTER FUNCTION and DROP FUNCTION update R5", async () => {
    expect((await scan("order-replace-fn")).findings).toEqual([]);
  });
  it("enabling RLS after an anon grant removes R4", async () => {
    expect(only((await scan("order-grant-before-rls")).findings, "R4")).toEqual([]);
  });
  it("reads files in file name order, not argument order", async () => {
    const { analyzeSources } = await import("../src/analyze.js");
    const create = { file: "20240101_a.sql", sql: "create table public.t (id int);" };
    const secure = { file: "20240102_b.sql", sql: "alter table public.t enable row level security;" };
    expect((await analyzeSources([create, secure])).findings).toEqual([]);
    // wrong order would hide nothing here, so also prove a later disable wins
    const disable = { file: "20240103_c.sql", sql: "alter table public.t disable row level security;" };
    expect(rules((await analyzeSources([create, secure, disable])).findings)).toEqual(["R6"]);
  });
});

describe("REVOKE handling", () => {
  it("drops an anon grant on a table that never gets RLS (no R4, no R7)", async () => {
    const r = await analyzeSources([
      { file: "a.sql", sql: "create table public.t (id int); grant all on public.t to anon; revoke all on public.t from anon;" },
    ]);
    expect(rules(r.findings)).toEqual(["R1"]);
  });
});

describe("R7 grant without matching RLS policy", () => {
  it("flags all four commands when the table has no RLS", async () => {
    const f = only((await scan("r7-no-rls")).findings, "R7");
    expect(f).toHaveLength(1);
    expect(f[0].object).toBe("public.notes");
    expect(f[0].severity).toBe("high");
    expect(f[0].line).toBe(2);
    expect(f[0].message).toContain("authenticated");
    expect(f[0].message).toContain("SELECT, INSERT, UPDATE, DELETE");
  });
  it("flags only the commands that have no policy when RLS is on", async () => {
    const f = only((await scan("r7-no-policy-cmd")).findings, "R7");
    expect(f).toHaveLength(2);
    const auth = f.find((x) => x.message.includes("authenticated"))!;
    const anon = f.find((x) => x.message.includes("anon"))!;
    expect(auth.message).toContain("INSERT, UPDATE, DELETE");
    expect(auth.message).not.toContain("SELECT,");
    expect(auth.severity).toBe("low");
    expect(anon.message).toContain("SELECT");
  });
  it("does not flag when every granted command has a policy for the role", async () => {
    expect(only((await scan("r7-good")).findings, "R7")).toEqual([]);
  });
  it("does not flag a revoked grant", async () => {
    expect(only((await scan("r7-revoked")).findings, "R7")).toEqual([]);
  });
  it("follows ALTER DEFAULT PRIVILEGES for tables created later", async () => {
    const f = only((await scan("r7-defaults")).findings, "R7");
    expect(f).toHaveLength(1);
    expect(f[0].object).toBe("public.later");
    expect(f[0].message).toContain("SELECT, INSERT");
  });
  it("handles GRANT ON ALL TABLES IN SCHEMA and a policy for public", async () => {
    const f = only((await scan("r7-all-in-schema")).findings, "R7");
    expect(f.map((x) => x.object)).toEqual(["public.a"]);
  });
  it("ignores tables outside the public schema", async () => {
    const r = await analyzeSources([
      { file: "a.sql", sql: "create table app.t (id int); grant select on app.t to authenticated;" },
    ]);
    expect(only(r.findings, "R7")).toEqual([]);
  });
});

describe("R10 authenticated can read every row", () => {
  it("flags SELECT USING (true) for authenticated: medium with an owner column, low without", async () => {
    const f = only((await scan("r10-bad")).findings, "R10");
    expect(f.map((x) => [x.object, x.severity])).toEqual([
      ["public.notes.read all", "medium"],
      ["public.docs.docs read all", "medium"],
      ["public.countries.countries read", "low"],
    ]);
    expect(f[0].message).toContain("any logged-in user can read every row");
  });
  it("does not flag owner checks, anon (R2), restrictive, RLS off, or UPDATE (R3)", async () => {
    const r = await scan("r10-good");
    expect(only(r.findings, "R10")).toEqual([]);
    expect(rules(r.findings).sort()).toEqual(["R1", "R2", "R3"]);
  });
  it("does not flag the realistic owner fix, in a later migration or ALTER POLICY", async () => {
    const base = `create table public.notes (id int, user_id uuid);
alter table public.notes enable row level security;
create policy "p" on public.notes for select to authenticated using (true);`;
    const dropped = await analyzeSources([
      { file: "a.sql", sql: base },
      { file: "b.sql", sql: `drop policy "p" on public.notes; create policy "p" on public.notes for select to authenticated using ((select auth.uid()) = user_id);` },
    ]);
    expect(dropped.findings).toEqual([]);
    const altered = await analyzeSources([
      { file: "a.sql", sql: base },
      { file: "b.sql", sql: `alter policy "p" on public.notes using ((select auth.uid()) = user_id);` },
    ]);
    expect(altered.findings).toEqual([]);
  });
});

describe("R11 policy only checks that someone is logged in", () => {
  it("flags auth.uid() IS NOT NULL and auth.role() = 'authenticated' on any command", async () => {
    const f = only((await scan("r11-bad")).findings, "R11");
    expect(f.map((x) => [x.object, x.severity])).toEqual([
      ["public.notes.logged in read", "medium"],
      ["public.notes.wrapped uid", "medium"],
      ["public.notes.role check", "medium"],
      ["public.notes.insert any", "medium"],
      ["public.notes.both", "medium"],
      ["public.tags.tags read", "low"],
    ]);
    expect(f[0].message).toContain("any logged-in user can read every row");
    expect(f[3].message).toContain("insert");
  });
  it("does not flag the realistic owner fix or anon, restrictive and true policies", async () => {
    const r = await scan("r11-good");
    expect(only(r.findings, "R11")).toEqual([]);
  });
  it("does not flag once the policy is changed to compare auth.uid() to a column", async () => {
    const r = await analyzeSources([
      { file: "a.sql", sql: `create table public.n (id int, user_id uuid); alter table public.n enable row level security;
create policy "p" on public.n for select to authenticated using (auth.uid() is not null);` },
      { file: "b.sql", sql: `alter policy "p" on public.n using (auth.uid() = user_id);` },
    ]);
    expect(r.findings).toEqual([]);
  });
});

describe("R12 anyone can insert rows", () => {
  it("flags an anon or no-TO INSERT whose WITH CHECK never reads the caller", async () => {
    const f = only((await scan("r12-bad")).findings, "R12");
    expect(f.map((x) => [x.object, x.severity])).toEqual([
      ["public.messages.anon insert", "medium"],
      ["public.messages.default insert", "medium"],
      ["public.messages.pub insert", "medium"],
    ]);
    expect(f[0].message).toContain("anyone can insert rows");
  });
  it("does not flag auth.uid()/auth.jwt() checks, authenticated-only, true (R2), restrictive or opaque checks", async () => {
    const r = await scan("r12-good");
    expect(only(r.findings, "R12")).toEqual([]);
    expect(rules(r.findings)).toEqual(["R2"]);
  });
  it("does not flag the realistic fix of adding auth.uid() = user_id", async () => {
    const r = await analyzeSources([
      { file: "a.sql", sql: `create table public.m (id int, user_id uuid); alter table public.m enable row level security;
create policy "p" on public.m for insert to anon with check (user_id is null);` },
      { file: "b.sql", sql: `alter policy "p" on public.m with check (auth.uid() = user_id);` },
    ]);
    expect(r.findings).toEqual([]);
  });
});

const T = (cols: string, extra = "") =>
  `create table public.t (id int, ${cols}); alter table public.t enable row level security; ${extra}`;
const run1 = (sql: string) => analyzeSources([{ file: "a.sql", sql }]);

describe("R10 more cases", () => {
  it("flags TO authenticated, anon as R2 only (anon is open, no R10)", async () => {
    const r = await run1(T("user_id uuid", `create policy "p" on public.t for select to authenticated, anon using (true);`));
    expect(rules(r.findings)).toEqual(["R2"]);
  });
  it("gives a policy on a table with no definition the low severity", async () => {
    const r = await run1(`create policy "p" on public.ghost for select to authenticated using (true);`);
    expect(r.findings.map((f) => [f.rule, f.severity])).toEqual([["R10", "low"]]);
  });
  it("handles quoted identifiers and a non-public schema table", async () => {
    const q = await run1(`create table public."Notes" (id int, user_id uuid); alter table public."Notes" enable row level security;
create policy "p" on public."Notes" for select to authenticated using (true);`);
    expect(q.findings.map((f) => [f.rule, f.severity, f.object])).toEqual([["R10", "medium", 'public.Notes.p']]);
    const s = await run1(`create table app.t (id int, user_id uuid); alter table app.t enable row level security;
create policy "p" on app.t for select to authenticated using (true);`);
    expect(s.findings.map((f) => [f.rule, f.severity, f.object])).toEqual([["R10", "medium", "app.t.p"]]);
  });
  it("does not treat a quoted mixed-case column as an owner column", async () => {
    const r = await run1(`create table public.t (id int, "User_ID" uuid); alter table public.t enable row level security;
create policy "p" on public.t for select to authenticated using (true);`);
    expect(r.findings[0].severity).toBe("low");
  });
  it("tracks DROP COLUMN and RENAME COLUMN", async () => {
    const base = `create table public.t (id int, user_id uuid); alter table public.t enable row level security;
create policy "p" on public.t for select to authenticated using (true);`;
    const dropped = await run1(base + ` alter table public.t drop column user_id;`);
    expect(dropped.findings[0].severity).toBe("low");
    const renamedAway = await run1(base + ` alter table public.t rename column user_id to who;`);
    expect(renamedAway.findings[0].severity).toBe("low");
    const renamedIn = await run1(`create table public.t (id int, who uuid); alter table public.t rename column who to owner_id;
alter table public.t enable row level security;
create policy "p" on public.t for select to authenticated using (true);`);
    expect(renamedIn.findings[0].severity).toBe("medium");
  });
  it("counts author_id, account_id, tenant_id and org_id as owner columns", async () => {
    for (const c of ["author_id", "account_id", "tenant_id", "org_id"]) {
      const r = await run1(T(`${c} uuid`, `create policy "p" on public.t for select to authenticated using (true);`));
      expect([c, r.findings[0].severity]).toEqual([c, "medium"]);
    }
  });
  it("does not say the table has no owner column when the columns are unknown (LIKE, INHERITS, PARTITION OF, CTAS)", async () => {
    const pol = `alter table public.t enable row level security; create policy "p" on public.t for select to authenticated using (true);`;
    const variants = [
      `create table public.t (like public.base);`,
      `create table public.t () inherits (public.base);`,
      `create table public.t partition of public.base for values in (1);`,
      `create table public.t as select 1 as id;`,
    ];
    for (const v of variants) {
      const r = await run1(v + pol);
      expect([v, r.findings[0].severity]).toEqual([v, "medium"]);
      expect(r.findings[0].message).not.toContain("column, so this may be shared");
    }
  });
  it("drops policies with the table (no orphan finding after DROP TABLE)", async () => {
    const r = await run1(T("user_id uuid", `create policy "p" on public.t for select to authenticated using (true); drop table public.t;`));
    expect(r.findings).toEqual([]);
  });
});

describe("R11 more cases", () => {
  it("builds the message from the clause that matched: WITH CHECK only", async () => {
    const r = await run1(T("user_id uuid", `create policy "p" on public.t for update to authenticated using (user_id = auth.uid()) with check (auth.uid() is not null);`));
    const f = only(r.findings, "R11");
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain("WITH CHECK only checks that the caller is logged in");
    expect(f[0].message).toContain("any values");
    expect(f[0].message).not.toContain("every row");
  });
  it("says insert any values for INSERT, without the garbled wording", async () => {
    const r = await run1(T("user_id uuid", `create policy "p" on public.t for insert to authenticated with check (auth.uid() is not null);`));
    const m = only(r.findings, "R11")[0].message;
    expect(m).toContain("insert rows with any values");
    expect(m).not.toContain("as anyone");
  });
  it("says every row when USING is the matching clause", async () => {
    const r = await run1(T("user_id uuid", `create policy "p" on public.t for delete to authenticated using (auth.uid() is not null);`));
    expect(only(r.findings, "R11")[0].message).toContain("any logged-in user can delete every row");
  });
  it("reports once, covering both clauses, when USING and WITH CHECK both match", async () => {
    const r = await run1(T("user_id uuid", `create policy "p" on public.t for update to authenticated using (auth.uid() is not null) with check (auth.uid() is not null);`));
    const f = only(r.findings, "R11");
    expect(f).toHaveLength(1);
    expect(f[0].message).toContain("update every row");
    expect(f[0].message).toContain("any values");
  });
  it("skips R11 when R3 already fired on the same policy", async () => {
    const r = await run1(T("user_id uuid", `create policy "p" on public.t for update to authenticated using (true) with check (auth.uid() is not null);`));
    expect(rules(r.findings)).toEqual(["R3"]);
  });
  it("skips R11 when R2 already fired on the same policy", async () => {
    const r = await run1(T("user_id uuid", `create policy "p" on public.t for all using (true) with check (auth.uid() is not null);`));
    expect(rules(r.findings)).toEqual(["R2"]);
  });
  it("does not match an OR or auth.jwt() ->> 'role' (documented false negatives)", async () => {
    const or = await run1(T("user_id uuid", `create policy "p" on public.t for select to authenticated using (auth.uid() is not null or user_id = auth.uid());`));
    expect(only(or.findings, "R11")).toEqual([]);
    const jwt = await run1(T("user_id uuid", `create policy "p" on public.t for select to authenticated using ((auth.jwt() ->> 'role') = 'authenticated');`));
    expect(only(jwt.findings, "R11")).toEqual([]);
  });
  it("handles quoted and non-public schema tables", async () => {
    const r = await run1(`create table app."Notes" (id int, user_id uuid); alter table app."Notes" enable row level security;
create policy "p" on app."Notes" for select using (auth.uid() is not null);`);
    expect(r.findings.map((f) => [f.rule, f.object])).toEqual([["R11", "app.Notes.p"]]);
  });
  it("follows ALTER POLICY changing the role from authenticated to anon", async () => {
    const r = await analyzeSources([
      { file: "a.sql", sql: T("user_id uuid", `create policy "p" on public.t for select to authenticated using (auth.uid() is not null);`) },
      { file: "b.sql", sql: `alter policy "p" on public.t to anon;` },
    ]);
    expect(only(r.findings, "R11")).toEqual([]);
  });
});

describe("R12 more cases", () => {
  it("skips FOR ALL policies (documented gap)", async () => {
    const r = await run1(T("body text", `create policy "p" on public.t for all to anon using (body is not null) with check (body is not null);`));
    expect(only(r.findings, "R12")).toEqual([]);
  });
  it("flags WITH CHECK (auth.role() = 'anon'): it names a role, not the caller", async () => {
    const r = await run1(T("body text", `create policy "p" on public.t for insert to anon with check (auth.role() = 'anon');`));
    expect(only(r.findings, "R12")).toHaveLength(1);
  });
  it("still skips a function in another schema, auth.email() and auth.jwt()", async () => {
    for (const c of ["extensions.check_it(body)", "auth.email() = body", "auth.jwt() ->> 'sub' = body"]) {
      const r = await run1(T("body text", `create policy "p" on public.t for insert to anon with check (${c});`));
      expect([c, only(r.findings, "R12").length]).toEqual([c, 0]);
    }
  });
  it("follows ALTER POLICY changing the role to authenticated", async () => {
    const r = await analyzeSources([
      { file: "a.sql", sql: T("body text", `create policy "p" on public.t for insert to anon with check (body is not null);`) },
      { file: "b.sql", sql: `alter policy "p" on public.t to authenticated;` },
    ]);
    expect(only(r.findings, "R12")).toEqual([]);
  });
  it("is low when anon INSERT was revoked, medium again after a re-grant", async () => {
    const pol = `create policy "p" on public.t for insert to anon with check (body is not null);`;
    const revoked = await run1(T("body text", pol) + ` revoke insert on public.t from anon;`);
    expect(only(revoked.findings, "R12").map((f) => f.severity)).toEqual(["low"]);
    const regrant = await run1(T("body text", pol) + ` revoke all on public.t from anon; grant insert on public.t to anon;`);
    expect(only(regrant.findings, "R12").map((f) => f.severity)).toEqual(["medium"]);
  });
});

describe("review round 2", () => {
  const COLS = "user_id, owner_id, created_by, profile_id, author_id, account_id, tenant_id or org_id";
  it("prints the owner column list in low R10 and low R11 messages", async () => {
    const r10 = await run1(T("body text", `create policy "p" on public.t for select to authenticated using (true);`));
    expect(only(r10.findings, "R10")[0].message).toContain(COLS);
    expect(only(r10.findings, "R10")[0].message).not.toContain("${");
    const r11 = await run1(T("body text", `create policy "p" on public.t for select to authenticated using (auth.uid() is not null);`));
    expect(only(r11.findings, "R11")[0].message).toContain(COLS);
    expect(only(r11.findings, "R11")[0].message).not.toContain("${");
  });
  it("R12: auth.role() = 'authenticated' on a no-TO INSERT is R11 only, not R12", async () => {
    const r = await run1(T("body text", `create policy "p" on public.t for insert with check (auth.role() = 'authenticated');`));
    expect(rules(r.findings)).toEqual(["R11"]);
  });
  it("R12: auth.role() = 'public' and = 'anon' are caller-blind, either side", async () => {
    for (const c of ["auth.role() = 'public'", "'anon' = auth.role()"]) {
      const r = await run1(T("body text", `create policy "p" on public.t for insert to anon with check (${c});`));
      expect([c, only(r.findings, "R12").length]).toEqual([c, 1]);
    }
  });
  it("R12 low only for a TO anon policy; no-TO policies stay medium after a revoke", async () => {
    const rev = ` revoke insert on public.t from anon;`;
    const noTo = await run1(T("body text", `create policy "p" on public.t for insert with check (body is not null);`) + rev);
    expect(only(noTo.findings, "R12").map((f) => f.severity)).toEqual(["medium"]);
    const pub = await run1(T("body text", `create policy "p" on public.t for insert to public with check (body is not null);`) + rev);
    expect(only(pub.findings, "R12").map((f) => f.severity)).toEqual(["medium"]);
  });
  it("a column-level REVOKE INSERT does not downgrade R12", async () => {
    const pol = `create policy "p" on public.t for insert to anon with check (body is not null);`;
    const r = await run1(T("body text", pol) + ` revoke insert (body) on public.t from anon;`);
    expect(only(r.findings, "R12").map((f) => f.severity)).toEqual(["medium"]);
  });
  it("REVOKE FROM PUBLIC alone does not downgrade a TO anon policy (anon keeps its direct grant)", async () => {
    const pol = `create policy "p" on public.t for insert to anon with check (body is not null);`;
    const r = await run1(T("body text", pol) + " revoke insert on public.t from public;");
    expect(only(r.findings, "R12").map((f) => f.severity)).toEqual(["medium"]);
  });
  it("a revoke naming anon, table-level or ALL TABLES IN SCHEMA, downgrades a TO anon policy", async () => {
    const pol = `create policy "p" on public.t for insert to anon with check (body is not null);`;
    for (const rv of [`revoke insert on public.t from public, anon;`, `revoke all on all tables in schema public from anon;`]) {
      const r = await run1(T("body text", pol) + " " + rv);
      expect([rv, only(r.findings, "R12").map((f) => f.severity)]).toEqual([rv, ["low"]]);
    }
  });
  it("a revoke issued before the table exists changes nothing", async () => {
    const r = await run1(`revoke insert on public.t from anon; ` + T("body text", `create policy "p" on public.t for insert to anon with check (body is not null);`));
    expect(only(r.findings, "R12").map((f) => f.severity)).toEqual(["medium"]);
  });
});

describe("mixed app and parse errors", () => {
  it("reports findings across several files with file and line", async () => {
    const r = await scan("mixed-app");
    expect(r.findings.map((f) => `${f.rule}:${f.object}`)).toEqual([
      "R1:public.profiles",
      "R2:public.orders.orders open",
      "R5:public.admin_sum()",
      "R9:public.admin_sum()",
    ]);
    expect(r.findings[1].file).toMatch(/20240101000000_init\.sql$/);
    expect(r.findings[1].line).toBe(4);
  });
  it("skips one bad statement, warns, and still checks the rest", async () => {
    const r = await scan("parse-error");
    expect(r.warnings).toHaveLength(1);
    expect(r.warnings[0].line).toBe(2);
    expect(rules(r.findings)).toEqual(["R1"]);
  });
});
