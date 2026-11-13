# rls-open-check

[![ci](https://github.com/LarytheLord/rls-open-check/actions/workflows/ci.yml/badge.svg)](https://github.com/LarytheLord/rls-open-check/actions/workflows/ci.yml)

A free command line tool that reads your Supabase or Postgres SQL migration
files and flags Row Level Security (RLS) setups that let the wrong people read
or write your data.

A common mistake in hurried or generated migrations is to turn RLS on, then add
a policy like `USING (true)` to make an error go away. That policy lets anyone
with your public API key read or change every row. This tool looks for that and
a few related mistakes.

Static check only. It runs on your files. It makes no network calls and needs
no database connection. It is a linter, not an audit: read [Limits](#limits)
before you trust a clean result.

## Why

Apps made with AI app builders can ship Supabase tables whose Row Level
Security is switched on but whose policies are always true, for example
`USING (true)` for `anon`. RLS is on, so the dashboard looks fine, but the
policy lets anyone with the public API key read or change every row. Supabase
documents RLS as the access control for tables exposed through its API:
https://supabase.com/docs/guides/database/postgres/row-level-security

This tool reads your migration files and flags that pattern and a few related
ones, before they reach production.

## Quick start (30 seconds)

Needs Node 18 or newer. This works today, without npm:

```
git clone https://github.com/LarytheLord/rls-open-check.git
cd rls-open-check
npm ci
npm run build
node dist/bin.js path/to/supabase/migrations
```

It exits 1 if it finds anything high or critical. No config, no database
connection, no network calls.

`npx rls-open-check` will work once the package is published to npm. It is not
published yet. After that, from the root of a Supabase project:

```
npx rls-open-check
npx rls-open-check db/schema.sql
npx rls-open-check supabase/migrations --fail-on medium
npx rls-open-check --json
```

Run it once per project. If you pass folders from two unrelated projects in
one run, their migrations are merged and treated as one database.

## Sample output

For a migration that opens a table to `anon` and forgets RLS on another:

```text
supabase/migrations/20240101000000_init.sql:3  [critical] R2  public.orders.orders open
    Policy "orders open" on public.orders allows ALL for anon with a condition that is always true, so anyone with the public API key gets access.
    Fix: Replace true with a real check such as auth.uid() = user_id, or change the role to authenticated.

supabase/migrations/20240101000000_init.sql:5  [critical] R1  public.notes
    Table public.notes is in the public schema and never has Row Level Security enabled.
    Fix: Add ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY and policies for who may read and write.

Scanned 1 file(s). 2 finding(s): 2 critical, 0 high, 0 medium, 0 low.
2 finding(s) at or above "high": failing.
Static check of migration files only. A clean result is not proof of safety.
```

The sample is checked against the real output by the test suite
(`tests/launch.test.ts`), so it does not drift.

## GitHub Action

Fail a pull request when a migration adds a high or critical finding (also in
[examples/github-action.yml](examples/github-action.yml)). This uses `npx`, so it
needs the package to be published; until then, build from a clone as in the
quick start:

```yaml
name: rls-check
on:
  pull_request:
    paths:
      - "supabase/migrations/**"

jobs:
  rls-open-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - run: npx rls-open-check supabase/migrations --fail-on high
```

Pin a version for repeatable builds, for example `npx rls-open-check@0.1.0`.
To see everything but never fail the build, add `|| true` to the command.

## What it checks

Each finding has a rule id, a severity and a one-line fix hint.

| Id | Severity | What it flags | Fix hint |
|----|----------|---------------|----------|
| R1 | critical | A table in the `public` schema that never gets `ENABLE ROW LEVEL SECURITY` | Enable RLS and add policies |
| R2 | critical (INSERT, UPDATE, DELETE, ALL) or high (SELECT) | A policy with `USING (true)` or `WITH CHECK (true)` for `anon` or `public`. A policy with no `TO` clause counts as `public` | Use a real condition such as `auth.uid() = user_id` |
| R3 | high | A policy for `authenticated` with `USING (true)` on UPDATE, DELETE or ALL, or `WITH CHECK (true)` on INSERT, UPDATE or ALL: any logged-in user can change or add anyone's rows | Limit rows to their owner, check the new row with `WITH CHECK (auth.uid() = user_id)` |
| R4 | high | `GRANT ... TO anon` on a table that has no RLS | Enable RLS or `REVOKE` the grant |
| R5 | medium | A `SECURITY DEFINER` function in `public` with no `SET search_path` | Add `SET search_path = ''` |
| R6 | critical | `DISABLE ROW LEVEL SECURITY` on a table and no later `ENABLE` | Enable RLS again |
| R7 | high (RLS off) or low (RLS on) | A `public` table with `GRANT SELECT`, `INSERT`, `UPDATE` or `DELETE` to `anon` or `authenticated`, where RLS is off or no policy covers that command for that role | Enable RLS and add a policy for the command, or `REVOKE` it |
| R8 | high | A policy whose `USING` or `WITH CHECK` reads `user_metadata` or `raw_user_meta_data`, for example `auth.jwt() -> 'user_metadata'`. Users can edit their own `user_metadata`, so they can pass the check. Like Supabase splinter lint 0015 | Use `app_metadata` (only the server can change it) or a table you control |
| R9 | medium | A `SECURITY DEFINER` function in `public` that `anon` or `authenticated` can run: `GRANT EXECUTE` to either role or `PUBLIC`, or no `REVOKE EXECUTE ... FROM PUBLIC` (Postgres grants EXECUTE to `PUBLIC` on new functions). Like splinter lints 0028 and 0029. Separate from R5, so one function can get both | `REVOKE EXECUTE ON FUNCTION ... FROM PUBLIC, anon, authenticated`, then grant only to roles that need it |

Details:

- **Migrations are applied in order.** Files are read in file name order (the
  timestamp prefix), like Supabase does. A later `DROP POLICY`, `ALTER POLICY`,
  `DROP TABLE`, `REVOKE`, `ENABLE ROW LEVEL SECURITY`, `CREATE OR REPLACE
  FUNCTION` or `ALTER FUNCTION ... SET search_path` removes an earlier finding.
- **Real parser.** SQL is parsed with the Postgres parser (`libpg-query`), not
  with regular expressions. Comments, quoting and dollar quoting are handled.
- **What counts as "always true".** `true`, `(true)`, `true::boolean`, `1 = 1`,
  and `OR` expressions that contain one of these.
- **Restrictive policies** (`AS RESTRICTIVE`) are skipped, because they only
  narrow access.
- **Policies on a table with RLS off** are not reported as R2 or R3. R1 or R6
  already covers that table.
- **R4 also looks at** `GRANT ... ON ALL TABLES IN SCHEMA` and
  `ALTER DEFAULT PRIVILEGES ... GRANT ... TO anon`. `PUBLIC` counts like `anon`.
- **R7 in detail.** Supabase has changed how new tables in `public` get access
  through the Data API, so more projects now grant `anon` and `authenticated`
  access to tables by hand, in migrations. See the
  [Supabase changelog entry](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically)
  and the [Securing your API guide](https://supabase.com/docs/guides/database/hardening-data-api).
  R7 checks each grant against the policies. It reads `GRANT`, `REVOKE`,
  `GRANT ... ON ALL TABLES IN SCHEMA` and `ALTER DEFAULT PRIVILEGES`. `PUBLIC`
  counts for both roles, and `ALL` counts as the four commands. A policy covers
  a command when it is permissive, is for that command or `ALL`, and names the
  role or `public`. With RLS off the finding is high. With RLS on and no policy
  the grant does nothing (Postgres denies by default), so it is low: it is
  usually a missing policy or a leftover grant. R7 can report the same table as
  R1, R4 or R6; they answer different questions. This tool does not read the
  dates or defaults of a Supabase project. It only reads your SQL.
- **R8 in detail.** Any string or column name that contains `user_metadata` or
  `raw_user_meta_data` inside a policy counts, in `USING` or `WITH CHECK`, for
  every policy including restrictive ones. This is a name match: a column of
  your own that is named `user_metadata` is flagged too, and a policy that reads
  metadata through a function the tool cannot see into is not. A policy changed
  later with `ALTER POLICY` or removed with `DROP POLICY` is judged by its last
  form.
- **R9 in detail.** The tool starts each function with EXECUTE held by `PUBLIC`,
  like Postgres. It then reads `GRANT` and `REVOKE` on a function, on
  `ALL FUNCTIONS IN SCHEMA`, and `ALTER DEFAULT PRIVILEGES ... ON FUNCTIONS`, in
  file order. `CREATE OR REPLACE` keeps the privileges the function had.
  Functions that return `trigger` are skipped, because the Data API cannot call
  them (splinter reports them). Only the `public` schema is checked. Supabase
  projects may also have default privileges set outside your migrations that
  give `anon` and `authenticated` EXECUTE on new functions. This tool cannot see
  those, so a clean R9 result does not rule out a function that is callable
  through such a default.
- A statement that does not parse is skipped with a warning. The rest of the
  file is still checked.

## Limits

Read this before you rely on the tool.

- **It is static.** It cannot see changes made in the Supabase dashboard, in the
  SQL editor, or by other tools. If your live database differs from your
  migration files, this tool does not know.
- **It is a linter, not a security review.** It is not a penetration test and
  not a certification of any kind.
- **A clean result is not proof of safety.** It finds a short list of common
  mistakes. It does not understand what your policies mean.
- It does not judge policy logic. `USING (user_id IS NOT NULL)` or a policy that
  checks the wrong column passes.
- It does not check Storage bucket settings, Edge Functions, API keys in your
  front end, views (views run with the owner's rights unless
  `security_invoker` is set), or `service_role` use.
- It does not check `FORCE ROW LEVEL SECURITY`, column privileges, or roles
  other than `anon`, `public` and `authenticated`.
- **Not tracked: `SET search_path` and dynamic SQL.** The tool does not follow
  `SET search_path`. It treats a table name with no schema as being in
  `public`, so a table created after `SET search_path = private` can get a false
  R1. It also does not look inside `DO $$ ... $$` blocks or `EXECUTE` strings.
  A table created or `ENABLE ROW LEVEL SECURITY` run inside such a block is not
  seen: a table that is created normally and has RLS enabled only inside
  `DO $$ ... EXECUTE ... $$` is reported as R1 (a false R1), and a table created
  inside `EXECUTE` is never checked. If you do this, review those tables by hand
  or move the statements out of the dynamic block.
- It does not connect to a database. To check the live state, query
  `pg_policies` and `pg_class.relrowsecurity` on the real project.

## Options

```
rls-open-check [options] [paths...]

  --fail-on <level>  Exit 1 if a finding is at or above this level:
                     low, medium, high, critical (default: high)
  --format <name>    Output format: text (default), json or sarif
  --json             Same as --format json
  -h, --help
  -v, --version
```

Exit codes: `0` no finding at or above `--fail-on`, `1` at least one, `2` usage
error or no files found. Parse warnings do not change the exit code.

JSON output has `findings` (each with `rule`, `severity`, `object`, `file`,
`line`, `message`, `fix`), `summary` (counts by severity), `warnings` and
`filesScanned`.

## SARIF and GitHub code scanning

To see findings in the Security tab and as annotations on the pull request,
upload a SARIF file. `--format sarif` prints a SARIF 2.1.0 log. File paths are relative to the git
root, so GitHub can show findings on the changed lines. A file outside the git root
(for example a path passed from another directory) has no repo-relative path, so
it is written as an absolute `file:///` URI. GitHub cannot place those on a
changed line, so run the tool from inside the repository. Code scanning must be available
for the repository (public repositories, or private ones with GitHub Code
Security). The exit code still
follows `--fail-on`, so write the file first and upload it even when the check
fails:

```yaml
jobs:
  rls-open-check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - run: npx rls-open-check supabase/migrations --format sarif > rls.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: rls.sarif
```

SARIF levels: critical and high are `error`, medium is `warning`, low is
`note`. Parse warnings go in the run's notifications, not in the results.

## Install

No install is needed with `npx`. To add it to a project:

```
npm install --save-dev rls-open-check
```

Requires Node 18 or newer.

## Validation

Numbers from running it on public Supabase code are in
[docs/VALIDATION.md](docs/VALIDATION.md).

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Develop

```
npm install
npm test        # vitest
npm run build   # compiles to dist/
```

Test fixtures are in `tests/fixtures`. Each rule has bad and good migrations,
and there are cases for migration order.

## License

MIT. Author: Guild (guilds.work).
