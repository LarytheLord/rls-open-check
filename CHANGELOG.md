# Changelog

All notable changes to rls-open-check are listed here. The format follows
Keep a Changelog, and the project uses Semantic Versioning.

## [0.2.0] - unreleased

### Changed

- R12 is now always low severity. In a hand-read sample of 52 findings none of 5 R12 findings was real, and in a second sample of 12 R12 findings 3 were real (3 of the 16 decided findings in both samples, about 19 percent): most anonymous inserts were public forms or event logs. The message still notes when INSERT was revoked from anon. See docs/VALIDATION.md.

### Added

- `-- rls-open-check-ignore R2` on the line directly above a statement ignores
  the listed rule ids (comma separated) for that statement. Ignored findings do
  not affect the exit code. Text output shows "N finding(s) ignored by comment",
  JSON has an `ignored` array, and SARIF marks them with `suppressions` of kind
  `inSource`. A trailing `-- reason` after the ids is allowed.
- `--strict` exits 1 on any parse warning and includes the number of skipped
  statements in the text summary. Without the flag, behavior is unchanged.
- Rule R8: policy whose `USING` or `WITH CHECK` reads `user_metadata` or
  `raw_user_meta_data`. Users can edit their own `user_metadata`. Follows
  Supabase splinter lint 0015 (`rls_references_user_metadata`).
- Rule R9: `SECURITY DEFINER` function in `public` that `anon` or
  `authenticated` can run, through an explicit `GRANT EXECUTE`, `PUBLIC`, or the
  Postgres default of EXECUTE for `PUBLIC`. Later `REVOKE`, `GRANT ... ON ALL
  FUNCTIONS IN SCHEMA` and `ALTER DEFAULT PRIVILEGES ... ON FUNCTIONS` are
  applied in file order. Follows splinter lints 0028 and 0029. Trigger functions
  are skipped.
- Rule R10: `SELECT` policy for `authenticated` with `USING (true)`. Medium when
  the table has a `user_id`, `owner_id`, `created_by` or `profile_id` column,
  low when it has none.
- Rule R11: policy whose `USING` or `WITH CHECK` is only `auth.uid() IS NOT NULL`
  or `auth.role() = 'authenticated'`, with no comparison to a column.
- Rule R12: `INSERT` policy for `anon` or with no `TO` clause whose `WITH CHECK`
  never reads `auth.uid()` or `auth.jwt()`.
- The analyzer now tracks column names per table.
- R8 to R12 are listed in the SARIF rule metadata.
- Every rule has a stable `### R1` style heading in the README, and each SARIF
  rule carries a `helpUri` that points to it
  (`https://github.com/LarytheLord/rls-open-check#r1`).
- Text output ends with one `Docs: <url>` line per rule that fired, not per
  finding.
- README section "Show that you check" with a badge snippet for CI users.

### Changed

- R3 now also flags `WITH CHECK (true)` on INSERT for `authenticated` (high).
  Before, an INSERT policy like this was not reported.
- A `SECURITY DEFINER` function in `public` without a `REVOKE EXECUTE` now
  reports R9 as well as R5. Projects that scan clean on 0.1.0 can get new
  findings.

## [0.1.0] - never published

Internal version, never published to npm. Its contents ship in 0.2.0, the first
public release.

### Added

- Command line tool that reads Supabase and Postgres SQL migration files with
  the Postgres parser (`libpg-query`) and applies them in file name order.
- Rule R1: table in `public` that never gets `ENABLE ROW LEVEL SECURITY`.
- Rule R2: policy with an always true condition for `anon` or `public`.
- Rule R3: policy for `authenticated` that lets any logged-in user update or
  delete any row.
- Rule R4: `GRANT` to `anon` on a table without RLS, including
  `GRANT ... ON ALL TABLES IN SCHEMA` and `ALTER DEFAULT PRIVILEGES`.
- Rule R5: `SECURITY DEFINER` function in `public` without `SET search_path`.
- Rule R6: `DISABLE ROW LEVEL SECURITY` with no later `ENABLE`.
- Rule R7: grant of `SELECT`, `INSERT`, `UPDATE` or `DELETE` to `anon` or
  `authenticated` where RLS is off, or no policy covers that command for that
  role.
- Output formats: text (default), `--format json` (and `--json`), and
  `--format sarif` (SARIF 2.1.0) for GitHub code scanning.
- `--fail-on <low|medium|high|critical>` for CI. Exit codes: 0 ok, 1 findings
  at or above the level, 2 usage or file error.
- No network calls and no database connection.

### Fixed

- `REVOKE` statements were read as grants because the parser omits `is_grant`
  for them, so a `REVOKE` never removed an earlier grant. They are now handled
  correctly.

### Known limits

- Static check of migration files only. It cannot see changes made in the
  dashboard or SQL editor.
- `SET search_path` and `DO $$ ... EXECUTE` blocks are not tracked. This can
  cause false R1 findings, and tables created inside `EXECUTE` are not checked.
- SARIF paths outside the git root are written as absolute `file:///` URIs.
- It does not judge policy logic, and a clean result is not proof of safety.
  See "Limits" in the README.
