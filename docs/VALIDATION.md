# Validation on public code

I ran rls-open-check 0.1.0 on public Supabase code to see what it finds, and
whether what it finds is right. This is static reading of files from shallow
clones. I did not connect to any database or API, and I did not report anything
to anyone.

Date of the run: 2026-11-13. Date of the re-run: 2026-11-14.
Command: `node dist/bin.js <migrations folder> --fail-on critical`, once per
project (see the note on merging at the end).

The 13 November run used rules R1 to R7. On 14 November I ran the same command
again on the same clones with R1 to R9 (R8 and R9 are new, and R3 now also
covers INSERT). The tables below show the 14 November numbers. The 13 November
totals were 126 SQL files and 97 findings (R1 14, R2 27, R5 52, R7 4). The file
count is the same (126). The finding count is now 137: 39 R9 findings and 1 R3
finding are new, and R1, R2, R5 and R7 are unchanged. There are 0 R8 findings,
because no policy in this corpus reads `user_metadata`.

## What was scanned

Eight public repositories (one of them contributes more than one row below). One is named because it is the Supabase team's own
demo code (the `examples` directories of `supabase/supabase`). The others hold
findings that are real, so they are not named here: they are described as
"an open-source starter", "a chat app", and so on.

| Source | Projects scanned | SQL files | Findings (14 Nov) | By rule (14 Nov) |
|--------|------------------|-----------|----------|---------|
| `supabase/supabase`, `examples/*` (demo code, 20 projects with migrations) | 20 | 32 | 37 | R1 14, R2 5, R5 8, R7 4, R9 6 |
| A large open-source project, its own app migrations | 1 | 48 | 12 | R2 10, R9 2 |
| A UI library demo from the same source as one of the rows above | 1 | 1 | 1 | R2 1 |
| An open-source subscription starter | 1 | 1 | 3 | R2 2, R5 1 |
| An open-source RAG demo app | 1 | 5 | 2 | R5 1, R9 1 |
| A collection of user-profile starters (5 frameworks) | 5 | 10 | 10 | R2 5, R5 5 |
| An open-source chat app | 1 | 25 | 15 | R5 10, R9 5 |
| An open-source ticketing demo (`schema.sql`) | 1 | 1 | 4 | R2 2, R5 1, R9 1 |
| An open-source chat product (`schema.sql` and a docs SQL file) | 2 files | 2 | 49 | R2 1, R5 24, R9 24 |
| An open-source starter (`schema.sql`) | 1 | 1 | 4 | R2 1, R3 1, R5 2 |

Totals (re-run 2026-11-14, rules R1 to R9): 126 SQL files, 137 findings. By
rule: R1 14, R2 27, R3 1, R4 0, R5 52, R6 0, R7 4, R8 0, R9 39. On 13 November
(rules R1 to R7) the totals were 126 SQL files and 97 findings: R1 14, R2 27,
R5 52, R7 4. By severity, the 14 critical R1 findings are tables with no RLS,
the two critical R2 findings are INSERT policies, the one R3 finding is high,
and all 39 R9 findings are medium. There were no parse warnings in any of the
34 runs.

Clean projects (no findings): 6 of the 20 `examples` projects on 14 November,
including `todo-list`, `clerk` and both `storage` upload examples. On 13
November it was 8 of 20. The two `slack-clone` variants are no longer clean:
R9 now reports two functions in each.

The counts of R5 and R9 are inflated by one file: 24 of the 52 R5 findings and
24 of the 39 R9 findings are in a single docs SQL file where every function is
`SECURITY DEFINER`, without `SET search_path` and without a revoke from
`PUBLIC`.

## Manual judgement of 12 findings

I read the SQL for each finding. The 12 were picked to cover every rule that
fired, not at random. Labels:

- **True positive**: the tool describes the SQL correctly. "Intended" means the
  author clearly meant it (for example a public docs table), so you may still
  accept it, but the tool is right that the data is open.
- **False positive**: the tool is wrong about the SQL.
- **Unclear**: correct about the SQL, but whether it is a problem depends on
  something the files do not show.

| # | Finding | Judgement | Reason |
|---|---------|-----------|--------|
| 1 | R2 high, `SELECT` for `anon, authenticated` `USING (true)` on a docs page table (a large open-source project's app migrations) | True positive, intended | Public site content. Anyone with the anon key can read every row, which is the point. |
| 2 | R2 critical, `INSERT` for `public` `WITH CHECK (true)` on a feedback table (same project as #1) | True positive, intended | Anyone can insert rows. Meant for anonymous feedback, but it allows spam and unbounded writes. The critical severity is the tool's rule for open writes. |
| 3 | R2 high, public read on a search table (same project as #1) | True positive, intended | A policy comment says read-only access for `anon` and `authenticated`, and writes use a key that bypasses RLS. |
| 4 | R2 high, "anyone can view all profiles" (`SELECT` to `public`, a starter) | True positive | Every profile row is readable by anyone with the anon key. Whether profile fields are public is a product choice. |
| 5 | R1 critical, `public.employees` (Supabase example `database/employees`, demo code) | True positive | `create table employees` and no `ENABLE ROW LEVEL SECURITY` anywhere in the folder. It is demo code, and with the default Supabase setup the table is reachable through the API. |
| 6 | R1 critical, `public.sales_2000_01` (Supabase example `enterprise-patterns/partitions`) | Unclear | The parent `sales` and each partition are all reported: 9 findings for 3 logical tables. Each partition is reachable on its own through the API, so it is correct, but noisy. |
| 7 | R5 medium, `public.delete_old_file()` (a chat app) | True positive | `SECURITY DEFINER`, no `SET search_path`. Another function in the same migration does set it, and the tool did not confuse the two. |
| 8 | R5 medium, `public.supabase_url()` (a RAG demo app) | True positive | `SECURITY DEFINER` reading `vault.decrypted_secrets`, no `search_path`, and public functions are executable by default. The value it returns is a project URL, so impact is low. |
| 9 | R5 medium, `public.handle_new_user()` (Supabase example `user-management/expo-push-notifications`) | True positive | Same pattern, inside a trigger function. The classic fix is one line: `SET search_path = ''`. |
| 10 | R7 low, `anon` granted `SELECT, DELETE` on `public.profiles` with no policy for those commands (same example) | True positive, low | `GRANT ALL` to `anon` from a schema dump. RLS is on and no `anon` policy covers `SELECT` or `DELETE`, so the grant is dead weight. The tool says so and rates it low. |
| 11 | R2 high, "Allow public read-only access." on `products` (subscription starter) | True positive, intended | Product catalog for a pricing page, read-only. |
| 12 | R2 high, "Users can read all user tiers" `USING (true)` (chat product `schema.sql`) | True positive, unclear impact | The policy has no `TO` clause so it applies to `public`. The comment says read-only for users, but it also reaches `anon`. Whether tier names are sensitive is not in the files. |

Result of this first sample (rules R1 to R7): 0 false positives, 10 true
positives (6 of them intended public data), 2 unclear. Twelve is a small sample and I chose it to cover each rule, so
this says "I found no false positive", not "the false positive rate is zero".
No code change came out of this run, so there is no new failing test.

## Re-run 2026-11-14 after R8 and R9

I re-ran the 34 runs with R1 to R9 and read the new findings. R8: there are no
findings to read, so R8 is not validated by this corpus (see below). R3: one new
finding, read. R9: 39 findings, which is more than 6, so I read 6, picked from
six different sources and not from the 24-finding docs file alone (one of the
six comes from it). The labels are the same as above. I did not look at any
live database: "reachable" means "the SQL file, applied as written, leaves
`EXECUTE` with `anon`".

| # | Finding | Judgement | Reason |
|---|---------|-----------|--------|
| 13 | R9 medium, `public.create_user(text)` (Supabase example `slack-clone/nextjs-slack-clone`, demo code) | True positive | `SECURITY DEFINER`, inserts into `auth.users`, no revoke from `PUBLIC`. The comment calls it a test helper, but as written anyone with the anon key can call it through the Data API. Of the six, the one with the highest impact. |
| 14 | R9 medium, `public.authorize(app_permission)` (same example) | True positive, intended | A role check that policies call. The caller needs `EXECUTE` for the policies to work, and it only returns a boolean. The tool is right that anon can call it, impact is low. It has `SET search_path`, so R5 stays quiet. |
| 15 | R9 medium, `public.create_new_project()` (Supabase example `realtime/flutter-figma-clone`) | True positive, low impact | `SECURITY DEFINER`, no revoke. For an anonymous caller `auth.uid()` is null, so the member insert probably fails on a null profile, but the function is reachable. The helper `is_project_member` in the same file is flagged for the same reason and is meant to be called from policies. |
| 16 | R9 medium, a feedback-submission function (a large open-source project's app migrations) | True positive, intended | The file revokes from `PUBLIC` and grants to `anon` on purpose, with a comment saying so. The tool reports `anon` only (not `authenticated`), which matches the grants. A real, deliberate exposure. |
| 17 | R9 medium, a seat-reservation function (an open-source ticketing demo) | True positive, low impact | `SECURITY DEFINER`, reachable by anon. The body starts with an `auth.uid() is null` check that raises, so anon cannot use it. The tool cannot see that check and reports the exposure only. |
| 18 | R9 medium, a get-API-key function (the docs SQL file of the chat product) | True positive, unclear whether applied | The function takes a user id from the caller and returns that user's key rows, as `SECURITY DEFINER`. The file grants `EXECUTE` to a separate login role and never revokes from `PUBLIC`, so on Supabase anon could pass any id. It is a docs file, so I do not know if it was applied. |
| 19 | R3 high, `INSERT` to `authenticated` with `WITH CHECK (true)` on a posts table (an open-source starter) | True positive | Any logged-in user can insert any row, including a row with another user's `author_id`. The update and delete policies on the same table do check the owner, so this one stands out. |

Result of this second sample: 0 false positives, 7 true positives (4 of them
intended or low impact by design), 0 unclear. R8: 0 findings, 0 read.

Both samples together: 19 findings read, 17 true positives, 2 unclear, 0 false
positives. The R9 sample is 6 of 39, and 24 of the 39 come from one file, so
read it as "I found no false positive in 6 R9 findings", not as a rate.

Why R8 shows 0: R8 looks for policies that read `user_metadata` (the claim the
user can change). `raw_user_meta_data` appears in this corpus only inside
trigger functions that copy a name or avatar into a profile row, which is not
what R8 targets. So the corpus has nothing for R8 to find. This is not
evidence that R8 is right; it rests on the unit tests only.

## What the run showed

- **R2 on `SELECT` is the common finding, and it is often a deliberate choice.**
  Public docs and catalog tables are normal. R2 `SELECT` is rated high so you
  look at it. If a table is meant to be public, it is fine to accept.
- **R2 on write commands is the one to fix first.** The two critical R2
  findings here are anonymous `INSERT` policies.
- **R5 is mostly a hygiene finding** with a one-line fix.
- **R9 is correct about the SQL, and impact varies.** It is high when the
  function takes a user id or writes to `auth.users`, and low when the function
  is a policy helper or checks `auth.uid()` itself. The one-line fix is
  `REVOKE EXECUTE ... FROM PUBLIC`, then a grant to the roles that need it.
- **R1 on demo code is expected.** Examples often skip RLS to stay short.
- **Partitioned tables are noisy.** Each partition is reported next to its
  parent. A future change could group them.

## Things this validation does not show

- It does not show recall. Nothing here exercises R8, since the corpus has no
  policy that reads `user_metadata`. I did not look for vulnerabilities the tool missed.
- It does not look at the live state of any project. A repository's migrations
  can differ from what runs in production.
- It scanned only migrations and schema files, not application code, Storage
  policies set from the dashboard, or Edge Functions.

## Note on running more than one project

Passing several unrelated projects in one run merges their migrations into one
database, which changes results (a table in one project can look like it has RLS
because of another). Run it once per project. The numbers above were produced
that way.

## Reproduce

```
git clone --depth 1 https://github.com/supabase/supabase.git
cd rls-open-check && npm ci && npm run build
node dist/bin.js ../supabase/examples/database/employees/supabase/migrations
```
