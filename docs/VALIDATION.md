# Validation on public code

I ran rls-open-check 0.1.0 on public Supabase code to see what it finds, and
whether what it finds is right. This is static reading of files from shallow
clones. I did not connect to any database or API, and I did not report anything
to anyone.

Date of the run: 2026-11-13. Command: `node dist/bin.js <migrations folder>
--fail-on critical`, once per project (see the note on merging at the end).

## What was scanned

Eight public repositories (one of them contributes more than one row below). One is named because it is the Supabase team's own
demo code (the `examples` directories of `supabase/supabase`). The others hold
findings that are real, so they are not named here: they are described as
"an open-source starter", "a chat app", and so on.

| Source | Projects scanned | SQL files | Findings | By rule |
|--------|------------------|-----------|----------|---------|
| `supabase/supabase`, `examples/*` (demo code, 20 projects with migrations) | 20 | 32 | 31 | R1 14, R2 5, R5 8, R7 4 |
| A large open-source project, its own app migrations | 1 | 48 | 10 | R2 10 |
| A UI library demo from the same source as one of the rows above | 1 | 1 | 1 | R2 1 |
| An open-source subscription starter | 1 | 1 | 3 | R2 2, R5 1 |
| An open-source RAG demo app | 1 | 5 | 1 | R5 1 |
| A collection of user-profile starters (5 frameworks) | 5 | 10 | 10 | R2 5, R5 5 |
| An open-source chat app | 1 | 25 | 10 | R5 10 |
| An open-source ticketing demo (`schema.sql`) | 1 | 1 | 3 | R2 2, R5 1 |
| An open-source chat product (`schema.sql` and a docs SQL file) | 2 files | 2 | 25 | R2 1, R5 24 |
| An open-source starter (`schema.sql`) | 1 | 1 | 3 | R2 1, R5 2 |

Totals: 126 SQL files, 97 findings. By rule: R1 14, R2 27, R3 0, R4 0, R5 52,
R6 0, R7 4. By severity, the two critical R2 findings are INSERT policies and
the 14 critical R1 findings are tables with no RLS. There were no parse
warnings in any of the 34 runs.

Clean projects (no findings): 8 of the 20 `examples` projects, including
`todo-list`, `clerk`, both `slack-clone` variants and both `storage` upload
examples.

The count of R5 is inflated by one file: 24 of the 52 are in a single docs SQL
file where every function is `SECURITY DEFINER` without `SET search_path`.

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

Result: 0 false positives, 10 true positives (6 of them intended public
data), 2 unclear. Twelve is a small sample and I chose it to cover each rule, so
this says "I found no false positive", not "the false positive rate is zero".
No code change came out of this run, so there is no new failing test.

## What the run showed

- **R2 on `SELECT` is the common finding, and it is often a deliberate choice.**
  Public docs and catalog tables are normal. R2 `SELECT` is rated high so you
  look at it. If a table is meant to be public, it is fine to accept.
- **R2 on write commands is the one to fix first.** The two critical R2
  findings here are anonymous `INSERT` policies.
- **R5 is mostly a hygiene finding** with a one-line fix.
- **R1 on demo code is expected.** Examples often skip RLS to stay short.
- **Partitioned tables are noisy.** Each partition is reported next to its
  parent. A future change could group them.

## Things this validation does not show

- It does not show recall. I did not look for vulnerabilities the tool missed.
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
