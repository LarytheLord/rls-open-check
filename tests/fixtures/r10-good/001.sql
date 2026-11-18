create table public.notes (id int primary key, user_id uuid, body text);
alter table public.notes enable row level security;
create policy "own read" on public.notes for select to authenticated using ((select auth.uid()) = user_id);
-- restrictive policies only narrow access
create policy "narrow" on public.notes as restrictive for select to authenticated using (true);

-- anon or no TO clause with true is R2, not R10
create table public.tips (id int primary key, user_id uuid);
alter table public.tips enable row level security;
create policy "tips anon" on public.tips for select to anon using (true);

-- RLS off: R1 covers the table, the policy does nothing
create table public.old (id int primary key, user_id uuid);
create policy "old read" on public.old for select to authenticated using (true);

-- UPDATE and DELETE with true for authenticated are R3, not R10
create table public.items (id int primary key, user_id uuid);
alter table public.items enable row level security;
create policy "items upd" on public.items for update to authenticated using (true) with check (auth.uid() = user_id);
