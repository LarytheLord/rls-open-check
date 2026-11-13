create table public.comments (id int primary key, user_id uuid, body text);
alter table public.comments enable row level security;
create policy "own insert" on public.comments for insert to authenticated with check (auth.uid() = user_id);
create policy "own insert 2" on public.comments for insert to authenticated with check ((select auth.uid()) = user_id);
-- restrictive policies only narrow access
create policy "narrow" on public.comments as restrictive for insert to authenticated with check (true);
-- select with true for authenticated is a read, not R3
create policy "read all" on public.comments for select to authenticated using (true);
