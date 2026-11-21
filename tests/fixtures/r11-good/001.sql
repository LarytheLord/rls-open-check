create table public.notes (id int primary key, user_id uuid, body text);
alter table public.notes enable row level security;
create policy "own read" on public.notes for select to authenticated using (auth.uid() = user_id);
create policy "own read2" on public.notes for select to authenticated using ((select auth.uid()) = user_id);
create policy "own update" on public.notes for update to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
create policy "own ins" on public.notes for insert to authenticated with check (auth.uid() is not null and auth.uid() = user_id);
create policy "role and own" on public.notes for delete to authenticated using (auth.role() = 'authenticated' and user_id = auth.uid());
create policy "member" on public.notes for select to authenticated using (exists (select 1 from public.members m where m.user_id = auth.uid()));
-- anon can never pass a uid check
create policy "anon only" on public.notes for select to anon using (auth.uid() is not null);
-- restrictive policies only narrow access
create policy "narrow" on public.notes as restrictive for select to authenticated using (auth.uid() is not null);
-- true is R3 or R10, not R11
create policy "open" on public.notes for update to authenticated using (true) with check (auth.uid() = user_id);
