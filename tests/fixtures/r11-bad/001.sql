create table public.notes (id int primary key, user_id uuid, body text);
alter table public.notes enable row level security;
create policy "logged in read" on public.notes for select to authenticated using (auth.uid() is not null);
create policy "wrapped uid" on public.notes for update to authenticated using ((select auth.uid()) is not null) with check ((select auth.uid()) is not null);
create policy "role check" on public.notes for delete using (auth.role() = 'authenticated');
create policy "insert any" on public.notes for insert to authenticated with check (auth.uid() is not null);
create policy "both" on public.notes for all to authenticated using (auth.uid() is not null and auth.role() = 'authenticated');

-- shared data, no owner column: read is low
create table public.tags (id int primary key, label text);
alter table public.tags enable row level security;
create policy "tags read" on public.tags for select to authenticated using (auth.role() = 'authenticated');
