create table public.comments (id int primary key, user_id uuid, body text);
alter table public.comments enable row level security;
create policy "any user inserts" on public.comments for insert to authenticated with check (true);
create policy "any user all" on public.comments for all to authenticated using (auth.uid() = user_id) with check (true);
