create table public.reports (id int primary key, user_id uuid, body text);
alter table public.reports enable row level security;
create policy "jwt arrow" on public.reports for select to authenticated using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');
create policy "jwt path" on public.reports for update to authenticated using ((auth.jwt() #>> '{user_metadata,role}') = 'admin');
create policy "users table" on public.reports for delete to authenticated using (
  exists (select 1 from auth.users u where u.id = auth.uid() and u.raw_user_meta_data ->> 'role' = 'admin')
);
create policy "check side" on public.reports for insert to authenticated with check ((auth.jwt() -> 'user_metadata' ->> 'tier') = 'pro');
create policy "narrow" on public.reports as restrictive for select to authenticated using ((auth.jwt() -> 'user_metadata' ->> 'ok') = 'yes');
