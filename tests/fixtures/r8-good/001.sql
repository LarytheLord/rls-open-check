create table public.reports (id int primary key, user_id uuid, user_metadata jsonb, body text);
alter table public.reports enable row level security;
-- app_metadata can only be changed by the server
create policy "app meta" on public.reports for select to authenticated using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
-- a table you control
create policy "role table" on public.reports for update to authenticated using (
  exists (select 1 from public.staff s where s.user_id = auth.uid())
);
create policy "owner" on public.reports for insert to authenticated with check (auth.uid() = user_id);
-- user_metadata outside a policy is not this rule
create function public.meta() returns jsonb language sql as $$ select auth.jwt() -> 'user_metadata' $$;
