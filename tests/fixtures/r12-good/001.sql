create table public.messages (id int primary key, body text, user_id uuid);
alter table public.messages enable row level security;
create policy "own insert" on public.messages for insert to anon, authenticated with check (auth.uid() = user_id);
create policy "jwt insert" on public.messages for insert with check ((auth.jwt() ->> 'sub')::uuid = user_id);
create policy "wrapped" on public.messages for insert to anon with check ((select auth.uid()) = user_id);
-- authenticated only, no identity: not anon
create policy "auth any" on public.messages for insert to authenticated with check (body is not null);
-- always true is R2, not R12
create policy "open" on public.messages for insert to anon with check (true);
-- restrictive policies only narrow access
create policy "narrow" on public.messages as restrictive for insert to anon with check (length(body) < 500);
-- checks the tool cannot see into: a function of your own, a subquery, a setting
create function public.captcha_ok(t text) returns boolean language sql as $$ select true $$;
create policy "captcha" on public.messages for insert to anon with check (captcha_ok(body));
create policy "subq" on public.messages for insert to anon with check (exists (select 1 from public.invites i where i.code = body));
create policy "setting" on public.messages for insert to anon with check (current_setting('request.headers', true)::json ->> 'x-token' = body);
