create table public.messages (id int primary key, body text, user_id uuid);
alter table public.messages enable row level security;
create policy "anon insert" on public.messages for insert to anon with check (length(body) < 500);
create policy "default insert" on public.messages for insert with check (body is not null);
create policy "pub insert" on public.messages for insert to public, authenticated with check (user_id is null);
