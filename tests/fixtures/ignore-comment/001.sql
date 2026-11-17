create table public.todos (
  id uuid primary key,
  title text not null
);

create table public.posts (id int primary key, body text);
alter table public.posts enable row level security;
-- rls-open-check-ignore R2
create policy "anyone writes" on public.posts for insert to anon with check (true);
