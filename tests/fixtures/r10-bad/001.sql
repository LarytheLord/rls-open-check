create table public.notes (id int primary key, user_id uuid, body text);
alter table public.notes enable row level security;
create policy "read all" on public.notes for select to authenticated using (true);

create table public.docs (id int primary key, body text);
alter table public.docs add column created_by uuid;
alter table public.docs enable row level security;
create policy "docs read all" on public.docs for select to authenticated using ((true));

-- shared reference data: no owner column, so low
create table public.countries (code text primary key, name text);
alter table public.countries enable row level security;
create policy "countries read" on public.countries for select to authenticated using (true);
