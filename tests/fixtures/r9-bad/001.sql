-- PUBLIC keeps EXECUTE by default, so anon and authenticated can call this
create function public.open_default() returns int language sql security definer set search_path = '' as $$ select 1 $$;

-- PUBLIC revoked, then granted back to one API role
create function public.auth_only(x int) returns int language sql security definer set search_path = '' as $$ select x $$;
revoke execute on function public.auth_only(int) from public;
grant execute on function public.auth_only(int) to authenticated;

create function public.anon_only() returns int language sql security definer set search_path = '' as $$ select 1 $$;
revoke all on function public.anon_only() from public;
grant execute on function public.anon_only() to anon;

-- revoking from anon alone does not help while PUBLIC still has EXECUTE
create function public.still_open() returns int language sql security definer set search_path = '' as $$ select 1 $$;
revoke execute on function public.still_open() from anon, authenticated;

-- invoker functions are not flagged
create function public.invoker() returns int language sql as $$ select 1 $$;
