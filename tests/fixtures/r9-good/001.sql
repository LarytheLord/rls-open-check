create function public.locked() returns int language sql security definer set search_path = '' as $$ select 1 $$;
revoke execute on function public.locked() from public;

create function public.locked_all(x int) returns int language sql security definer set search_path = '' as $$ select x $$;
revoke execute on function public.locked_all(int) from public, anon, authenticated;

create function public.service_only() returns int language sql security definer set search_path = '' as $$ select 1 $$;
revoke all on function public.service_only() from public;
grant execute on function public.service_only() to service_role;

-- other schemas are not exposed
create function private.hidden() returns int language sql security definer set search_path = '' as $$ select 1 $$;

-- invoker functions run with the caller's rights
create function public.invoker() returns int language sql as $$ select 1 $$;

-- trigger functions cannot be called through the API
create function public.on_signup() returns trigger language plpgsql security definer set search_path = '' as $$ begin return new; end $$;
