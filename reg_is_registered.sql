-- Run once in Supabase: SQL Editor -> New query -> Run.
-- Lets the sign-up and sign-in screens ask "is this registration number already registered?"
create or replace function public.reg_is_registered(p_reg text)
returns boolean
language sql
security definer
set search_path = public, auth
stable
as $$
  select exists (select 1 from public.students where lower(reg_number) = lower(p_reg))
      or exists (select 1 from auth.users where lower(email) = lower(p_reg) || '@hashclass.app');
$$;

revoke all on function public.reg_is_registered(text) from public;
grant execute on function public.reg_is_registered(text) to anon, authenticated;
