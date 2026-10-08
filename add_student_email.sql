-- Run once in Supabase: SQL Editor -> New query -> Run.

-- 1. Email column on the students table
alter table public.students add column if not exists email text;

-- 2. Lets a newly registered student save their own email (used right after sign up)
create or replace function public.set_my_email(p_email text)
returns void
language sql
security definer
set search_path = public
as $$
  update public.students
     set email = lower(trim(p_email))
   where id = auth.uid();
$$;
revoke all on function public.set_my_email(text) from public;
grant execute on function public.set_my_email(text) to authenticated;

-- 3. Fill in emails for students who already registered with the new form
update public.students s
   set email = lower(u.raw_user_meta_data->>'contact_email')
  from auth.users u
 where u.id = s.id
   and s.email is null
   and coalesce(u.raw_user_meta_data->>'contact_email', '') <> '';
