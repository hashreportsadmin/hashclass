-- ============================================================================
-- HashCLASS: admin panel additions
-- Run the whole file once in: Supabase Dashboard > SQL Editor > New query > Run.
-- Run it AFTER supabase.sql (which you already ran). Safe to run again.
--
-- Admin sign-in:  Position = Tutorial Lecturer   Password = Hashdatt@2001
-- (behind the scenes the admin account is lecturer@hashclass.app)
-- ============================================================================

create extension if not exists pgcrypto with schema extensions;

-- 1. Who is an admin ---------------------------------------------------------
create table if not exists public.admins (
  id         uuid primary key references auth.users (id) on delete cascade,
  position   text        not null default 'Tutorial Lecturer',
  created_at timestamptz not null default now()
);

alter table public.admins enable row level security;
drop policy if exists "admin reads own row" on public.admins;
create policy "admin reads own row"
  on public.admins for select
  to authenticated
  using (id = auth.uid());
grant select on public.admins to authenticated;

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (select 1 from public.admins where id = auth.uid());
$$;
revoke all on function public.is_admin() from public, anon;
grant execute on function public.is_admin() to authenticated;

-- 2. New class columns -------------------------------------------------------
alter table public.class_sessions
  add column if not exists duration_minutes integer not null default 60
    check (duration_minutes between 15 and 480);
alter table public.class_sessions
  add column if not exists started_at timestamptz;

-- 3. Class links live in their own table.
--    A student can read a link only while the class is LIVE (after START CLASS).
create table if not exists public.class_links (
  session_id  uuid primary key references public.class_sessions (id) on delete cascade,
  meeting_url text not null check (meeting_url ~* '^https://')
);

-- Move any link that was saved on the session row itself into class_links
insert into public.class_links (session_id, meeting_url)
select id, meeting_url from public.class_sessions
where meeting_url ~* '^https://'
on conflict (session_id) do nothing;
update public.class_sessions set meeting_url = null where meeting_url is not null;

-- If a link is ever written to class_sessions.meeting_url again (for example from
-- the SQL editor), move it into class_links straight away so it never leaks early.
create or replace function public.hc_move_link()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.meeting_url is not null and new.meeting_url ~* '^https://' then
    insert into public.class_links (session_id, meeting_url)
    values (new.id, new.meeting_url)
    on conflict (session_id) do update set meeting_url = excluded.meeting_url;
  end if;
  if new.meeting_url is not null then
    update public.class_sessions set meeting_url = null where id = new.id;
  end if;
  return null;
end;
$$;
drop trigger if exists hc_move_link_trg on public.class_sessions;
create trigger hc_move_link_trg
  after insert or update of meeting_url on public.class_sessions
  for each row execute function public.hc_move_link();

-- 4. Row Level Security for admins -------------------------------------------
alter table public.class_links enable row level security;

drop policy if exists "admin manages class links"     on public.class_links;
drop policy if exists "student reads live class link" on public.class_links;
drop policy if exists "admin reads students"          on public.students;
drop policy if exists "admin reads registrations"     on public.registrations;
drop policy if exists "admin updates payments"        on public.registrations;
drop policy if exists "admin manages class sessions"  on public.class_sessions;
drop policy if exists "admin reads attendance"        on public.attendance;

create policy "admin manages class links"
  on public.class_links for all
  to authenticated
  using (public.is_admin())
  with check (public.is_admin());

create policy "student reads live class link"
  on public.class_links for select
  to authenticated
  using (
    exists (
      select 1
      from public.class_sessions s
      join public.registrations r
        on r.course_code = s.course_code and r.student_id = auth.uid()
      where s.id = class_links.session_id
        and s.status = 'live'
    )
  );

create policy "admin reads students"
  on public.students for select
  to authenticated
  using (public.is_admin());

create policy "admin reads registrations"
  on public.registrations for select
  to authenticated
  using (public.is_admin());

create policy "admin updates payments"
  on public.registrations for update
  to authenticated
  using (public.is_admin())
  with check (public.is_admin());

create policy "admin manages class sessions"
  on public.class_sessions for all
  to authenticated
  using (public.is_admin())
  with check (public.is_admin());

create policy "admin reads attendance"
  on public.attendance for select
  to authenticated
  using (public.is_admin());

grant select, insert, update, delete on public.class_links to authenticated;
grant update (payment_status) on public.registrations to authenticated;
grant update, delete on public.class_sessions to authenticated;

-- 5. Saving a lesson: one call that saves the class and its link together ----
create or replace function public.admin_create_class(
  p_course    text,
  p_starts_at timestamptz,
  p_duration  integer,
  p_link      text
) returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  new_id uuid;
begin
  if not public.is_admin() then
    raise exception 'not_admin';
  end if;

  insert into public.class_sessions (course_code, starts_at, duration_minutes, status)
  values (p_course, p_starts_at, p_duration, 'scheduled')
  returning id into new_id;

  insert into public.class_links (session_id, meeting_url)
  values (new_id, p_link);

  return new_id;
end;
$$;
revoke all on function public.admin_create_class(text, timestamptz, integer, text) from public, anon;
grant execute on function public.admin_create_class(text, timestamptz, integer, text) to authenticated;

-- 6. Real time: the admin panel also listens to new registrations --------------
do $$
begin
  if not exists (select 1 from pg_publication_tables
                 where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'students') then
    alter publication supabase_realtime add table public.students;
  end if;
end $$;

-- 7. The admin account ---------------------------------------------------------
-- Creates lecturer@hashclass.app with the password above.
-- If this block prints a notice instead of finishing, create the user by hand:
--   Dashboard > Authentication > Users > Add user > Create new user
--   Email: lecturer@hashclass.app   Password: Hashdatt@2001   tick "Auto Confirm User"
-- then run this file again (or just the INSERT INTO public.admins statement below).
do $$
declare
  admin_id    uuid;
  admin_email text := 'lecturer@hashclass.app';
begin
  select id into admin_id from auth.users where email = admin_email;
  if admin_id is null then
    admin_id := gen_random_uuid();

    insert into auth.users (
      instance_id, id, aud, role, email, encrypted_password, email_confirmed_at,
      raw_app_meta_data, raw_user_meta_data, created_at, updated_at,
      confirmation_token, recovery_token, email_change_token_new, email_change,
      email_change_token_current, phone_change, phone_change_token, reauthentication_token
    ) values (
      '00000000-0000-0000-0000-000000000000', admin_id, 'authenticated', 'authenticated',
      admin_email, extensions.crypt('Hashdatt@2001', extensions.gen_salt('bf')), now(),
      '{"provider":"email","providers":["email"]}', '{}', now(), now(),
      '', '', '', '', '', '', '', ''
    );

    insert into auth.identities (id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at)
    values (
      gen_random_uuid(), admin_id, admin_id::text,
      jsonb_build_object('sub', admin_id::text, 'email', admin_email, 'email_verified', true),
      'email', now(), now(), now()
    );
  end if;
exception when others then
  raise notice 'Could not create the admin user automatically (%). Create it in Authentication > Users, then run this file again.', sqlerrm;
end $$;

insert into public.admins (id)
select id from auth.users where email = 'lecturer@hashclass.app'
on conflict (id) do nothing;

-- Make the API pick up the new columns and functions immediately
notify pgrst, 'reload schema';

-- ============================================================================
-- Handy checks (leave commented; copy the one you want)
-- ============================================================================
-- Is the admin account ready?  (should return one row)
-- select a.id, u.email, a.position from public.admins a join auth.users u on u.id = a.id;
