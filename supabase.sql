-- ============================================================================
-- HashCLASS: Supabase schema
-- Run the whole file once in: Supabase Dashboard > SQL Editor > New query > Run.
-- It is safe to run again; existing tables and rows are kept.
-- ============================================================================

-- 1. Courses (prices live here so the browser can never change what a course costs)
create table if not exists public.courses (
  code      text primary key,
  price_tzs integer not null check (price_tzs >= 0)
);

insert into public.courses (code, price_tzs) values
  ('AF211', 10000),
  ('AF212', 10000),
  ('AF227', 10000)
on conflict (code) do update set price_tzs = excluded.price_tzs;

-- 2. Students (one row per signed-up user, linked to Supabase Auth)
create table if not exists public.students (
  id             uuid primary key references auth.users (id) on delete cascade,
  full_name      text        not null check (full_name ~ '^[A-Z]+( [A-Z]+)+$'),
  reg_number     text        not null unique check (reg_number ~ '^T[0-9]{2}-[0-9]{2}-[0-9]{5}$'),
  year_of_study  smallint    not null check (year_of_study = 2),
  payment_number text        not null check (payment_number ~ '^\+255[67][0-9]{8}$'),
  payment_name   text        not null check (payment_name ~ '^[A-Z]+( [A-Z]+)*$'),
  created_at     timestamptz not null default now()
);

-- 3. Courses a student registered for
create table if not exists public.registrations (
  id             bigint generated always as identity primary key,
  student_id     uuid        not null references public.students (id) on delete cascade,
  course_code    text        not null references public.courses (code),
  price_tzs      integer     not null,
  payment_status text        not null default 'pending' check (payment_status in ('pending', 'paid')),
  created_at     timestamptz not null default now(),
  unique (student_id, course_code)
);

-- 4. Class sessions (created by you or a lecturer, see the examples at the bottom)
create table if not exists public.class_sessions (
  id          uuid primary key default gen_random_uuid(),
  course_code text        not null references public.courses (code),
  title       text,
  status      text        not null default 'scheduled' check (status in ('scheduled', 'live', 'ended')),
  starts_at   timestamptz not null default now(),
  ends_at     timestamptz,
  meeting_url text,
  created_at  timestamptz not null default now()
);

-- 5. Attendance (one row each time a student joins a live class)
create table if not exists public.attendance (
  id         bigint generated always as identity primary key,
  session_id uuid        not null references public.class_sessions (id) on delete cascade,
  student_id uuid        not null references public.students (id) on delete cascade,
  joined_at  timestamptz not null default now(),
  unique (session_id, student_id)
);

create index if not exists attendance_student_idx on public.attendance (student_id, joined_at desc);
create index if not exists registrations_student_idx on public.registrations (student_id);

-- ============================================================================
-- Row Level Security: students can only ever see and write their own data
-- ============================================================================
alter table public.courses        enable row level security;
alter table public.students       enable row level security;
alter table public.registrations  enable row level security;
alter table public.class_sessions enable row level security;
alter table public.attendance     enable row level security;

drop policy if exists "courses are public"            on public.courses;
drop policy if exists "student reads own profile"     on public.students;
drop policy if exists "student reads own courses"     on public.registrations;
drop policy if exists "student reads own class sessions" on public.class_sessions;
drop policy if exists "student reads own attendance"  on public.attendance;
drop policy if exists "student joins live class"      on public.attendance;

create policy "courses are public"
  on public.courses for select
  to anon, authenticated
  using (true);

create policy "student reads own profile"
  on public.students for select
  to authenticated
  using (id = auth.uid());

create policy "student reads own courses"
  on public.registrations for select
  to authenticated
  using (student_id = auth.uid());

-- A student sees only sessions for courses they registered for
create policy "student reads own class sessions"
  on public.class_sessions for select
  to authenticated
  using (
    exists (
      select 1 from public.registrations r
      where r.student_id = auth.uid()
        and r.course_code = class_sessions.course_code
    )
  );

create policy "student reads own attendance"
  on public.attendance for select
  to authenticated
  using (student_id = auth.uid());

-- A student can mark themselves present, only in a live session of a course they registered for
create policy "student joins live class"
  on public.attendance for insert
  to authenticated
  with check (
    student_id = auth.uid()
    and exists (
      select 1
      from public.class_sessions s
      join public.registrations r
        on r.course_code = s.course_code and r.student_id = auth.uid()
      where s.id = attendance.session_id
        and s.status = 'live'
    )
  );

grant select on public.courses to anon, authenticated;
grant select on public.students, public.registrations, public.class_sessions to authenticated;
grant select, insert on public.attendance to authenticated;

-- ============================================================================
-- Registration: one call that saves the student and their courses together.
-- Prices come from the courses table, never from the browser.
-- ============================================================================
create or replace function public.complete_registration(
  p_full_name      text,
  p_reg_number     text,
  p_year_of_study  smallint,
  p_payment_number text,
  p_payment_name   text,
  p_courses        text[]
) returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  uid        uuid := auth.uid();
  auth_email text;
  inserted   integer;
begin
  if uid is null then
    raise exception 'not_authenticated';
  end if;

  if exists (select 1 from public.students where id = uid) then
    raise exception 'already_registered';
  end if;

  -- The account's sign-in identity must match the registration number being saved
  select email into auth_email from auth.users where id = uid;
  if lower(split_part(auth_email, '@', 1)) <> lower(p_reg_number) then
    raise exception 'reg_number_mismatch';
  end if;

  if p_courses is null or cardinality(p_courses) = 0 then
    raise exception 'no_courses';
  end if;

  insert into public.students
    (id, full_name, reg_number, year_of_study, payment_number, payment_name)
  values
    (uid, p_full_name, p_reg_number, p_year_of_study, p_payment_number, p_payment_name);

  insert into public.registrations (student_id, course_code, price_tzs)
  select uid, c.code, c.price_tzs
  from public.courses c
  where c.code = any (p_courses);

  get diagnostics inserted = row_count;
  if inserted = 0 then
    raise exception 'no_courses';
  end if;
end;
$$;

revoke all on function public.complete_registration(text, text, smallint, text, text, text[]) from public, anon;
grant execute on function public.complete_registration(text, text, smallint, text, text, text[]) to authenticated;

-- ============================================================================
-- Real time: the dashboard listens to these tables
-- ============================================================================
do $$
begin
  if not exists (select 1 from pg_publication_tables
                 where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'attendance') then
    alter publication supabase_realtime add table public.attendance;
  end if;
  if not exists (select 1 from pg_publication_tables
                 where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'class_sessions') then
    alter publication supabase_realtime add table public.class_sessions;
  end if;
  if not exists (select 1 from pg_publication_tables
                 where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'registrations') then
    alter publication supabase_realtime add table public.registrations;
  end if;
end $$;

-- ============================================================================
-- Day-to-day admin queries (run these yourself in the SQL editor when needed).
-- Leave them commented out; copy the one you want.
-- ============================================================================

-- Start a live class (students registered for AF211 see it instantly):
-- insert into public.class_sessions (course_code, title, status, meeting_url)
-- values ('AF211', 'Revision class', 'live', 'https://meet.google.com/your-link');

-- End a live class:
-- update public.class_sessions set status = 'ended', ends_at = now()
-- where course_code = 'AF211' and status = 'live';

-- Mark a student's course as paid:
-- update public.registrations set payment_status = 'paid'
-- where student_id = (select id from public.students where reg_number = 'T23-04-01234');

-- Who attended a session:
-- select s.reg_number, s.full_name, a.joined_at
-- from public.attendance a join public.students s on s.id = a.student_id
-- where a.session_id = '<session id>' order by a.joined_at;
