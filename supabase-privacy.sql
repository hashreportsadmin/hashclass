-- HashCLASS: every student sees ONLY their own data.
-- Run once in Supabase > SQL Editor. Safe to run again.
--
-- These are RESTRICTIVE policies. They are combined (AND) with the policies you already have,
-- so they can only narrow what a signed-in student can read. They never widen access and they
-- do not touch inserts, updates or deletes. The lecturer (is_admin()) keeps full read access.
-- Needs the is_admin() function from supabase-admin.sql.

alter table public.students      enable row level security;
alter table public.registrations enable row level security;
alter table public.attendance    enable row level security;
alter table public.class_links   enable row level security;

-- A student can read only their own profile row
drop policy if exists hc_students_own_read on public.students;
create policy hc_students_own_read on public.students
  as restrictive for select to authenticated
  using (id = auth.uid() or public.is_admin());

-- A student can read only their own course registrations and payment status
drop policy if exists hc_registrations_own_read on public.registrations;
create policy hc_registrations_own_read on public.registrations
  as restrictive for select to authenticated
  using (student_id = auth.uid() or public.is_admin());

-- A student can read only their own attendance history
drop policy if exists hc_attendance_own_read on public.attendance;
create policy hc_attendance_own_read on public.attendance
  as restrictive for select to authenticated
  using (student_id = auth.uid() or public.is_admin());

-- A class link is readable only while the class is live AND the student has PAID for that course
drop policy if exists hc_links_paid_only on public.class_links;
create policy hc_links_paid_only on public.class_links
  as restrictive for select to authenticated
  using (
    public.is_admin()
    or exists (
      select 1
      from public.class_sessions s
      join public.registrations r on r.course_code = s.course_code
      where s.id = class_links.session_id
        and s.status = 'live'
        and r.student_id = auth.uid()
        and r.payment_status = 'paid'
    )
  );
