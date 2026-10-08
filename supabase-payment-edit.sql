-- Lets a signed-in student change ONLY their own payment number and payment name.
-- Run once in Supabase: SQL Editor > New query > paste > Run.
create or replace function public.update_my_payment(p_payment_number text, p_payment_name text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null then
    raise exception 'not_signed_in';
  end if;
  if p_payment_number !~ '^\+255[67][0-9]{8}$' then
    raise exception 'invalid_payment_number';
  end if;
  if p_payment_name !~ '^[A-Z]+( [A-Z]+)*$' or length(p_payment_name) < 2 then
    raise exception 'invalid_payment_name';
  end if;
  update public.students
     set payment_number = p_payment_number,
         payment_name   = p_payment_name
   where id = auth.uid();
end;
$$;

revoke all on function public.update_my_payment(text, text) from public, anon;
grant execute on function public.update_my_payment(text, text) to authenticated;
