-- Invented demo schema (typical AI-built app mistakes)
create table public.profiles (id uuid primary key references auth.users, full_name text);
create table public.invoices (id bigint generated always as identity primary key, user_id uuid, amount numeric);
create table if not exists "public"."notes" (id bigint primary key, owner uuid, body text);
create table public.audit_log (id bigint primary key, msg text);
alter table public.profiles enable row level security;
alter table public.notes enable row level security;
alter table public.audit_log enable row level security;
create policy "Anyone can do anything" on public.notes for all using (true) with check (true);
create policy "logged in can read profiles" on public.profiles for select using (auth.role() = 'authenticated');
create view public.invoice_totals as select user_id, sum(amount) from public.invoices group by user_id;
create or replace function public.make_admin(uid uuid) returns void language plpgsql security definer as $$
begin
  update public.profiles set full_name = 'admin' where id = uid;
end;
$$;
