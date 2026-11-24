create table public.todos (id bigint primary key, user_id uuid not null default auth.uid(), title text);
alter table public.todos enable row level security;
create policy "own todos" on public.todos for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
create view public.my_todos with (security_invoker = true) as select * from public.todos;
create or replace function public.count_todos() returns int language sql security definer set search_path = '' as $$ select count(*)::int from public.todos; $$;
