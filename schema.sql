-- CoocksWorld: база для админки. Выполни целиком в Supabase: SQL Editor -> New query -> Run.
-- Скрипт можно запускать повторно, ничего не сломается.

-- 1. Таблицы -----------------------------------------------------------------

create table if not exists public.profiles (
  id         uuid primary key references auth.users (id) on delete cascade,
  nickname   text not null default '',
  email      text,
  role       text not null default 'user' check (role in ('user', 'admin', 'owner')),
  created_at timestamptz not null default now()
);

create table if not exists public.server_status (
  id         int primary key default 1 check (id = 1),
  status     text not null default 'rework' check (status in ('online', 'rework', 'maintenance')),
  message    text not null default '' check (char_length(message) <= 300),
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users (id) on delete set null
);

insert into public.server_status (id, status, message)
values (1, 'rework', '')
on conflict (id) do nothing;

-- 2. Автоматический профиль при регистрации ----------------------------------

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email, nickname)
  values (
    new.id,
    new.email,
    left(coalesce(new.raw_user_meta_data ->> 'nickname', ''), 24)
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- профили для тех, кто уже успел зарегистрироваться
insert into public.profiles (id, email, nickname)
select u.id, u.email, left(coalesce(u.raw_user_meta_data ->> 'nickname', ''), 24)
from auth.users u
on conflict (id) do nothing;

-- 3. Роль текущего пользователя (нужна правилам доступа) ---------------------

create or replace function public.my_role()
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce((select p.role from public.profiles p where p.id = auth.uid()), 'none');
$$;

revoke all on function public.my_role() from public, anon;
grant execute on function public.my_role() to authenticated;

-- 4. Права доступа -----------------------------------------------------------

alter table public.profiles      enable row level security;
alter table public.server_status enable row level security;

revoke all on public.profiles      from anon, authenticated;
revoke all on public.server_status from anon, authenticated;

-- профили: читать может сам пользователь и администрация; менять только роль, и только владелец
grant select on public.profiles to authenticated;
grant update (role) on public.profiles to authenticated;

drop policy if exists "profiles: read own or staff" on public.profiles;
create policy "profiles: read own or staff"
  on public.profiles for select to authenticated
  using (id = auth.uid() or public.my_role() in ('admin', 'owner'));

drop policy if exists "profiles: owner changes roles" on public.profiles;
create policy "profiles: owner changes roles"
  on public.profiles for update to authenticated
  using (public.my_role() = 'owner')
  with check (public.my_role() = 'owner');

-- статус: читают все (в том числе посетители сайта), меняют админы и владелец
grant select on public.server_status to anon, authenticated;
grant update (status, message, updated_at, updated_by) on public.server_status to authenticated;

drop policy if exists "status: everyone reads" on public.server_status;
create policy "status: everyone reads"
  on public.server_status for select to anon, authenticated
  using (true);

drop policy if exists "status: staff updates" on public.server_status;
create policy "status: staff updates"
  on public.server_status for update to authenticated
  using (public.my_role() in ('admin', 'owner'))
  with check (public.my_role() in ('admin', 'owner'));

-- 5. Первый владелец ---------------------------------------------------------
-- Выполни ОТДЕЛЬНО, после того как зарегистрируешься на странице admin.html.
-- Замени почту на ту, с которой регистрировался, и убери "--" в начале строки:
--
-- update public.profiles set role = 'owner' where lower(email) = lower('ТВОЯ_ПОЧТА@example.com');
