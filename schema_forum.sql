-- CoocksWorld: форум и роль модератора.
-- Выполни целиком в Supabase: SQL Editor -> New query -> Run. Сначала должен быть выполнен schema.sql.
-- Скрипт можно запускать повторно, ничего не сломается.

-- 1. Роль moder ---------------------------------------------------------------

alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check
  check (role in ('user', 'moder', 'admin', 'owner'));

-- Ранги: guest (не вошёл) 0, user 1, moder 2, admin и owner 3
create or replace function public.role_rank(r text)
returns int
language sql
immutable
set search_path = ''
as $$
  select case r when 'owner' then 3 when 'admin' then 3 when 'moder' then 2 when 'user' then 1 else 0 end;
$$;

create or replace function public.my_rank()
returns int
language sql
stable
security definer
set search_path = ''
as $$
  select case
    when auth.uid() is null then 0
    else public.role_rank(coalesce((select p.role from public.profiles p where p.id = auth.uid()), 'guest'))
  end;
$$;

grant execute on function public.role_rank(text) to anon, authenticated;
grant execute on function public.my_rank() to anon, authenticated;

-- 2. Таблицы форума -----------------------------------------------------------

create table if not exists public.forum_boards (
  id          bigint generated always as identity primary key,
  title       text not null check (char_length(title) between 1 and 60),
  description text not null default '' check (char_length(description) <= 200),
  -- кто видит раздел
  read_min    text not null default 'guest' check (read_min   in ('guest', 'user', 'moder', 'admin')),
  -- кто может создавать темы
  thread_min  text not null default 'user'  check (thread_min in ('user', 'moder', 'admin')),
  -- кто может отвечать в темах
  reply_min   text not null default 'user'  check (reply_min  in ('user', 'moder', 'admin')),
  sort        int  not null default 0,
  created_at  timestamptz not null default now(),
  created_by  uuid references auth.users (id) on delete set null
);

create table if not exists public.forum_threads (
  id           bigint generated always as identity primary key,
  board_id     bigint not null references public.forum_boards (id) on delete cascade,
  title        text   not null check (char_length(title) between 3 and 120),
  author_id    uuid references auth.users (id) on delete set null,
  pinned       boolean not null default false,
  locked       boolean not null default false,
  -- кто может отвечать именно в этой теме (пусто = как в разделе)
  reply_min    text check (reply_min in ('user', 'moder', 'admin')),
  posts_count  int not null default 0,
  last_post_at timestamptz not null default now(),
  last_post_by uuid references auth.users (id) on delete set null,
  created_at   timestamptz not null default now()
);
alter table public.forum_threads add column if not exists reply_min text;
alter table public.forum_threads drop constraint if exists forum_threads_reply_min_check;
alter table public.forum_threads add constraint forum_threads_reply_min_check
  check (reply_min is null or reply_min in ('user', 'moder', 'admin'));
create index if not exists forum_threads_board_idx on public.forum_threads (board_id, pinned desc, last_post_at desc);

create table if not exists public.forum_posts (
  id         bigint generated always as identity primary key,
  thread_id  bigint not null references public.forum_threads (id) on delete cascade,
  author_id  uuid references auth.users (id) on delete set null,
  body       text not null check (char_length(body) between 1 and 5000),
  created_at timestamptz not null default now(),
  edited_at  timestamptz
);
create index if not exists forum_posts_thread_idx on public.forum_posts (thread_id, created_at);

-- 2b. Наказания: мут и бан ------------------------------------------------------

create table if not exists public.forum_sanctions (
  id         bigint generated always as identity primary key,
  user_id    uuid not null references auth.users (id) on delete cascade,
  kind       text not null check (kind in ('mute', 'ban')),
  reason     text not null default '' check (char_length(reason) <= 300),
  until_at   timestamptz,                       -- пусто = навсегда
  created_at timestamptz not null default now(),
  created_by uuid references auth.users (id) on delete set null,
  revoked_at timestamptz,
  revoked_by uuid references auth.users (id) on delete set null
);
create index if not exists forum_sanctions_user_idx on public.forum_sanctions (user_id, kind) where revoked_at is null;

-- действует ли наказание сейчас
create or replace function public.has_sanction(p_user uuid, p_kind text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.forum_sanctions s
    where s.user_id = p_user and s.kind = p_kind and s.revoked_at is null
      and (s.until_at is null or s.until_at > now())
  );
$$;

create or replace function public.am_banned() returns boolean language sql stable security definer set search_path = ''
as $$ select auth.uid() is not null and public.has_sanction(auth.uid(), 'ban'); $$;
create or replace function public.am_muted() returns boolean language sql stable security definer set search_path = ''
as $$ select auth.uid() is not null and public.has_sanction(auth.uid(), 'mute'); $$;

revoke all on function public.has_sanction(uuid, text) from public;
grant execute on function public.has_sanction(uuid, text) to anon, authenticated;
grant execute on function public.am_banned() to anon, authenticated;
grant execute on function public.am_muted() to anon, authenticated;

-- Публичная витрина профилей: ник, роль и отметки о наказаниях (без почты)
create or replace view public.forum_users as
  select p.id, p.nickname, p.role,
         public.has_sanction(p.id, 'mute') as muted,
         public.has_sanction(p.id, 'ban')  as banned
  from public.profiles p
  where not public.am_banned();
grant select on public.forum_users to anon, authenticated;

-- Мои наказания: чтобы сайт мог показать причину и срок
create or replace function public.forum_my_status()
returns table (kind text, reason text, until_at timestamptz)
language sql
stable
security definer
set search_path = ''
as $$
  select s.kind, s.reason, s.until_at
  from public.forum_sanctions s
  where s.user_id = auth.uid() and s.revoked_at is null
    and (s.until_at is null or s.until_at > now())
  order by s.until_at desc nulls first;
$$;
revoke all on function public.forum_my_status() from public, anon;
grant execute on function public.forum_my_status() to authenticated;

-- 3. Вспомогательные функции прав ---------------------------------------------

create or replace function public.can_read_board(p_board bigint)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.forum_boards b
    where b.id = p_board and not public.am_banned() and public.my_rank() >= public.role_rank(b.read_min)
  );
$$;

-- можно ли отвечать в теме: нужен ранг, и тема не закрыта (модераторы пишут и в закрытые)
create or replace function public.can_reply(p_thread bigint)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.forum_threads t
    join public.forum_boards b on b.id = t.board_id
    where t.id = p_thread
      and not public.am_banned() and not public.am_muted()
      and public.my_rank() >= public.role_rank(b.read_min)
      and public.my_rank() >= public.role_rank(b.reply_min)
      and public.my_rank() >= public.role_rank(coalesce(t.reply_min, 'user'))
      and (not t.locked or public.my_rank() >= 2)
  );
$$;

grant execute on function public.can_read_board(bigint) to anon, authenticated;
grant execute on function public.can_reply(bigint) to anon, authenticated;

-- 4. Триггеры: счётчики, антифлуд ---------------------------------------------

create or replace function public.forum_post_flood()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if public.my_rank() < 2 and exists (
    select 1 from public.forum_posts p
    where p.author_id = new.author_id and p.created_at > now() - interval '8 seconds'
  ) then
    raise exception 'Подожди несколько секунд перед следующим сообщением';
  end if;
  return new;
end;
$$;

drop trigger if exists forum_post_flood on public.forum_posts;
create trigger forum_post_flood before insert on public.forum_posts
  for each row execute function public.forum_post_flood();

create or replace function public.forum_post_count()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare tid bigint;
begin
  if tg_op = 'DELETE' then tid := old.thread_id; else tid := new.thread_id; end if;
  update public.forum_threads t set
    posts_count  = (select count(*) from public.forum_posts p where p.thread_id = tid),
    last_post_at = coalesce((select max(p.created_at) from public.forum_posts p where p.thread_id = tid), t.last_post_at),
    last_post_by = (select p.author_id from public.forum_posts p where p.thread_id = tid order by p.created_at desc, p.id desc limit 1)
  where t.id = tid;
  return null;
end;
$$;

drop trigger if exists forum_post_count on public.forum_posts;
create trigger forum_post_count after insert or delete on public.forum_posts
  for each row execute function public.forum_post_count();

-- правка своего сообщения помечается временем
create or replace function public.forum_post_edited()
returns trigger
language plpgsql
as $$
begin
  if new.body is distinct from old.body then new.edited_at := now(); end if;
  new.thread_id := old.thread_id;
  new.author_id := old.author_id;
  new.created_at := old.created_at;
  return new;
end;
$$;

drop trigger if exists forum_post_edited on public.forum_posts;
create trigger forum_post_edited before update on public.forum_posts
  for each row execute function public.forum_post_edited();

-- 5. Создание темы одним действием (тема + первое сообщение) ------------------

drop function if exists public.forum_create_thread(bigint, text, text);

create or replace function public.forum_create_thread(p_board bigint, p_title text, p_body text, p_reply_min text default null)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  b   public.forum_boards;
  tid bigint;
  r   int := public.my_rank();
begin
  if auth.uid() is null then raise exception 'Нужно войти в аккаунт'; end if;
  if public.am_banned() then raise exception 'Ты забанен на форуме'; end if;
  if public.am_muted() then raise exception 'Ты в муте и не можешь писать'; end if;
  select * into b from public.forum_boards where id = p_board;
  if not found or r < public.role_rank(b.read_min) or r < public.role_rank(b.thread_min) then
    raise exception 'Нет прав создавать темы в этом разделе';
  end if;
  p_title := btrim(coalesce(p_title, ''));
  p_body  := btrim(coalesce(p_body, ''));
  if char_length(p_title) < 3 or char_length(p_title) > 120 then raise exception 'Название темы: от 3 до 120 символов'; end if;
  if char_length(p_body) < 1 or char_length(p_body) > 5000 then raise exception 'Сообщение: от 1 до 5000 символов'; end if;
  -- ограничивать ответы в своей теме могут только модераторы и выше
  if p_reply_min is not null and p_reply_min not in ('user', 'moder', 'admin') then raise exception 'Неверное право ответа'; end if;
  if p_reply_min = 'user' then p_reply_min := null; end if;
  if p_reply_min is not null and (r < 2 or public.role_rank(p_reply_min) > r) then
    raise exception 'Нет прав ограничивать ответы';
  end if;

  insert into public.forum_threads (board_id, title, author_id, last_post_by, reply_min)
  values (p_board, p_title, auth.uid(), auth.uid(), p_reply_min)
  returning id into tid;

  insert into public.forum_posts (thread_id, author_id, body) values (tid, auth.uid(), p_body);
  return tid;
end;
$$;

revoke all on function public.forum_create_thread(bigint, text, text, text) from public, anon;
grant execute on function public.forum_create_thread(bigint, text, text, text) to authenticated;

-- 6. Права доступа ------------------------------------------------------------

alter table public.forum_boards  enable row level security;
alter table public.forum_threads enable row level security;
alter table public.forum_posts   enable row level security;

revoke all on public.forum_boards  from anon, authenticated;
revoke all on public.forum_threads from anon, authenticated;
revoke all on public.forum_posts   from anon, authenticated;

-- разделы: видят по правам, меняют только админы и владелец
grant select on public.forum_boards to anon, authenticated;
grant insert, update, delete on public.forum_boards to authenticated;

drop policy if exists "boards: read by rank" on public.forum_boards;
create policy "boards: read by rank" on public.forum_boards for select to anon, authenticated
  using (not public.am_banned() and public.my_rank() >= public.role_rank(read_min));

drop policy if exists "boards: admins create" on public.forum_boards;
create policy "boards: admins create" on public.forum_boards for insert to authenticated
  with check (public.my_rank() >= 3);

drop policy if exists "boards: admins update" on public.forum_boards;
create policy "boards: admins update" on public.forum_boards for update to authenticated
  using (public.my_rank() >= 3) with check (public.my_rank() >= 3);

drop policy if exists "boards: admins delete" on public.forum_boards;
create policy "boards: admins delete" on public.forum_boards for delete to authenticated
  using (public.my_rank() >= 3);

-- темы: читают по правам раздела; закреплять, закрывать и удалять могут модераторы и выше
grant select on public.forum_threads to anon, authenticated;
grant update (pinned, locked, reply_min) on public.forum_threads to authenticated;
grant delete on public.forum_threads to authenticated;

drop policy if exists "threads: read by board" on public.forum_threads;
create policy "threads: read by board" on public.forum_threads for select to anon, authenticated
  using (public.can_read_board(board_id));

drop policy if exists "threads: moderators update" on public.forum_threads;
create policy "threads: moderators update" on public.forum_threads for update to authenticated
  using (public.my_rank() >= 2) with check (public.my_rank() >= 2);

drop policy if exists "threads: moderators delete" on public.forum_threads;
create policy "threads: moderators delete" on public.forum_threads for delete to authenticated
  using (public.my_rank() >= 2);

-- сообщения
grant select on public.forum_posts to anon, authenticated;
grant insert (thread_id, author_id, body) on public.forum_posts to authenticated;
grant update (body) on public.forum_posts to authenticated;
grant delete on public.forum_posts to authenticated;

drop policy if exists "posts: read by board" on public.forum_posts;
create policy "posts: read by board" on public.forum_posts for select to anon, authenticated
  using (exists (select 1 from public.forum_threads t where t.id = thread_id));

drop policy if exists "posts: write by rank" on public.forum_posts;
create policy "posts: write by rank" on public.forum_posts for insert to authenticated
  with check (author_id = auth.uid() and public.can_reply(thread_id));

drop policy if exists "posts: edit own" on public.forum_posts;
create policy "posts: edit own" on public.forum_posts for update to authenticated
  using (author_id = auth.uid() and public.can_reply(thread_id))
  with check (author_id = auth.uid());

drop policy if exists "posts: delete own or moderator" on public.forum_posts;
create policy "posts: delete own or moderator" on public.forum_posts for delete to authenticated
  using (author_id = auth.uid() or public.my_rank() >= 2);

-- 7. Стартовые разделы (только если форум пуст) --------------------------------

insert into public.forum_boards (title, description, read_min, thread_min, reply_min, sort)
select * from (values
  ('Новости и объявления', 'Важные новости проекта. Темы создают админы, отвечать могут все.', 'guest', 'admin', 'user', 10),
  ('Общение',              'Болтовня обо всём, что связано с сервером и игрой.',              'guest', 'user',  'user', 20),
  ('Вопросы и помощь',     'Не получается зайти или что-то непонятно? Спрашивай здесь.',      'guest', 'user',  'user', 30),
  ('Для администрации',    'Закрытый раздел для модераторов и админов.',                      'moder', 'moder', 'moder', 90)
) as v(title, description, read_min, thread_min, reply_min, sort)
where not exists (select 1 from public.forum_boards);

-- 8. Роли: владелец назначает кого угодно, админ - только user <-> moder -------

drop policy if exists "profiles: owner changes roles" on public.profiles;
drop policy if exists "profiles: roles by rank" on public.profiles;
create policy "profiles: roles by rank"
  on public.profiles for update to authenticated
  using (
    public.my_role() = 'owner'
    or (public.my_role() = 'admin' and role in ('user', 'moder'))
  )
  with check (
    public.my_role() = 'owner'
    or (public.my_role() = 'admin' and role in ('user', 'moder'))
  );

-- 9. Выдача и снятие наказаний ---------------------------------------------------
-- Мут: модераторы и выше, только тем, чья роль ниже. Бан: админы и выше; админов банит только владелец.

alter table public.forum_sanctions enable row level security;
revoke all on public.forum_sanctions from anon, authenticated;
grant select on public.forum_sanctions to authenticated;

drop policy if exists "sanctions: staff reads" on public.forum_sanctions;
create policy "sanctions: staff reads" on public.forum_sanctions for select to authenticated
  using (public.my_rank() >= 2);

create or replace function public.forum_sanction(p_user uuid, p_kind text, p_minutes int, p_reason text)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  r    int := public.my_rank();
  trole text;
  new_id bigint;
begin
  if p_kind not in ('mute', 'ban') then raise exception 'Неизвестный тип наказания'; end if;
  if p_kind = 'mute' and r < 2 then raise exception 'Мутить могут модераторы и выше'; end if;
  if p_kind = 'ban'  and r < 3 then raise exception 'Банить могут админы и выше'; end if;
  if p_user = auth.uid() then raise exception 'Нельзя наказать самого себя'; end if;
  select role into trole from public.profiles where id = p_user;
  if trole is null then raise exception 'Пользователь не найден'; end if;
  if trole = 'owner' then raise exception 'Владельца наказать нельзя'; end if;
  if public.role_rank(trole) >= r and not (public.my_role() = 'owner') then
    raise exception 'Нельзя наказать пользователя с такой же или более высокой ролью';
  end if;
  if p_minutes is not null and (p_minutes < 1 or p_minutes > 525600) then raise exception 'Срок: от 1 минуты до года'; end if;
  p_reason := left(btrim(coalesce(p_reason, '')), 300);

  update public.forum_sanctions set revoked_at = now(), revoked_by = auth.uid()
  where user_id = p_user and kind = p_kind and revoked_at is null;

  insert into public.forum_sanctions (user_id, kind, reason, until_at, created_by)
  values (p_user, p_kind, p_reason, case when p_minutes is null then null else now() + make_interval(mins => p_minutes) end, auth.uid())
  returning id into new_id;
  return new_id;
end;
$$;

create or replace function public.forum_unsanction(p_user uuid, p_kind text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare r int := public.my_rank();
begin
  if p_kind = 'mute' and r < 2 then raise exception 'Размутить могут модераторы и выше'; end if;
  if p_kind = 'ban'  and r < 3 then raise exception 'Разбанить могут админы и выше'; end if;
  if p_kind not in ('mute', 'ban') then raise exception 'Неизвестный тип наказания'; end if;
  update public.forum_sanctions set revoked_at = now(), revoked_by = auth.uid()
  where user_id = p_user and kind = p_kind and revoked_at is null;
end;
$$;

revoke all on function public.forum_sanction(uuid, text, int, text) from public, anon;
revoke all on function public.forum_unsanction(uuid, text) from public, anon;
grant execute on function public.forum_sanction(uuid, text, int, text) to authenticated;
grant execute on function public.forum_unsanction(uuid, text) to authenticated;
