-- expected: profiles ok (RLS + policy); orders missing RLS; messages RLS without policy; notes missing RLS
create table public.profiles (id uuid primary key, name text);
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles for select using (auth.uid() = id);

create table if not exists public.orders (id bigint primary key, total numeric);

create table "public"."messages" (id bigint primary key, body text);
alter table only "public"."messages" enable row level security;

-- create table notes_in_a_comment (id int);
create table notes (id bigint primary key, body text);
