-- =====================================================================
-- Shift Rota — Supabase policies & schema
-- Run this once in the Supabase SQL Editor. It is idempotent (safe to
-- re-run) — every statement drops-then-recreates or uses IF NOT EXISTS.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. Recursion-safe admin check
--    A SECURITY DEFINER function bypasses RLS on `profiles` when it runs,
--    so admin policies can call it WITHOUT the infinite-recursion error
--    you get from `auth.uid() in (select id from profiles where ...)`.
-- ---------------------------------------------------------------------
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1 from public.profiles where id = auth.uid() and is_admin = true
  );
$$;
grant execute on function public.is_admin() to authenticated;

-- ---------------------------------------------------------------------
-- 2. Profiles — everyone (logged in) can see everyone; admins can edit any
-- ---------------------------------------------------------------------
drop policy if exists "Anyone can view profiles" on public.profiles;
create policy "Anyone can view profiles" on public.profiles
  for select to authenticated using (true);

drop policy if exists "Users can update own profile" on public.profiles;
create policy "Users can update own profile" on public.profiles
  for update using (id = auth.uid()) with check (id = auth.uid());

drop policy if exists "Admins can update any profile" on public.profiles;
create policy "Admins can update any profile" on public.profiles
  for update using (public.is_admin()) with check (public.is_admin());

-- Enforce unique usernames (case-insensitive), ignoring blanks
create unique index if not exists profiles_username_lower_key
  on public.profiles (lower(username)) where username is not null;

-- ---------------------------------------------------------------------
-- 3. Rotas — any logged-in user can view anyone's rota (People tab).
--    Writes stay restricted to the owner, plus admins can manage any rota.
-- ---------------------------------------------------------------------
drop policy if exists "Anyone can view rota_settings" on public.rota_settings;
create policy "Anyone can view rota_settings" on public.rota_settings
  for select to authenticated using (true);

drop policy if exists "Admins can manage any rota_settings" on public.rota_settings;
create policy "Admins can manage any rota_settings" on public.rota_settings
  for all using (user_id = auth.uid() or public.is_admin())
  with check (user_id = auth.uid() or public.is_admin());

drop policy if exists "Anyone can view overrides" on public.overrides;
create policy "Anyone can view overrides" on public.overrides
  for select to authenticated using (true);

drop policy if exists "Anyone can view shift_types" on public.shift_types;
create policy "Anyone can view shift_types" on public.shift_types
  for select to authenticated using (true);

-- ---------------------------------------------------------------------
-- 4. Pinned / starred users
-- ---------------------------------------------------------------------
create table if not exists public.pinned_users (
  user_id   uuid not null references auth.users(id) on delete cascade,
  pinned_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz default now(),
  primary key (user_id, pinned_id)
);
alter table public.pinned_users enable row level security;

drop policy if exists "Users manage own pins" on public.pinned_users;
create policy "Users manage own pins" on public.pinned_users
  for all using (user_id = auth.uid()) with check (user_id = auth.uid());
