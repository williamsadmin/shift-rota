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

-- Company / location grouping. `pending_*` hold a user's join request until an
-- admin approves it (moving it into company/location). Users update their own
-- pending fields; admins (via the existing update-any policy) approve/edit.
alter table public.profiles add column if not exists company text;
alter table public.profiles add column if not exists location text;
alter table public.profiles add column if not exists pending_company text;
alter table public.profiles add column if not exists pending_location text;

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

-- Scheduled future rota versions (each { effective_from, rota_start, weeks,
-- week_start_day, pattern }). Only needed for the "scheduled rota changes" feature.
alter table public.rota_settings add column if not exists schedule jsonb;

drop policy if exists "Anyone can view overrides" on public.overrides;
create policy "Anyone can view overrides" on public.overrides
  for select to authenticated using (true);

-- Admins can edit any user's calendar (day overrides).
drop policy if exists "Admins can manage any overrides" on public.overrides;
create policy "Admins can manage any overrides" on public.overrides
  for all using (user_id = auth.uid() or public.is_admin())
  with check (user_id = auth.uid() or public.is_admin());

-- Tracks whether the user has told their workplace about a requested overtime
-- day, so the "tell your workplace" reminder can be dismissed once done.
alter table public.overrides add column if not exists notified_workplace boolean default false;

drop policy if exists "Anyone can view shift_types" on public.shift_types;
create policy "Anyone can view shift_types" on public.shift_types
  for select to authenticated using (true);

-- Admins can create/edit shift types for any user (used by the admin rota editor
-- when adding a template shift to someone who doesn't have it yet).
drop policy if exists "Admins can manage any shift_types" on public.shift_types;
create policy "Admins can manage any shift_types" on public.shift_types
  for all using (owner_id = auth.uid() or public.is_admin())
  with check (owner_id = auth.uid() or public.is_admin());

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

-- ---------------------------------------------------------------------
-- 5. Overtime requests (dates a user has flagged to request overtime)
-- ---------------------------------------------------------------------
create table if not exists public.overtime_requests (
  user_id      uuid not null references auth.users(id) on delete cascade,
  request_date date not null,
  created_at   timestamptz default now(),
  primary key (user_id, request_date)
);
alter table public.overtime_requests enable row level security;

drop policy if exists "Users manage own overtime" on public.overtime_requests;
create policy "Users manage own overtime" on public.overtime_requests
  for all using (user_id = auth.uid()) with check (user_id = auth.uid());

-- ---------------------------------------------------------------------
-- 6. Shift & bus ratings (personal — one rating per user per day)
-- ---------------------------------------------------------------------
create table if not exists public.shift_ratings (
  user_id      uuid not null references auth.users(id) on delete cascade,
  rating_date  date not null,
  shift_name   text not null,
  shift_rating smallint not null check (shift_rating between 1 and 5),
  bus_number   text,
  bus_rating   smallint check (bus_rating between 1 and 5),
  created_at   timestamptz default now(),
  primary key (user_id, rating_date)
);
alter table public.shift_ratings enable row level security;

drop policy if exists "Users manage own ratings" on public.shift_ratings;
create policy "Users manage own ratings" on public.shift_ratings
  for all using (user_id = auth.uid()) with check (user_id = auth.uid());
