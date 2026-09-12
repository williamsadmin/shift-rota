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

-- Which 3 tabs a user has chosen for the top bar (the rest live in the ☰ menu).
-- Covered by the existing "Users can update own profile" policy.
alter table public.profiles add column if not exists top_tabs text[];

-- What kind of account this is — changes some terminology and hides fields
-- that don't apply (e.g. duty board / GB Hours compliance / pay are bus-driver
-- only). Covered by the existing "Users can update own profile" policy.
alter table public.profiles add column if not exists account_type text not null default 'bus';
alter table public.profiles drop constraint if exists profiles_account_type_check;
alter table public.profiles add constraint profiles_account_type_check check (account_type in ('bus','education'));

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
-- 6. Shift ratings (personal — one shift rating per user per day)
-- ---------------------------------------------------------------------
create table if not exists public.shift_ratings (
  user_id      uuid not null references auth.users(id) on delete cascade,
  rating_date  date not null,
  shift_name   text not null,
  shift_rating smallint not null check (shift_rating between 1 and 5),
  created_at   timestamptz default now(),
  primary key (user_id, rating_date)
);
-- Drop the old combined bus columns if this table was created by an earlier
-- version of this script (bus ratings now live in their own table, below).
alter table public.shift_ratings drop column if exists bus_number;
alter table public.shift_ratings drop column if exists bus_rating;
alter table public.shift_ratings enable row level security;

drop policy if exists "Users manage own ratings" on public.shift_ratings;
create policy "Users manage own ratings" on public.shift_ratings
  for all using (user_id = auth.uid()) with check (user_id = auth.uid());

-- ---------------------------------------------------------------------
-- 7. Bus ratings (personal — independent of shift ratings; a user can log
--    more than one bus on the same day, one rating per bus per day)
-- ---------------------------------------------------------------------
create table if not exists public.bus_ratings (
  user_id     uuid not null references auth.users(id) on delete cascade,
  rating_date date not null,
  bus_number  text not null,
  bus_rating  smallint not null check (bus_rating between 1 and 5),
  created_at  timestamptz default now(),
  primary key (user_id, rating_date, bus_number)
);
alter table public.bus_ratings enable row level security;

drop policy if exists "Users manage own bus ratings" on public.bus_ratings;
create policy "Users manage own bus ratings" on public.bus_ratings
  for all using (user_id = auth.uid()) with check (user_id = auth.uid());

-- ---------------------------------------------------------------------
-- 8. Calendar shares — the .ics live-link token. Only the owner and admins
--    may see or create it (unlike overrides, this must NOT be world-readable
--    or anyone could pull anyone else's live calendar feed).
-- ---------------------------------------------------------------------
alter table public.calendar_shares enable row level security;

drop policy if exists "Anyone can view calendar_shares" on public.calendar_shares;
drop policy if exists "Users manage own calendar share" on public.calendar_shares;
drop policy if exists "Admins can manage any calendar share" on public.calendar_shares;
create policy "Admins can manage any calendar share" on public.calendar_shares
  for all using (user_id = auth.uid() or public.is_admin())
  with check (user_id = auth.uid() or public.is_admin());

-- ---------------------------------------------------------------------
-- 9. Blocks — shift templates are grouped by their existing `category`
--    field (e.g. "Matlock Sixes", "Red Arrow"), and each category is only
--    visible to the companies listed for it here. A category with no rows
--    here is hidden from everyone except admins (deliberate — an admin must
--    explicitly grant a company before its drivers see that block). Rota
--    templates can't reuse `category` (it's already the '__rota__' marker
--    that tells them apart from shift templates), so they get their own
--    `restricted_companies` array column instead, same "empty = hidden" rule.
--    Admins always see everything regardless of this table, everywhere.
-- ---------------------------------------------------------------------
create table if not exists public.category_companies (
  category text not null,
  company  text not null,
  primary key (category, company)
);
alter table public.category_companies enable row level security;

drop policy if exists "Anyone can view category_companies" on public.category_companies;
create policy "Anyone can view category_companies" on public.category_companies
  for select to authenticated using (true);

drop policy if exists "Admins can manage category_companies" on public.category_companies;
create policy "Admins can manage category_companies" on public.category_companies
  for all using (public.is_admin()) with check (public.is_admin());

alter table public.shift_types add column if not exists restricted_companies text[];

-- A user's self-declared extra blocks ("I also know the Two route") — starts
-- 'pending' until an admin approves it; only then does it grant access
-- alongside whatever their own company already grants by default.
create table if not exists public.user_block_access (
  user_id      uuid not null references auth.users(id) on delete cascade,
  category     text not null,
  status       text not null default 'pending' check (status in ('pending','approved')),
  requested_at timestamptz default now(),
  decided_at   timestamptz,
  primary key (user_id, category)
);
alter table public.user_block_access enable row level security;

drop policy if exists "Users manage own block requests" on public.user_block_access;
create policy "Users manage own block requests" on public.user_block_access
  for all using (user_id = auth.uid() or public.is_admin())
  with check (user_id = auth.uid() or public.is_admin());
