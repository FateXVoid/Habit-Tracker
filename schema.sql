-- Supabase schema for the Habit Tracker license/key system.
-- Run this in Supabase SQL Editor once before deploying.

create extension if not exists pgcrypto;

create table if not exists public.license_keys (
  id uuid primary key default gen_random_uuid(),
  license_key text not null unique,
  role text not null default 'user' check (role in ('user','developer')),
  is_revoked boolean not null default false,
  created_at timestamptz not null default now(),
  last_login_at timestamptz
);

create table if not exists public.license_devices (
  id uuid primary key default gen_random_uuid(),
  license_id uuid not null references public.license_keys(id) on delete cascade,
  device_id text not null,
  created_at timestamptz not null default now(),
  unique (license_id, device_id)
);

create table if not exists public.license_sessions (
  id uuid primary key default gen_random_uuid(),
  token text not null unique,
  license_id uuid not null references public.license_keys(id) on delete cascade,
  device_id text not null,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

create index if not exists license_devices_license_idx on public.license_devices(license_id);
create index if not exists license_sessions_license_idx on public.license_sessions(license_id);
create index if not exists license_sessions_token_idx on public.license_sessions(token);

alter table public.license_keys enable row level security;
alter table public.license_devices enable row level security;
alter table public.license_sessions enable row level security;

revoke all on table public.license_keys from anon, authenticated;
revoke all on table public.license_devices from anon, authenticated;
revoke all on table public.license_sessions from anon, authenticated;

-- Atomically claim a device. A user key can claim only one device.
-- A developer key can claim the same or additional devices.
create or replace function public.claim_license_device(p_license_id uuid, p_device_id text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  k record;
  cnt integer;
  same_device boolean;
begin
  select id, role, is_revoked into k
  from public.license_keys
  where id = p_license_id
  for update;

  if not found then
    return jsonb_build_object('ok',false,'code','not_found');
  end if;

  if k.is_revoked then
    return jsonb_build_object('ok',false,'code','revoked');
  end if;

  select count(*), exists(
    select 1 from public.license_devices d
    where d.license_id=p_license_id and d.device_id=p_device_id
  )
  into cnt, same_device
  from public.license_devices d
  where d.license_id=p_license_id;

  if k.role='developer' then
    if not same_device then
      insert into public.license_devices(license_id,device_id)
      values(p_license_id,p_device_id)
      on conflict (license_id,device_id) do nothing;
    end if;
    return jsonb_build_object('ok',true,'device_count',cnt + case when same_device then 0 else 1 end);
  end if;

  if same_device then
    return jsonb_build_object('ok',true,'device_count',1);
  end if;

  if cnt>0 then
    return jsonb_build_object('ok',false,'code','device_bound');
  end if;

  insert into public.license_devices(license_id,device_id)
  values(p_license_id,p_device_id);

  return jsonb_build_object('ok',true,'device_count',1);
end;
$$;

revoke all on function public.claim_license_device(uuid,text) from anon, authenticated;

-- Optional cleanup job can delete expired sessions:
-- delete from public.license_sessions where expires_at < now();
