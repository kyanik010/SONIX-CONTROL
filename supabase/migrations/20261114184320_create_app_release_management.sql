create table if not exists public.app_releases (
  id uuid primary key default gen_random_uuid(),
  channel text not null default 'stable'
    check (channel in ('stable','beta')),
  version_name text not null
    check (length(btrim(version_name)) between 1 and 40),
  version_code integer not null check (version_code > 0),
  apk_url text not null check (apk_url ~ '^https://'),
  release_url text not null check (release_url ~ '^https://'),
  sha256 text not null check (sha256 ~ '^[0-9a-fA-F]{64}$'),
  apk_size_bytes bigint check (apk_size_bytes is null or apk_size_bytes > 0),
  release_notes text not null default '' check (length(release_notes) <= 12000),
  update_policy text not null default 'optional'
    check (update_policy in ('optional','mandatory')),
  target_platform text not null default 'all'
    check (target_platform in ('all','android','android_tv')),
  target_abis text[] not null default array['all']::text[]
    check (
      cardinality(target_abis) > 0
      and target_abis <@ array['all','armeabi-v7a','arm64-v8a','x86','x86_64']::text[]
      and (not ('all' = any(target_abis)) or cardinality(target_abis) = 1)
    ),
  min_supported_version_code integer not null default 0
    check (min_supported_version_code >= 0),
  status text not null default 'draft'
    check (status in ('draft','published','disabled')),
  published_at timestamptz,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint app_releases_channel_version_code_key unique (channel, version_code),
  constraint app_releases_published_at_check
    check (status <> 'published' or published_at is not null)
);

create table if not exists public.app_release_targets (
  release_id uuid not null references public.app_releases(id) on delete cascade,
  device_id uuid not null references public.devices(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (release_id, device_id)
);

create index if not exists app_releases_lookup_idx
  on public.app_releases (channel, status, version_code desc);
create index if not exists app_releases_platform_status_idx
  on public.app_releases (target_platform, status);
create index if not exists app_release_targets_device_idx
  on public.app_release_targets (device_id, release_id);

alter table public.app_releases enable row level security;
alter table public.app_release_targets enable row level security;

revoke all on table public.app_releases from anon, authenticated;
revoke all on table public.app_release_targets from anon, authenticated;
grant all on table public.app_releases to service_role;
grant all on table public.app_release_targets to service_role;

comment on table public.app_releases is
  'SONIX Android application releases. Access only through authenticated admin/device Edge Functions using service_role.';
comment on table public.app_release_targets is
  'Optional per-device targeting for SONIX application releases; managed only by Edge Functions.';
