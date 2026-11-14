alter table public.devices
  add column if not exists app_version_code integer
    check (app_version_code is null or app_version_code > 0),
  add column if not exists app_abi text
    check (app_abi is null or app_abi in ('armeabi-v7a','arm64-v8a','x86','x86_64','unknown'));

create index if not exists devices_app_version_code_idx
  on public.devices (app_version_code);
