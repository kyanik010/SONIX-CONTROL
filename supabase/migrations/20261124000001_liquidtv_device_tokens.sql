-- Per-device authentication token hash & issuance timestamps for SONIX-CONTROL / LiquidTV
alter table public.devices
  add column if not exists device_token_hash text,
  add column if not exists device_token_issued_at timestamptz;

create index if not exists devices_device_token_hash_idx
  on public.devices (device_token_hash)
  where device_token_hash is not null;
