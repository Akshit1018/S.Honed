-- Per-finding work status on a saved brief.
create table if not exists finding_status (
  user_id    text not null,
  scan_id    text not null,
  finding_id text not null,
  status     text not null default 'open',
  updated_at timestamptz not null default now(),
  primary key (user_id, scan_id, finding_id)
);

create index if not exists finding_status_scan_idx
  on finding_status (user_id, scan_id);
