-- Honed briefs: one row per user-submitted site, repo, or software note.
create table if not exists scans (
  id           text primary key,
  user_id      text not null,
  target       text not null,
  target_type  text not null,
  mode         text not null default 'standard',
  status       text not null default 'queued',
  score        integer,
  grade        text,
  summary      text,
  report_json  text not null default '{}',
  error        text,
  created_at   timestamptz not null default now(),
  completed_at timestamptz
);

create index if not exists scans_user_created_idx
  on scans (user_id, created_at desc);
