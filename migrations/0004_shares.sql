-- Public share tokens for a finished brief (guest or signed-in).
create table if not exists shares (
  token        text primary key,
  scan_id      text,
  target       text not null,
  report_json  text not null,
  created_at   timestamptz not null default now()
);

create index if not exists shares_created_idx on shares (created_at desc);
