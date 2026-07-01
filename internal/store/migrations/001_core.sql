create table if not exists agents (
  agent_id text primary key,
  name text not null,
  registered_at text not null
);

create table if not exists channels (
  id integer primary key autoincrement,
  name text not null unique,
  created_at text not null
);

create table if not exists threads (
  id text primary key,
  subject text not null,
  channel_name text,
  created_by text not null,
  created_at text not null,
  status text not null default 'open' check(status in ('open','closed')),
  foreign key(channel_name) references channels(name),
  foreign key(created_by) references agents(agent_id)
);

create table if not exists messages (
  id text primary key,
  kind text not null check(kind in ('dm','channel')),
  from_agent text not null,
  to_agent text,
  channel_name text,
  body text not null,
  created_at text not null,
  thread_id text,
  check(
    (kind = 'dm' and to_agent is not null and channel_name is null) or
    (kind = 'channel' and to_agent is null and channel_name is not null)
  ),
  foreign key(from_agent) references agents(agent_id),
  foreign key(to_agent) references agents(agent_id),
  foreign key(channel_name) references channels(name),
  foreign key(thread_id) references threads(id)
);

create table if not exists inbox (
  id text primary key,
  agent_id text not null,
  message_id text not null,
  from_agent text not null,
  body text not null,
  created_at text not null,
  foreign key(agent_id) references agents(agent_id),
  foreign key(message_id) references messages(id),
  foreign key(from_agent) references agents(agent_id)
);

create table if not exists receipts (
  id text primary key,
  message_id text not null,
  from_agent text not null,
  to_agent text not null,
  stage text not null,
  ok integer not null,
  reason text,
  at text not null,
  proof_json text not null,
  foreign key(message_id) references messages(id),
  foreign key(from_agent) references agents(agent_id)
);

create table if not exists route_records (
  route_id text primary key,
  agent_id text not null,
  kind text not null,
  status text not null,
  priority integer not null,
  proof_at text,
  expires_at text,
  foreign key(agent_id) references agents(agent_id)
);

create table if not exists capability_grants (
  grant_id text primary key,
  subject text not null,
  target text not null,
  capabilities_json text not null,
  created_at text not null,
  expires_at text not null
);

create index if not exists idx_threads_channel_created on threads(channel_name, created_at, id);
create index if not exists idx_messages_to_agent_created on messages(to_agent, created_at, id);
create index if not exists idx_messages_channel_created on messages(channel_name, created_at, id);
create index if not exists idx_inbox_agent_created on inbox(agent_id, created_at, id);
create index if not exists idx_receipts_message_at on receipts(message_id, at, id);
create index if not exists idx_route_records_agent_priority on route_records(agent_id, priority);
create index if not exists idx_capability_grants_subject_target on capability_grants(subject, target);
