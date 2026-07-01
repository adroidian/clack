create table if not exists artifacts (
  id text primary key,
  uri text not null,
  media_type text,
  sha256 text,
  size_bytes integer,
  created_by text not null,
  created_at text not null,
  metadata_json text not null default '{}',
  foreign key(created_by) references agents(agent_id)
);

create table if not exists message_artifacts (
  message_id text not null,
  artifact_id text not null,
  role text not null default 'attachment',
  primary key(message_id, artifact_id),
  foreign key(message_id) references messages(id),
  foreign key(artifact_id) references artifacts(id)
);

create index if not exists idx_artifacts_created_by_created on artifacts(created_by, created_at, id);
