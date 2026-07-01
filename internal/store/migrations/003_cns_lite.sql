alter table agents add column cns_version text not null default '1.0-draft';
alter table agents add column owner text not null default 'human://unknown';
alter table agents add column description text not null default '';
alter table agents add column harness_type text not null default 'unknown';
alter table agents add column host text not null default 'unknown';
alter table agents add column trust_class text not null default 'unknown';
alter table agents add column hermes_profile text;
alter table agents add column expires_at text not null default '9999-12-31T23:59:59Z';
alter table agents add column updated_at text;
alter table agents add column metadata_json text not null default '{}';
alter table agents add column public_key_ref text;

alter table route_records add column route_record_version text not null default '1.0-draft';
alter table route_records add column endpoint text;
alter table route_records add column created_at text not null default '1970-01-01T00:00:00Z';
alter table route_records add column updated_at text;
alter table route_records add column proof_kind text not null default 'none';
alter table route_records add column proof_id text;
alter table route_records add column ttl_seconds integer;
alter table route_records add column metadata_json text not null default '{}';

alter table capability_grants add column grant_version text not null default '1.0-draft';
alter table capability_grants add column owner_approved_by text;
alter table capability_grants add column constraints_json text not null default '{}';
alter table capability_grants add column metadata_json text not null default '{}';

create index if not exists idx_agents_owner_name on agents(owner, name);
create index if not exists idx_agents_expires_at on agents(expires_at);
create index if not exists idx_route_records_status_expiry on route_records(status, expires_at);
create index if not exists idx_capability_grants_expiry on capability_grants(expires_at);
