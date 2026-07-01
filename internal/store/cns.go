package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

const (
	cnsVersion            = "1.0-draft"
	routeRecordVersion    = "1.0-draft"
	grantVersion          = "1.0-draft"
	defaultCNSExpiryYears = 1
)

var humanIDRe = regexp.MustCompile(`^human://[a-z0-9][a-z0-9-]*$`)

type AgentIdentity struct {
	CNSVersion    string
	AgentID       string
	Owner         string
	Name          string
	Description   string
	HarnessType   string
	Host          string
	TrustClass    string
	HermesProfile string
	RegisteredAt  string
	ExpiresAt     string
	UpdatedAt     string
	Metadata      string
	PublicKeyRef  string
}

type RouteRecord struct {
	RouteRecordVersion string
	RouteID            string
	AgentID            string
	Kind               string
	Status             string
	Priority           int
	Endpoint           string
	CreatedAt          string
	ExpiresAt          string
	UpdatedAt          string
	ProofAt            string
	ProofKind          string
	ProofID            string
	TTLSeconds         int
	Metadata           string
}

type CapabilityGrant struct {
	GrantVersion    string
	GrantID         string
	Subject         string
	Target          string
	Capabilities    []string
	OwnerApprovedBy string
	CreatedAt       string
	ExpiresAt       string
	Constraints     string
	Metadata        string
}

var (
	validHarnessTypes = map[string]bool{"hermes": true, "claude-code": true, "openclaw": true, "unknown": true}
	validTrustClasses = map[string]bool{"core-private": true, "peer-aaron": true, "cross-human": true, "unknown": true}
	validRouteKinds   = map[string]bool{"local-http": true, "clack-http": true, "filedrop": true, "store-only": true, "hermes-wake": true, "openclaw-hook": true, "relay": true, "lakebed-dead-drop": true, "tailscale-http": true, "p2p-libp2p": true, "p2p-iroh": true, "unknown": true}
	validRouteStatus  = map[string]bool{"active": true, "stale": true, "unreachable": true}
	validProofKinds   = map[string]bool{"heartbeat": true, "delivery": true, "wake-output": true, "health-check": true, "none": true}
	validCapabilities = map[string]bool{"discover": true, "store-only": true, "direct-send": true, "wake": true, "reply": true, "tools": true, "admin": true}
)

func (s *Store) UpsertAgentIdentity(identity AgentIdentity) (AgentIdentity, error) {
	identity = normalizeIdentity(identity)
	if err := validateIdentity(identity); err != nil {
		return AgentIdentity{}, err
	}
	_, err := s.db.Exec(`insert into agents(agent_id,name,registered_at,cns_version,owner,description,harness_type,host,trust_class,hermes_profile,expires_at,updated_at,metadata_json,public_key_ref)
values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
on conflict(agent_id) do update set
  name=excluded.name,
  cns_version=excluded.cns_version,
  owner=excluded.owner,
  description=excluded.description,
  harness_type=excluded.harness_type,
  host=excluded.host,
  trust_class=excluded.trust_class,
  hermes_profile=excluded.hermes_profile,
  expires_at=excluded.expires_at,
  updated_at=excluded.updated_at,
  metadata_json=excluded.metadata_json,
  public_key_ref=excluded.public_key_ref`, identity.AgentID, identity.Name, identity.RegisteredAt, identity.CNSVersion, identity.Owner, identity.Description, identity.HarnessType, identity.Host, identity.TrustClass, nullIfEmpty(identity.HermesProfile), identity.ExpiresAt, nullIfEmpty(identity.UpdatedAt), identity.Metadata, nullIfEmpty(identity.PublicKeyRef))
	if err != nil {
		return AgentIdentity{}, err
	}
	return identity, nil
}

func (s *Store) GetAgentIdentity(agentID string) (AgentIdentity, error) {
	if err := validateAgentID(agentID); err != nil {
		return AgentIdentity{}, err
	}
	var i AgentIdentity
	var hermesProfile, updatedAt, publicKeyRef sql.NullString
	err := s.db.QueryRow(`select cns_version,agent_id,owner,name,description,harness_type,host,trust_class,hermes_profile,registered_at,expires_at,updated_at,metadata_json,public_key_ref from agents where agent_id=?`, agentID).Scan(&i.CNSVersion, &i.AgentID, &i.Owner, &i.Name, &i.Description, &i.HarnessType, &i.Host, &i.TrustClass, &hermesProfile, &i.RegisteredAt, &i.ExpiresAt, &updatedAt, &i.Metadata, &publicKeyRef)
	if err != nil {
		return AgentIdentity{}, err
	}
	i.HermesProfile = hermesProfile.String
	i.UpdatedAt = updatedAt.String
	i.PublicKeyRef = publicKeyRef.String
	return i, nil
}

func (s *Store) UpsertRouteRecord(route RouteRecord) (RouteRecord, error) {
	route = normalizeRoute(route)
	if err := validateRoute(route); err != nil {
		return RouteRecord{}, err
	}
	if err := s.ensureAgent(route.AgentID); err != nil {
		return RouteRecord{}, err
	}
	_, err := s.db.Exec(`insert into route_records(route_id,agent_id,kind,status,priority,proof_at,expires_at,route_record_version,endpoint,created_at,updated_at,proof_kind,proof_id,ttl_seconds,metadata_json)
values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
on conflict(route_id) do update set
  agent_id=excluded.agent_id,
  kind=excluded.kind,
  status=excluded.status,
  priority=excluded.priority,
  proof_at=excluded.proof_at,
  expires_at=excluded.expires_at,
  route_record_version=excluded.route_record_version,
  endpoint=excluded.endpoint,
  updated_at=excluded.updated_at,
  proof_kind=excluded.proof_kind,
  proof_id=excluded.proof_id,
  ttl_seconds=excluded.ttl_seconds,
  metadata_json=excluded.metadata_json`, route.RouteID, route.AgentID, route.Kind, route.Status, route.Priority, nullIfEmpty(route.ProofAt), route.ExpiresAt, route.RouteRecordVersion, nullIfEmpty(route.Endpoint), route.CreatedAt, nullIfEmpty(route.UpdatedAt), route.ProofKind, nullIfEmpty(route.ProofID), nullIfZero(route.TTLSeconds), route.Metadata)
	if err != nil {
		return RouteRecord{}, err
	}
	return route, nil
}

func (s *Store) ListRouteRecords(agentID string) ([]RouteRecord, error) {
	if err := validateAgentID(agentID); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`select route_record_version,route_id,agent_id,kind,status,priority,coalesce(endpoint,''),created_at,expires_at,coalesce(updated_at,''),coalesce(proof_at,''),proof_kind,coalesce(proof_id,''),coalesce(ttl_seconds,0),metadata_json from route_records where agent_id=? order by priority,route_id`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var routes []RouteRecord
	for rows.Next() {
		var r RouteRecord
		if err := rows.Scan(&r.RouteRecordVersion, &r.RouteID, &r.AgentID, &r.Kind, &r.Status, &r.Priority, &r.Endpoint, &r.CreatedAt, &r.ExpiresAt, &r.UpdatedAt, &r.ProofAt, &r.ProofKind, &r.ProofID, &r.TTLSeconds, &r.Metadata); err != nil {
			return nil, err
		}
		routes = append(routes, r)
	}
	return routes, rows.Err()
}

func (s *Store) UpsertCapabilityGrant(grant CapabilityGrant) (CapabilityGrant, error) {
	grant = normalizeGrant(grant)
	if err := validateGrant(grant); err != nil {
		return CapabilityGrant{}, err
	}
	if err := s.ensureAgent(grant.Subject); err != nil {
		return CapabilityGrant{}, fmt.Errorf("unknown grant subject: %w", err)
	}
	if err := s.ensureAgent(grant.Target); err != nil {
		return CapabilityGrant{}, fmt.Errorf("unknown grant target: %w", err)
	}
	capJSON, err := json.Marshal(grant.Capabilities)
	if err != nil {
		return CapabilityGrant{}, err
	}
	_, err = s.db.Exec(`insert into capability_grants(grant_id,subject,target,capabilities_json,created_at,expires_at,grant_version,owner_approved_by,constraints_json,metadata_json)
values(?,?,?,?,?,?,?,?,?,?)
on conflict(grant_id) do update set
  subject=excluded.subject,
  target=excluded.target,
  capabilities_json=excluded.capabilities_json,
  created_at=excluded.created_at,
  expires_at=excluded.expires_at,
  grant_version=excluded.grant_version,
  owner_approved_by=excluded.owner_approved_by,
  constraints_json=excluded.constraints_json,
  metadata_json=excluded.metadata_json`, grant.GrantID, grant.Subject, grant.Target, string(capJSON), grant.CreatedAt, grant.ExpiresAt, grant.GrantVersion, nullIfEmpty(grant.OwnerApprovedBy), grant.Constraints, grant.Metadata)
	if err != nil {
		return CapabilityGrant{}, err
	}
	return grant, nil
}

func (s *Store) CheckCapability(subject, target, capability string, at time.Time) (CapabilityGrant, bool, error) {
	if err := validateAgentID(subject); err != nil {
		return CapabilityGrant{}, false, err
	}
	if err := validateAgentID(target); err != nil {
		return CapabilityGrant{}, false, err
	}
	if !validCapabilities[capability] {
		return CapabilityGrant{}, false, fmt.Errorf("unknown capability: %s", capability)
	}
	rows, err := s.db.Query(`select grant_version,grant_id,subject,target,capabilities_json,coalesce(owner_approved_by,''),created_at,expires_at,constraints_json,metadata_json from capability_grants where subject=? and target=? and expires_at>? order by expires_at desc, grant_id`, subject, target, at.UTC().Format(time.RFC3339))
	if err != nil {
		return CapabilityGrant{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		grant, err := scanGrant(rows)
		if err != nil {
			return CapabilityGrant{}, false, err
		}
		if slices.Contains(grant.Capabilities, capability) {
			return grant, true, nil
		}
	}
	return CapabilityGrant{}, false, rows.Err()
}

func normalizeIdentity(i AgentIdentity) AgentIdentity {
	now := time.Now().UTC().Format(time.RFC3339)
	if i.CNSVersion == "" {
		i.CNSVersion = cnsVersion
	}
	if i.Name == "" {
		i.Name = shortName(i.AgentID)
	}
	if i.Description == "" {
		i.Description = i.Name
	}
	if i.HarnessType == "" {
		i.HarnessType = "unknown"
	}
	if i.Host == "" {
		i.Host = "unknown"
	}
	if i.TrustClass == "" {
		i.TrustClass = "unknown"
	}
	if i.RegisteredAt == "" {
		i.RegisteredAt = now
	}
	if i.UpdatedAt == "" {
		i.UpdatedAt = now
	}
	if i.ExpiresAt == "" {
		i.ExpiresAt = time.Now().UTC().AddDate(defaultCNSExpiryYears, 0, 0).Format(time.RFC3339)
	}
	if i.Metadata == "" {
		i.Metadata = "{}"
	}
	return i
}

func normalizeRoute(r RouteRecord) RouteRecord {
	now := time.Now().UTC().Format(time.RFC3339)
	if r.RouteRecordVersion == "" {
		r.RouteRecordVersion = routeRecordVersion
	}
	if r.Status == "" {
		r.Status = "active"
	}
	if r.Priority == 0 {
		r.Priority = 50
	}
	if r.CreatedAt == "" {
		r.CreatedAt = now
	}
	if r.UpdatedAt == "" {
		r.UpdatedAt = now
	}
	if r.ProofKind == "" {
		r.ProofKind = "none"
	}
	if r.TTLSeconds > 0 && r.ExpiresAt == "" {
		t, _ := parseTime(r.CreatedAt)
		r.ExpiresAt = t.Add(time.Duration(r.TTLSeconds) * time.Second).Format(time.RFC3339)
	}
	if r.ExpiresAt == "" {
		r.ExpiresAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	}
	if r.Metadata == "" {
		r.Metadata = "{}"
	}
	return r
}

func normalizeGrant(g CapabilityGrant) CapabilityGrant {
	now := time.Now().UTC().Format(time.RFC3339)
	if g.GrantVersion == "" {
		g.GrantVersion = grantVersion
	}
	if g.CreatedAt == "" {
		g.CreatedAt = now
	}
	if g.ExpiresAt == "" {
		g.ExpiresAt = time.Now().UTC().AddDate(0, 1, 0).Format(time.RFC3339)
	}
	if g.Constraints == "" {
		g.Constraints = "{}"
	}
	if g.Metadata == "" {
		g.Metadata = "{}"
	}
	return g
}

func validateIdentity(i AgentIdentity) error {
	if i.CNSVersion != cnsVersion {
		return fmt.Errorf("cnsVersion must be %s", cnsVersion)
	}
	if err := validateAgentID(i.AgentID); err != nil {
		return err
	}
	if !humanIDRe.MatchString(i.Owner) {
		return errors.New("owner must be human://<name>")
	}
	if i.Name != shortName(i.AgentID) {
		return errors.New("name must match agentId name component")
	}
	if !validHarnessTypes[i.HarnessType] {
		return fmt.Errorf("unknown harnessType: %s", i.HarnessType)
	}
	if !validTrustClasses[i.TrustClass] {
		return fmt.Errorf("unknown trustClass: %s", i.TrustClass)
	}
	if i.HarnessType == "hermes" && i.HermesProfile == "" {
		return errors.New("hermesProfile required for hermes identities")
	}
	return validateTimeOrder(i.RegisteredAt, i.ExpiresAt, "registeredAt", "expiresAt")
}

func validateRoute(r RouteRecord) error {
	if r.RouteRecordVersion != routeRecordVersion {
		return fmt.Errorf("routeRecordVersion must be %s", routeRecordVersion)
	}
	if r.RouteID == "" {
		return errors.New("routeId required")
	}
	if err := validateAgentID(r.AgentID); err != nil {
		return err
	}
	if !validRouteKinds[r.Kind] {
		return fmt.Errorf("unknown route kind: %s", r.Kind)
	}
	if !validRouteStatus[r.Status] {
		return fmt.Errorf("unknown route status: %s", r.Status)
	}
	if r.Priority <= 0 {
		return errors.New("priority must be positive")
	}
	if !validProofKinds[r.ProofKind] {
		return fmt.Errorf("unknown proofKind: %s", r.ProofKind)
	}
	if (r.ProofKind == "delivery" || r.ProofKind == "wake-output") && r.ProofID == "" {
		return errors.New("proofId required for delivery or wake-output proof")
	}
	return validateTimeOrder(r.CreatedAt, r.ExpiresAt, "createdAt", "expiresAt")
}

func validateGrant(g CapabilityGrant) error {
	if g.GrantVersion != grantVersion {
		return fmt.Errorf("grantVersion must be %s", grantVersion)
	}
	if g.GrantID == "" {
		return errors.New("grantId required")
	}
	if err := validateAgentID(g.Subject); err != nil {
		return fmt.Errorf("subject: %w", err)
	}
	if err := validateAgentID(g.Target); err != nil {
		return fmt.Errorf("target: %w", err)
	}
	if len(g.Capabilities) == 0 {
		return errors.New("capabilities must be non-empty")
	}
	for _, capability := range g.Capabilities {
		if !validCapabilities[capability] {
			return fmt.Errorf("unknown capability: %s", capability)
		}
	}
	if (slices.Contains(g.Capabilities, "tools") || slices.Contains(g.Capabilities, "admin")) && g.OwnerApprovedBy == "" {
		return errors.New("ownerApprovedBy required for tools/admin")
	}
	if g.OwnerApprovedBy != "" && !humanIDRe.MatchString(g.OwnerApprovedBy) {
		return errors.New("ownerApprovedBy must be human://<name>")
	}
	return validateTimeOrder(g.CreatedAt, g.ExpiresAt, "createdAt", "expiresAt")
}

func validateTimeOrder(start, end, startName, endName string) error {
	startAt, err := parseTime(start)
	if err != nil {
		return fmt.Errorf("%s must be ISO-8601: %w", startName, err)
	}
	endAt, err := parseTime(end)
	if err != nil {
		return fmt.Errorf("%s must be ISO-8601: %w", endName, err)
	}
	if !endAt.After(startAt) {
		return fmt.Errorf("%s must be after %s", endName, startName)
	}
	return nil
}

func parseTime(value string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339Nano, value)
}

func scanGrant(rows *sql.Rows) (CapabilityGrant, error) {
	var g CapabilityGrant
	var caps string
	if err := rows.Scan(&g.GrantVersion, &g.GrantID, &g.Subject, &g.Target, &caps, &g.OwnerApprovedBy, &g.CreatedAt, &g.ExpiresAt, &g.Constraints, &g.Metadata); err != nil {
		return CapabilityGrant{}, err
	}
	if err := json.Unmarshal([]byte(caps), &g.Capabilities); err != nil {
		return CapabilityGrant{}, err
	}
	return g, nil
}

func nullIfZero(i int) any {
	if i == 0 {
		return nil
	}
	return i
}
