package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const heartbeatVersion = "1.0-draft"

type HeartbeatPayload struct {
	HeartbeatVersion string         `json:"heartbeatVersion"`
	AgentID          string         `json:"agentId"`
	RouteID          string         `json:"routeId"`
	ProofKind        string         `json:"proofKind"`
	ProofAt          string         `json:"proofAt"`
	TTLSeconds       int            `json:"ttlSeconds"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

type HeartbeatResult struct {
	Updated   bool   `json:"updated"`
	RouteID   string `json:"routeId"`
	AgentID   string `json:"agentId"`
	Status    string `json:"status"`
	ProofKind string `json:"proofKind"`
	ProofAt   string `json:"proofAt"`
	ExpiresAt string `json:"expiresAt"`
}

var (
	heartbeatProofKinds = map[string]bool{"heartbeat": true, "delivery": true, "wake-output": true, "health-check": true}
	secretFieldNames    = map[string]bool{"token": true, "secret": true, "password": true, "apiKey": true, "api_key": true, "anthropic_token": true, "hooksToken": true, "publicKey": true}
)

func (s *Store) ApplyHeartbeat(payload HeartbeatPayload) (HeartbeatResult, error) {
	payload = normalizeHeartbeat(payload)
	proofAt, err := validateHeartbeatPayload(payload)
	if err != nil {
		return HeartbeatResult{}, err
	}
	var agentID string
	var ttlSeconds int
	err = s.db.QueryRow(`select agent_id, coalesce(ttl_seconds,0) from route_records where route_id=?`, payload.RouteID).Scan(&agentID, &ttlSeconds)
	if err == sql.ErrNoRows {
		return HeartbeatResult{}, errors.New("route-not-found")
	}
	if err != nil {
		return HeartbeatResult{}, err
	}
	if agentID != payload.AgentID {
		return HeartbeatResult{}, errors.New("route-agent-mismatch")
	}
	if payload.TTLSeconds > 0 {
		ttlSeconds = payload.TTLSeconds
	}
	if ttlSeconds < 60 {
		ttlSeconds = defaultTTLForRouteKind(s, payload.RouteID)
	}
	expiresAt := proofAt.Add(time.Duration(ttlSeconds) * time.Second).UTC().Format(time.RFC3339)
	proofAtText := proofAt.UTC().Format(time.RFC3339)
	_, err = s.db.Exec(`update route_records set status='active', proof_at=?, proof_kind=?, ttl_seconds=?, expires_at=?, updated_at=? where route_id=?`, proofAtText, payload.ProofKind, ttlSeconds, expiresAt, proofAtText, payload.RouteID)
	if err != nil {
		return HeartbeatResult{}, err
	}
	return HeartbeatResult{Updated: true, RouteID: payload.RouteID, AgentID: payload.AgentID, Status: "active", ProofKind: payload.ProofKind, ProofAt: proofAtText, ExpiresAt: expiresAt}, nil
}

func (s *Store) MarkExpiredRoutesStale(at time.Time) (int64, error) {
	res, err := s.db.Exec(`update route_records set status='stale', updated_at=? where status='active' and expires_at <= ?`, at.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) MarkRouteUnreachable(routeID string, at time.Time) error {
	if strings.TrimSpace(routeID) == "" {
		return errors.New("routeId required")
	}
	res, err := s.db.Exec(`update route_records set status='unreachable', updated_at=? where route_id=? and status='stale'`, at.UTC().Format(time.RFC3339), routeID)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return errors.New("stale-route-not-found")
	}
	return nil
}

func normalizeHeartbeat(h HeartbeatPayload) HeartbeatPayload {
	if h.HeartbeatVersion == "" {
		h.HeartbeatVersion = heartbeatVersion
	}
	if h.ProofKind == "" {
		h.ProofKind = "heartbeat"
	}
	return h
}

func validateHeartbeatPayload(h HeartbeatPayload) (time.Time, error) {
	if h.HeartbeatVersion != heartbeatVersion {
		return time.Time{}, fmt.Errorf("heartbeatVersion must be %s", heartbeatVersion)
	}
	if err := validateAgentID(h.AgentID); err != nil {
		return time.Time{}, fmt.Errorf("agentId: %w", err)
	}
	if strings.TrimSpace(h.RouteID) == "" {
		return time.Time{}, errors.New("routeId required")
	}
	if !heartbeatProofKinds[h.ProofKind] {
		return time.Time{}, fmt.Errorf("unknown proofKind: %s", h.ProofKind)
	}
	proofAt, err := parseTime(h.ProofAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("proofAt must be ISO-8601: %w", err)
	}
	if h.TTLSeconds != 0 && h.TTLSeconds < 60 {
		return time.Time{}, errors.New("ttlSeconds must be integer >= 60")
	}
	if containsSecretFields(h.Metadata) {
		return time.Time{}, errors.New("secret fields must not appear in heartbeat metadata")
	}
	return proofAt, nil
}

func containsSecretFields(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case map[string]any:
		for k, v := range x {
			if secretFieldNames[k] || containsSecretFields(v) {
				return true
			}
		}
	case []any:
		for _, item := range x {
			if containsSecretFields(item) {
				return true
			}
		}
	}
	return false
}

func defaultTTLForRouteKind(s *Store, routeID string) int {
	var kind string
	if err := s.db.QueryRow(`select kind from route_records where route_id=?`, routeID).Scan(&kind); err != nil {
		return 300
	}
	switch kind {
	case "hermes-wake":
		return 3600
	case "filedrop", "store-only":
		return 86400
	case "relay":
		return 900
	default:
		return 300
	}
}

func HeartbeatPayloadFromJSON(payload []byte) (HeartbeatPayload, error) {
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return HeartbeatPayload{}, err
	}
	if containsSecretFields(raw) {
		return HeartbeatPayload{}, errors.New("secret fields must not appear in heartbeat")
	}
	var h HeartbeatPayload
	if err := json.Unmarshal(payload, &h); err != nil {
		return HeartbeatPayload{}, err
	}
	return h, nil
}
