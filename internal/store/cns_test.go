package store

import (
	"strings"
	"testing"
	"time"
)

func TestCNSIdentityUpsertAndValidation(t *testing.T) {
	s := openTestStore(t)

	identity, err := s.UpsertAgentIdentity(AgentIdentity{
		AgentID:       "agent://zari.example",
		Owner:         "human://example",
		Name:          "zari",
		Description:   "overwatch test agent",
		HarnessType:   "hermes",
		Host:          "ex",
		TrustClass:    "core-private",
		HermesProfile: "zari",
		RegisteredAt:  "2026-06-28T00:00:00Z",
		ExpiresAt:     "2027-06-28T00:00:00Z",
		Metadata:      `{"lane":"test"}`,
		PublicKeyRef:  "cns-keyring://zari.example/ed25519-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if identity.CNSVersion != "1.0-draft" || identity.Name != "zari" {
		t.Fatalf("unexpected normalized identity: %+v", identity)
	}

	got, err := s.GetAgentIdentity("agent://zari.example")
	if err != nil {
		t.Fatal(err)
	}
	if got.Owner != "human://example" || got.HarnessType != "hermes" || got.HermesProfile != "zari" || got.Metadata != `{"lane":"test"}` {
		t.Fatalf("unexpected stored identity: %+v", got)
	}

	_, err = s.UpsertAgentIdentity(AgentIdentity{
		AgentID:      "agent://bad.example",
		Owner:        "human://example",
		Name:         "notbad",
		HarnessType:  "hermes",
		Host:         "ex",
		RegisteredAt: "2026-06-28T00:00:00Z",
		ExpiresAt:    "2027-06-28T00:00:00Z",
	})
	if err == nil || !strings.Contains(err.Error(), "name must match") {
		t.Fatalf("expected name mismatch validation, got %v", err)
	}

	_, err = s.UpsertAgentIdentity(AgentIdentity{
		AgentID:      "agent://bad.example",
		Owner:        "human://example",
		Name:         "bad",
		HarnessType:  "hermes",
		Host:         "ex",
		RegisteredAt: "2026-06-28T00:00:00Z",
		ExpiresAt:    "2027-06-28T00:00:00Z",
	})
	if err == nil || !strings.Contains(err.Error(), "hermesProfile required") {
		t.Fatalf("expected hermesProfile validation, got %v", err)
	}
}

func TestCNSRouteRecordsValidateAndListByPriority(t *testing.T) {
	s := openTestStore(t)
	mustIdentity(t, s, "agent://zari.example")

	if _, err := s.UpsertRouteRecord(RouteRecord{
		RouteID:   "route-store",
		AgentID:   "agent://zari.example",
		Kind:      "store-only",
		Status:    "active",
		Priority:  50,
		CreatedAt: "2026-06-28T00:00:00Z",
		ExpiresAt: "2026-06-29T00:00:00Z",
		ProofKind: "none",
		Metadata:  `{"mode":"dead-drop"}`,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertRouteRecord(RouteRecord{
		RouteID:    "route-direct",
		AgentID:    "agent://zari.example",
		Kind:       "clack-http",
		Status:     "active",
		Priority:   10,
		Endpoint:   "http://example.invalid/a2a",
		CreatedAt:  "2026-06-28T00:00:00Z",
		ExpiresAt:  "2026-06-29T00:00:00Z",
		ProofAt:    "2026-06-28T00:05:00Z",
		ProofKind:  "delivery",
		ProofID:    "rcpt-test",
		TTLSeconds: 86400,
	}); err != nil {
		t.Fatal(err)
	}

	routes, err := s.ListRouteRecords("agent://zari.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[0].RouteID != "route-direct" || routes[1].RouteID != "route-store" {
		t.Fatalf("routes not sorted by priority: %+v", routes)
	}

	_, err = s.UpsertRouteRecord(RouteRecord{
		RouteID:   "route-bad",
		AgentID:   "agent://zari.example",
		Kind:      "clack-http",
		Status:    "active",
		Priority:  10,
		CreatedAt: "2026-06-28T00:00:00Z",
		ExpiresAt: "2026-06-29T00:00:00Z",
		ProofKind: "delivery",
	})
	if err == nil || !strings.Contains(err.Error(), "proofId required") {
		t.Fatalf("expected proofId validation, got %v", err)
	}
}

func TestCNSCapabilityGrantCheck(t *testing.T) {
	s := openTestStore(t)
	mustIdentity(t, s, "agent://zari.example")
	mustIdentity(t, s, "agent://vesper.example")

	grant, err := s.UpsertCapabilityGrant(CapabilityGrant{
		GrantID:         "grant-zari-to-vesper-wake-20260628",
		Subject:         "agent://zari.example",
		Target:          "agent://vesper.example",
		Capabilities:    []string{"store-only", "direct-send", "wake"},
		OwnerApprovedBy: "human://example",
		CreatedAt:       "2026-06-28T00:00:00Z",
		ExpiresAt:       "2026-07-28T00:00:00Z",
		Constraints:     `{"topics":["ops.*"],"maxWakeTurns":20}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if grant.GrantVersion != "1.0-draft" || len(grant.Capabilities) != 3 {
		t.Fatalf("unexpected grant: %+v", grant)
	}

	_, ok, err := s.CheckCapability("agent://zari.example", "agent://vesper.example", "wake", time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected wake capability to be granted")
	}
	_, ok, err = s.CheckCapability("agent://zari.example", "agent://vesper.example", "admin", time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("admin should not be granted")
	}
	_, ok, err = s.CheckCapability("agent://zari.example", "agent://vesper.example", "wake", time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expired grant should not authorize wake")
	}

	_, err = s.UpsertCapabilityGrant(CapabilityGrant{
		GrantID:      "grant-tools-missing-owner",
		Subject:      "agent://zari.example",
		Target:       "agent://vesper.example",
		Capabilities: []string{"tools"},
		CreatedAt:    "2026-06-28T00:00:00Z",
		ExpiresAt:    "2026-07-28T00:00:00Z",
	})
	if err == nil || !strings.Contains(err.Error(), "ownerApprovedBy required") {
		t.Fatalf("expected owner approval validation, got %v", err)
	}

	_, err = s.UpsertCapabilityGrant(CapabilityGrant{
		GrantID:         "grant-tools-bad-owner",
		Subject:         "agent://zari.example",
		Target:          "agent://vesper.example",
		Capabilities:    []string{"tools"},
		OwnerApprovedBy: "aaron",
		CreatedAt:       "2026-06-28T00:00:00Z",
		ExpiresAt:       "2026-07-28T00:00:00Z",
	})
	if err == nil || !strings.Contains(err.Error(), "ownerApprovedBy must be human://") {
		t.Fatalf("expected ownerApprovedBy URI validation, got %v", err)
	}

	_, err = s.UpsertCapabilityGrant(CapabilityGrant{
		GrantID:      "grant-unknown-capability",
		Subject:      "agent://zari.example",
		Target:       "agent://vesper.example",
		Capabilities: []string{"telepathy"},
		CreatedAt:    "2026-06-28T00:00:00Z",
		ExpiresAt:    "2026-07-28T00:00:00Z",
	})
	if err == nil || !strings.Contains(err.Error(), "unknown capability") {
		t.Fatalf("expected unknown capability validation, got %v", err)
	}

	_, err = s.UpsertCapabilityGrant(CapabilityGrant{
		GrantID:      "grant-expired-at-creation",
		Subject:      "agent://zari.example",
		Target:       "agent://vesper.example",
		Capabilities: []string{"store-only"},
		CreatedAt:    "2026-07-28T00:00:00Z",
		ExpiresAt:    "2026-06-28T00:00:00Z",
	})
	if err == nil || !strings.Contains(err.Error(), "expiresAt must be after createdAt") {
		t.Fatalf("expected grant time-order validation, got %v", err)
	}
}

func TestCNSMigrationColumnsPreserveRegisterAgent(t *testing.T) {
	s := openTestStore(t)
	mustRegister(t, s, "agent://legacy.example")
	identity, err := s.GetAgentIdentity("agent://legacy.example")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Owner != "human://unknown" || identity.HarnessType != "unknown" || identity.CNSVersion != "1.0-draft" {
		t.Fatalf("legacy RegisterAgent defaults not preserved: %+v", identity)
	}
}

func mustIdentity(t *testing.T, s *Store, id string) {
	t.Helper()
	_, err := s.UpsertAgentIdentity(AgentIdentity{
		AgentID:       id,
		Owner:         "human://example",
		Name:          shortName(id),
		Description:   shortName(id),
		HarnessType:   "hermes",
		Host:          "test-host",
		TrustClass:    "core-private",
		HermesProfile: shortName(id),
		RegisteredAt:  "2026-06-28T00:00:00Z",
		ExpiresAt:     "2027-06-28T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
}
