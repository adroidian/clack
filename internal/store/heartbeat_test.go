package store

import (
	"strings"
	"testing"
	"time"
)

func TestHeartbeatAppliesProofAndExtendsExpiry(t *testing.T) {
	s := openTestStore(t)
	mustIdentity(t, s, "agent://zari.example")
	_, err := s.UpsertRouteRecord(RouteRecord{
		RouteID:    "route-zari-clack-http",
		AgentID:    "agent://zari.example",
		Kind:       "clack-http",
		Status:     "stale",
		Priority:   10,
		CreatedAt:  "2026-06-29T00:00:00Z",
		ExpiresAt:  "2026-06-29T00:05:00Z",
		ProofKind:  "none",
		TTLSeconds: 300,
	})
	if err != nil {
		t.Fatal(err)
	}

	result, err := s.ApplyHeartbeat(HeartbeatPayload{
		HeartbeatVersion: "1.0-draft",
		AgentID:          "agent://zari.example",
		RouteID:          "route-zari-clack-http",
		ProofKind:        "heartbeat",
		ProofAt:          "2026-06-29T00:10:00Z",
		TTLSeconds:       300,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Updated || result.Status != "active" || result.ExpiresAt != "2026-06-29T00:15:00Z" {
		t.Fatalf("unexpected heartbeat result: %+v", result)
	}
	routes, err := s.ListRouteRecords("agent://zari.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Status != "active" || routes[0].ProofKind != "heartbeat" || routes[0].ProofAt != "2026-06-29T00:10:00Z" || routes[0].ExpiresAt != "2026-06-29T00:15:00Z" {
		t.Fatalf("unexpected route after heartbeat: %+v", routes)
	}
}

func TestHeartbeatValidationAndRouteOwnership(t *testing.T) {
	s := openTestStore(t)
	mustIdentity(t, s, "agent://zari.example")
	mustIdentity(t, s, "agent://vesper.example")
	_, err := s.UpsertRouteRecord(RouteRecord{
		RouteID:    "route-zari-store",
		AgentID:    "agent://zari.example",
		Kind:       "store-only",
		Status:     "active",
		Priority:   50,
		CreatedAt:  "2026-06-29T00:00:00Z",
		ExpiresAt:  "2026-06-30T00:00:00Z",
		ProofKind:  "none",
		TTLSeconds: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.ApplyHeartbeat(HeartbeatPayload{AgentID: "agent://zari.example", RouteID: "route-missing", ProofKind: "heartbeat", ProofAt: "2026-06-29T00:10:00Z", TTLSeconds: 300})
	if err == nil || !strings.Contains(err.Error(), "route-not-found") {
		t.Fatalf("expected route-not-found, got %v", err)
	}
	_, err = s.ApplyHeartbeat(HeartbeatPayload{AgentID: "agent://missing.example", RouteID: "route-zari-store", ProofKind: "heartbeat", ProofAt: "2026-06-29T00:10:00Z", TTLSeconds: 300})
	if err == nil || !strings.Contains(err.Error(), "route-agent-mismatch") {
		t.Fatalf("expected route-agent-mismatch, got %v", err)
	}
	_, err = s.ApplyHeartbeat(HeartbeatPayload{AgentID: "agent://zari.example", RouteID: "", ProofKind: "heartbeat", ProofAt: "2026-06-29T00:10:00Z", TTLSeconds: 300})
	if err == nil || !strings.Contains(err.Error(), "routeId required") {
		t.Fatalf("expected routeId validation, got %v", err)
	}
	_, err = s.ApplyHeartbeat(HeartbeatPayload{AgentID: "agent://zari.example", RouteID: "route-zari-store", ProofKind: "telepathy", ProofAt: "2026-06-29T00:10:00Z", TTLSeconds: 300})
	if err == nil || !strings.Contains(err.Error(), "unknown proofKind") {
		t.Fatalf("expected proofKind validation, got %v", err)
	}
	_, err = s.ApplyHeartbeat(HeartbeatPayload{AgentID: "agent://zari.example", RouteID: "route-zari-store", ProofKind: "heartbeat", ProofAt: "not-a-date", TTLSeconds: 300})
	if err == nil || !strings.Contains(err.Error(), "proofAt must be ISO-8601") {
		t.Fatalf("expected proofAt validation, got %v", err)
	}
	_, err = s.ApplyHeartbeat(HeartbeatPayload{AgentID: "agent://zari.example", RouteID: "route-zari-store", ProofKind: "heartbeat", ProofAt: "2026-06-29T00:10:00Z", TTLSeconds: 0})
	if err != nil {
		t.Fatalf("expected omitted TTL to fall back to route/default TTL, got %v", err)
	}
	_, err = s.ApplyHeartbeat(HeartbeatPayload{AgentID: "agent://zari.example", RouteID: "route-zari-store", ProofKind: "heartbeat", ProofAt: "2026-06-29T00:10:00Z", TTLSeconds: 59})
	if err == nil || !strings.Contains(err.Error(), "ttlSeconds must be integer >= 60") {
		t.Fatalf("expected TTL validation, got %v", err)
	}
	_, err = HeartbeatPayloadFromJSON([]byte(`{"heartbeatVersion":"1.0-draft","agentId":"agent://zari.example","routeId":"route-zari-store","proofKind":"heartbeat","proofAt":"2026-06-29T00:10:00Z","ttlSeconds":300,"token":"nope"}`))
	if err == nil || !strings.Contains(err.Error(), "secret fields") {
		t.Fatalf("expected secret field validation, got %v", err)
	}
}

func TestHeartbeatMarksExpiredRoutesStaleAndUnreachable(t *testing.T) {
	s := openTestStore(t)
	mustIdentity(t, s, "agent://zari.example")
	_, err := s.UpsertRouteRecord(RouteRecord{
		RouteID:    "route-zari-expiring",
		AgentID:    "agent://zari.example",
		Kind:       "clack-http",
		Status:     "active",
		Priority:   10,
		CreatedAt:  "2026-06-29T00:00:00Z",
		ExpiresAt:  "2026-06-29T00:05:00Z",
		ProofKind:  "heartbeat",
		TTLSeconds: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := s.MarkExpiredRoutesStale(time.Date(2026, 6, 29, 0, 6, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if changed != 1 {
		t.Fatalf("stale rows = %d, want 1", changed)
	}
	routes, err := s.ListRouteRecords("agent://zari.example")
	if err != nil {
		t.Fatal(err)
	}
	if routes[0].Status != "stale" {
		t.Fatalf("status = %s, want stale", routes[0].Status)
	}
	if err := s.MarkRouteUnreachable("route-zari-expiring", time.Date(2026, 6, 29, 0, 7, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	routes, err = s.ListRouteRecords("agent://zari.example")
	if err != nil {
		t.Fatal(err)
	}
	if routes[0].Status != "unreachable" {
		t.Fatalf("status = %s, want unreachable", routes[0].Status)
	}
}
