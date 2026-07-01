package store

import (
	"database/sql"
	"strings"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir() + "/clack.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestRegisterAgentValidatesAgentURIAndDefaultsName(t *testing.T) {
	s := openTestStore(t)

	for _, bad := range []string{"zari", "agent://zari", "agent://Zari.example", "agent://zari.example.extra", "agent://zari_1.example"} {
		if _, err := s.RegisterAgent(bad, ""); err == nil || !strings.Contains(err.Error(), "agent://<name>.<owner>") {
			t.Fatalf("RegisterAgent(%q) expected stable agent URI validation error, got %v", bad, err)
		}
	}

	a, err := s.RegisterAgent("agent://zari.example", "")
	if err != nil {
		t.Fatal(err)
	}
	if a.Name != "zari" {
		t.Fatalf("default name = %q, want zari", a.Name)
	}
}

func TestSendDMQueuesInboxAndEmitsSpecReceipts(t *testing.T) {
	s := openTestStore(t)
	mustRegister(t, s, "agent://zari.example")
	mustRegister(t, s, "agent://vesper.example")

	msg, receipts, err := s.SendDM("agent://zari.example", "agent://vesper.example", "ping")
	if err != nil {
		t.Fatal(err)
	}
	if msg.FromAgent != "agent://zari.example" || msg.ToAgent != "agent://vesper.example" || msg.Body != "ping" {
		t.Fatalf("unexpected message: %+v", msg)
	}
	wantStages := []string{"accepted", "policy-checked", "routed", "stored"}
	if got := stages(receipts); strings.Join(got, ",") != strings.Join(wantStages, ",") {
		t.Fatalf("receipt stages = %v, want %v", got, wantStages)
	}
	for _, r := range receipts {
		if r.ReceiptVersion != "1.0-draft" || r.ID == "" || r.MessageID != msg.ID || r.From != "agent://zari.example" || r.To != "agent://vesper.example" || r.At == "" || r.Proof == "" {
			t.Fatalf("receipt missing spec fields: %+v", r)
		}
	}

	items, err := s.ListInbox("agent://vesper.example")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Body != "ping" || items[0].FromAgent != "agent://zari.example" {
		t.Fatalf("unexpected inbox items: %+v", items)
	}

	var storedProof string
	if err := s.db.QueryRow(`select proof_json from receipts where message_id=? and stage='stored'`, msg.ID).Scan(&storedProof); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(storedProof, "inboxPath") || !strings.Contains(storedProof, "store-only") {
		t.Fatalf("stored proof lacks inbox/store-only evidence: %s", storedProof)
	}
}

func TestListReceiptsReturnsSpecFields(t *testing.T) {
	s := openTestStore(t)
	mustRegister(t, s, "agent://zari.example")
	mustRegister(t, s, "agent://vesper.example")
	msg, _, err := s.SendDM("agent://zari.example", "agent://vesper.example", "ping")
	if err != nil {
		t.Fatal(err)
	}

	receipts, err := s.ListReceipts()
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 4 {
		t.Fatalf("len(receipts) = %d, want 4", len(receipts))
	}
	for _, r := range receipts {
		if r.ReceiptVersion != "1.0-draft" || r.MessageID != msg.ID || r.From == "" || r.To == "" || r.At == "" || r.Proof == "" {
			t.Fatalf("listed receipt missing spec fields: %+v", r)
		}
	}
}

func TestSendDMRejectsUnknownTarget(t *testing.T) {
	s := openTestStore(t)
	mustRegister(t, s, "agent://zari.example")
	_, _, err := s.SendDM("agent://zari.example", "agent://missing.example", "ping")
	if err == nil || !strings.Contains(err.Error(), "unknown agent") {
		t.Fatalf("expected unknown agent error, got %v", err)
	}
}

func TestChannelCreateIsIdempotent(t *testing.T) {
	s := openTestStore(t)

	first, err := s.CreateChannel("ops")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateChannel("ops")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == 0 || second.ID == 0 || first.ID != second.ID {
		t.Fatalf("CreateChannel IDs = first:%d second:%d, want same non-zero id", first.ID, second.ID)
	}
}

func TestChannelPostPersistsMessageAndReceipts(t *testing.T) {
	s := openTestStore(t)
	mustRegister(t, s, "agent://zari.example")

	msg, receipts, err := s.PostChannel("ops", "agent://zari.example", "status?")
	if err != nil {
		t.Fatal(err)
	}
	if msg.ChannelName != "ops" || msg.Body != "status?" {
		t.Fatalf("unexpected channel message: %+v", msg)
	}
	if got := stages(receipts); strings.Join(got, ",") != "accepted,stored" {
		t.Fatalf("receipt stages = %v", got)
	}
	for _, r := range receipts {
		if r.ReceiptVersion != "1.0-draft" || r.From != "agent://zari.example" || r.To != "agent://channel.ops" || r.At == "" || r.Proof == "" {
			t.Fatalf("channel receipt missing spec fields: %+v", r)
		}
	}

	var body string
	if err := s.db.QueryRow(`select body from messages where id=? and kind='channel'`, msg.ID).Scan(&body); err != nil {
		t.Fatal(err)
	}
	if body != "status?" {
		t.Fatalf("stored channel body = %q", body)
	}
}

func TestInitCreatesCoreTables(t *testing.T) {
	s := openTestStore(t)
	for _, table := range []string{"schema_migrations", "agents", "channels", "messages", "inbox", "receipts", "route_records", "capability_grants", "threads", "artifacts", "message_artifacts"} {
		if !tableExists(t, s.db, table) {
			t.Fatalf("expected table %s to exist", table)
		}
	}
}

func TestInitRecordsMigrationsAndIsIdempotent(t *testing.T) {
	s := openTestStore(t)

	versions := appliedMigrationVersions(t, s.db)
	want := []string{"001", "002", "003"}
	if strings.Join(versions, ",") != strings.Join(want, ",") {
		t.Fatalf("migration versions = %v, want %v", versions, want)
	}

	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	versions = appliedMigrationVersions(t, s.db)
	if strings.Join(versions, ",") != strings.Join(want, ",") {
		t.Fatalf("migration versions after second init = %v, want %v", versions, want)
	}
}

func TestInitMigratesExistingSkeletonDatabase(t *testing.T) {
	s, err := Open(t.TempDir() + "/legacy.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.db.Exec(`create table agents (agent_id text primary key, name text not null, registered_at text not null)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`insert into agents(agent_id,name,registered_at) values('agent://legacy.example','legacy','2026-06-28T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}

	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"schema_migrations", "agents", "channels", "messages", "inbox", "receipts", "route_records", "capability_grants", "threads", "artifacts", "message_artifacts"} {
		if !tableExists(t, s.db, table) {
			t.Fatalf("expected migrated legacy DB to include table %s", table)
		}
	}
	var legacyName string
	if err := s.db.QueryRow(`select name from agents where agent_id='agent://legacy.example'`).Scan(&legacyName); err != nil {
		t.Fatal(err)
	}
	if legacyName != "legacy" {
		t.Fatalf("legacy agent name = %q, want legacy", legacyName)
	}
}

func mustRegister(t *testing.T, s *Store, id string) {
	t.Helper()
	if _, err := s.RegisterAgent(id, ""); err != nil {
		t.Fatal(err)
	}
}

func stages(receipts []Receipt) []string {
	out := make([]string, 0, len(receipts))
	for _, r := range receipts {
		out = append(out, r.Stage)
	}
	return out
}

func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var found string
	err := db.QueryRow(`select name from sqlite_master where type='table' and name=?`, name).Scan(&found)
	return err == nil && found == name
}

func appliedMigrationVersions(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`select version from schema_migrations order by version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var versions []string
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			t.Fatal(err)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return versions
}
