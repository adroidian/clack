package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestReceiptJSONMatchesSpecShape(t *testing.T) {
	s := openTestStore(t)
	mustRegister(t, s, "agent://zari.example")
	mustRegister(t, s, "agent://vesper.example")

	_, receipts, err := s.SendDM("agent://zari.example", "agent://vesper.example", "ping")
	if err != nil {
		t.Fatal(err)
	}
	for _, receipt := range receipts {
		payload, err := receipt.JSON()
		if err != nil {
			t.Fatalf("receipt %s JSON: %v", receipt.ID, err)
		}
		var doc ReceiptDocument
		if err := json.Unmarshal(payload, &doc); err != nil {
			t.Fatal(err)
		}
		if doc.ReceiptVersion != "1.0-draft" || doc.ReceiptID != receipt.ID || doc.MessageID == "" || doc.From != "agent://zari.example" || doc.To != "agent://vesper.example" || doc.At == "" || doc.Proof == nil {
			t.Fatalf("receipt doc missing spec fields: %+v", doc)
		}
		if err := ValidateReceiptDocument(doc); err != nil {
			t.Fatalf("receipt doc failed validation: %+v err=%v", doc, err)
		}
	}
}

func TestReceiptValidationRejectsSpecViolations(t *testing.T) {
	reason := "route-unreachable"
	valid := ReceiptDocument{
		ReceiptVersion: "1.0-draft",
		ReceiptID:      "rcpt-test",
		MessageID:      "msg-test",
		From:           "agent://zari.example",
		To:             "agent://vesper.example",
		Stage:          "stored",
		OK:             true,
		At:             time.Date(2026, 6, 29, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Proof:          map[string]any{"inboxPath": "sqlite://inbox"},
	}
	if err := ValidateReceiptDocument(valid); err != nil {
		t.Fatal(err)
	}

	bad := valid
	bad.Proof = map[string]any{"routeTier": "store-only"}
	if err := ValidateReceiptDocument(bad); err == nil || !strings.Contains(err.Error(), "stored receipt requires storage proof") {
		t.Fatalf("expected stored proof validation, got %v", err)
	}

	bad = valid
	bad.Stage = "failed"
	bad.OK = true
	if err := ValidateReceiptDocument(bad); err == nil || !strings.Contains(err.Error(), "failed stage") {
		t.Fatalf("expected failed stage validation, got %v", err)
	}

	bad = valid
	bad.OK = false
	bad.Reason = &reason
	if err := ValidateReceiptDocument(bad); err == nil || !strings.Contains(err.Error(), "non-failed receipt stages") {
		t.Fatalf("expected non-failed ok=false validation, got %v", err)
	}

	bad = valid
	bad.Stage = "failed"
	bad.OK = false
	bad.Reason = nil
	if err := ValidateReceiptDocument(bad); err == nil || !strings.Contains(err.Error(), "failed receipt needs reason") {
		t.Fatalf("expected failed reason validation, got %v", err)
	}

	bad = valid
	bad.Stage = "failed"
	bad.OK = false
	bad.Reason = &reason
	bad.Proof = map[string]any{"routeTier": "store-only"}
	if err := ValidateReceiptDocument(bad); err != nil {
		t.Fatalf("expected valid failed receipt, got %v", err)
	}
}

func TestChannelReceiptTargetAllowed(t *testing.T) {
	s := openTestStore(t)
	mustRegister(t, s, "agent://zari.example")
	_, receipts, err := s.PostChannel("ops", "agent://zari.example", "status?")
	if err != nil {
		t.Fatal(err)
	}
	for _, receipt := range receipts {
		if _, err := receipt.JSON(); err != nil {
			t.Fatalf("channel receipt should validate agent://channel target: %+v err=%v", receipt, err)
		}
	}
}
