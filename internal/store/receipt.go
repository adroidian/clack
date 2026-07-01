package store

import (
	"encoding/json"
	"errors"
	"fmt"
)

type ReceiptRoute struct {
	Kind   string `json:"kind"`
	Target string `json:"target,omitempty"`
	Via    string `json:"via,omitempty"`
}

type ReceiptDocument struct {
	ReceiptVersion string         `json:"receiptVersion"`
	ReceiptID      string         `json:"receiptId"`
	MessageID      string         `json:"messageId"`
	From           string         `json:"from"`
	To             string         `json:"to"`
	Stage          string         `json:"stage"`
	Route          *ReceiptRoute  `json:"route,omitempty"`
	OK             bool           `json:"ok"`
	Reason         *string        `json:"reason"`
	At             string         `json:"at"`
	Proof          map[string]any `json:"proof"`
}

func (r Receipt) Document() (ReceiptDocument, error) {
	proof := map[string]any{}
	if r.Proof != "" {
		if err := json.Unmarshal([]byte(r.Proof), &proof); err != nil {
			return ReceiptDocument{}, fmt.Errorf("decode receipt proof: %w", err)
		}
	}
	var reason *string
	if r.Reason != "" {
		reason = &r.Reason
	}
	doc := ReceiptDocument{
		ReceiptVersion: r.ReceiptVersion,
		ReceiptID:      r.ID,
		MessageID:      r.MessageID,
		From:           r.From,
		To:             r.To,
		Stage:          r.Stage,
		OK:             r.OK,
		Reason:         reason,
		At:             r.At,
		Proof:          proof,
	}
	if kind, ok := proof["routeKind"].(string); ok && kind != "" {
		doc.Route = &ReceiptRoute{Kind: kind, Via: "runtime-proof"}
	}
	return doc, nil
}

func (r Receipt) JSON() ([]byte, error) {
	doc, err := r.Document()
	if err != nil {
		return nil, err
	}
	if err := ValidateReceiptDocument(doc); err != nil {
		return nil, err
	}
	return json.Marshal(doc)
}

func ValidateReceiptDocument(r ReceiptDocument) error {
	if r.ReceiptVersion != receiptVersion {
		return fmt.Errorf("receiptVersion must be %s", receiptVersion)
	}
	if r.ReceiptID == "" {
		return errors.New("receiptId required")
	}
	if r.MessageID == "" {
		return errors.New("messageId required")
	}
	if err := validateAgentID(r.From); err != nil {
		return fmt.Errorf("from: %w", err)
	}
	if err := validateReceiptTarget(r.To); err != nil {
		return fmt.Errorf("to: %w", err)
	}
	if !validReceiptStages[r.Stage] {
		return fmt.Errorf("unknown receipt stage: %s", r.Stage)
	}
	if r.Stage == "failed" {
		if r.OK {
			return errors.New("failed stage must ok=false")
		}
		if r.Reason == nil || *r.Reason == "" {
			return errors.New("failed receipt needs reason")
		}
	} else if !r.OK {
		return errors.New("non-failed receipt stages must ok=true")
	}
	if r.At == "" {
		return errors.New("at required")
	}
	if _, err := parseTime(r.At); err != nil {
		return fmt.Errorf("at must be ISO-8601: %w", err)
	}
	if r.Proof == nil {
		return errors.New("proof must be object")
	}
	if r.Route != nil && !validRouteKinds[r.Route.Kind] {
		return fmt.Errorf("route.kind must be known route kind: %s", r.Route.Kind)
	}
	if r.Stage == "stored" && !hasAnyProof(r.Proof, "inboxPath", "objectId", "deadDropId") {
		return errors.New("stored receipt requires storage proof")
	}
	if r.Stage == "woke" && !hasAnyProof(r.Proof, "wakeLog", "wakeJobId") {
		return errors.New("woke receipt requires wakeLog or wakeJobId")
	}
	return nil
}

var validReceiptStages = map[string]bool{
	"accepted": true, "policy-checked": true, "routed": true, "stored": true,
	"delivered": true, "woke": true, "responded": true, "failed": true,
}

func validateReceiptTarget(target string) error {
	if validateAgentID(target) == nil {
		return nil
	}
	if !channelTargetRe.MatchString(target) {
		return fmt.Errorf("target must be agent://<name>.<owner> or agent://channel.<name>")
	}
	return nil
}

func hasAnyProof(proof map[string]any, keys ...string) bool {
	for _, key := range keys {
		if v, ok := proof[key]; ok && v != nil && v != "" {
			return true
		}
	}
	return false
}
