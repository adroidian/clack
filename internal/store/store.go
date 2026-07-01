package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const receiptVersion = "1.0-draft"

var (
	agentIDRe       = regexp.MustCompile(`^agent://[a-z0-9][a-z0-9-]*\.[a-z0-9][a-z0-9-]*$`)
	channelTargetRe = regexp.MustCompile(`^agent://channel\.[a-z0-9][a-z0-9-]*$`)
)

type Store struct{ db *sql.DB }

type Agent struct{ AgentID, Name string }
type Message struct{ ID, FromAgent, ToAgent, Body, ChannelName string }
type Receipt struct {
	ReceiptVersion string
	ID             string
	MessageID      string
	From           string
	To             string
	Stage          string
	OK             bool
	Reason         string
	At             string
	Proof          string
}
type InboxItem struct{ ID, AgentID, FromAgent, Body string }
type Channel struct {
	ID   int64
	Name string
}

type receiptWriter interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Init() error { return s.applyMigrations() }

func (s *Store) RegisterAgent(agentID, name string) (Agent, error) {
	if err := validateAgentID(agentID); err != nil {
		return Agent{}, err
	}
	if name == "" {
		name = shortName(agentID)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`insert into agents(agent_id,name,registered_at) values(?,?,?) on conflict(agent_id) do update set name=excluded.name`, agentID, name, now)
	return Agent{AgentID: agentID, Name: name}, err
}

func (s *Store) SendDM(from, to, body string) (Message, []Receipt, error) {
	if err := validateAgentID(from); err != nil {
		return Message{}, nil, err
	}
	if err := validateAgentID(to); err != nil {
		return Message{}, nil, err
	}
	if err := s.ensureAgent(from); err != nil {
		return Message{}, nil, err
	}
	if err := s.ensureAgent(to); err != nil {
		return Message{}, nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return Message{}, nil, err
	}
	defer tx.Rollback()

	id := newID("msg")
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.Exec(`insert into messages(id,kind,from_agent,to_agent,body,created_at) values(?,'dm',?,?,?,?)`, id, from, to, body, now); err != nil {
		return Message{}, nil, err
	}
	if _, err := tx.Exec(`insert into inbox(id,agent_id,message_id,from_agent,body,created_at) values(?,?,?,?,?,?)`, newID("inbox"), to, id, from, body, now); err != nil {
		return Message{}, nil, err
	}
	receipts, err := s.receipts(tx, id, from, to, []string{"accepted", "policy-checked", "routed", "stored"})
	if err != nil {
		return Message{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return Message{}, nil, err
	}
	return Message{ID: id, FromAgent: from, ToAgent: to, Body: body}, receipts, nil
}

func (s *Store) CreateChannel(name string) (Channel, error) {
	if name == "" {
		return Channel{}, errors.New("channel name required")
	}
	return createChannel(s.db, name)
}

func createChannel(w receiptWriter, name string) (Channel, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := w.Exec(`insert into channels(name,created_at) values(?,?) on conflict(name) do update set name=excluded.name`, name, now); err != nil {
		return Channel{}, err
	}

	var id int64
	querier, ok := w.(interface {
		QueryRow(query string, args ...any) *sql.Row
	})
	if !ok {
		return Channel{}, errors.New("channel writer cannot query channel id")
	}
	if err := querier.QueryRow(`select id from channels where name=?`, name).Scan(&id); err != nil {
		return Channel{}, err
	}
	return Channel{ID: id, Name: name}, nil
}

func (s *Store) PostChannel(channel, from, body string) (Message, []Receipt, error) {
	if err := validateAgentID(from); err != nil {
		return Message{}, nil, err
	}
	if err := s.ensureAgent(from); err != nil {
		return Message{}, nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return Message{}, nil, err
	}
	defer tx.Rollback()

	if _, err := createChannel(tx, channel); err != nil {
		return Message{}, nil, err
	}
	id := newID("msg")
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.Exec(`insert into messages(id,kind,from_agent,channel_name,body,created_at) values(?,'channel',?,?,?,?)`, id, from, channel, body, now); err != nil {
		return Message{}, nil, err
	}
	to := "agent://channel." + channel
	receipts, err := s.receipts(tx, id, from, to, []string{"accepted", "stored"})
	if err != nil {
		return Message{}, nil, err
	}
	if err := tx.Commit(); err != nil {
		return Message{}, nil, err
	}
	return Message{ID: id, FromAgent: from, ChannelName: channel, Body: body}, receipts, nil
}

func (s *Store) ListInbox(agentID string) ([]InboxItem, error) {
	rows, err := s.db.Query(`select id,agent_id,from_agent,body from inbox where agent_id=? order by created_at,id`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InboxItem
	for rows.Next() {
		var it InboxItem
		if err := rows.Scan(&it.ID, &it.AgentID, &it.FromAgent, &it.Body); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

func (s *Store) ListReceipts() ([]Receipt, error) {
	rows, err := s.db.Query(`select id,message_id,from_agent,to_agent,stage,ok,coalesce(reason,''),at,proof_json from receipts order by at,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Receipt
	for rows.Next() {
		var r Receipt
		r.ReceiptVersion = receiptVersion
		if err := rows.Scan(&r.ID, &r.MessageID, &r.From, &r.To, &r.Stage, &r.OK, &r.Reason, &r.At, &r.Proof); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) ensureAgent(agentID string) error {
	var n int
	if err := s.db.QueryRow(`select count(*) from agents where agent_id=?`, agentID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("unknown agent: %s", agentID)
	}
	return nil
}

func (s *Store) receipts(w receiptWriter, messageID, from, to string, stages []string) ([]Receipt, error) {
	receipts := make([]Receipt, 0, len(stages))
	for _, stage := range stages {
		r, err := s.receipt(w, messageID, from, to, stage, true, "")
		if err != nil {
			return nil, err
		}
		receipts = append(receipts, r)
	}
	return receipts, nil
}

func (s *Store) receipt(w receiptWriter, messageID, from, to, stage string, ok bool, reason string) (Receipt, error) {
	id := newID("rcpt")
	at := time.Now().UTC().Format(time.RFC3339Nano)
	proofFields := map[string]any{"routeTier": "store-only", "localOnly": true}
	switch stage {
	case "policy-checked":
		proofFields["capabilityTier"] = "local-dev"
	case "routed":
		proofFields["routeKind"] = "store-only"
		proofFields["routeSource"] = "local-sqlite"
	case "stored":
		proofFields["inboxPath"] = "sqlite://inbox"
	}
	proof, err := json.Marshal(proofFields)
	if err != nil {
		return Receipt{}, err
	}
	if _, err := w.Exec(`insert into receipts(id,message_id,from_agent,to_agent,stage,ok,reason,at,proof_json) values(?,?,?,?,?,?,?,?,?)`, id, messageID, from, to, stage, ok, nullIfEmpty(reason), at, string(proof)); err != nil {
		return Receipt{}, err
	}
	return Receipt{ReceiptVersion: receiptVersion, ID: id, MessageID: messageID, From: from, To: to, Stage: stage, OK: ok, Reason: reason, At: at, Proof: string(proof)}, nil
}

func validateAgentID(agentID string) error {
	if !agentIDRe.MatchString(agentID) {
		return fmt.Errorf("agentId must match agent://<name>.<owner>")
	}
	return nil
}
func shortName(agentID string) string {
	x := strings.TrimPrefix(agentID, "agent://")
	return strings.Split(x, ".")[0]
}
func newID(prefix string) string { return fmt.Sprintf("%s-%d", prefix, time.Now().UTC().UnixNano()) }
func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
