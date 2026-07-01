package store

import (
	"embed"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct {
	Version string
	Number  int
	Name    string
	Path    string
	SQL     string
}

const createSchemaMigrationsTable = `
create table if not exists schema_migrations (
  version text primary key,
  name text not null,
  applied_at text not null
);
`

func (s *Store) applyMigrations() error {
	if _, err := s.db.Exec(`pragma foreign_keys=on`); err != nil {
		return fmt.Errorf("enable foreign keys: %w", err)
	}
	if _, err := s.db.Exec(createSchemaMigrationsTable); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	migrations, err := loadMigrations()
	if err != nil {
		return err
	}
	for _, m := range migrations {
		applied, err := s.migrationApplied(m.Version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		if err := s.applyMigration(m); err != nil {
			return err
		}
	}
	return nil
}

func loadMigrations() ([]migration, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("read migrations: %w", err)
	}
	out := make([]migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		name := entry.Name()
		parts := strings.SplitN(strings.TrimSuffix(name, ".sql"), "_", 2)
		if len(parts) != 2 || len(parts[0]) != 3 || parts[1] == "" {
			return nil, fmt.Errorf("migration %q must use zero-padded NNN_name.sql", name)
		}
		number, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("migration %q version must be numeric: %w", name, err)
		}
		path := "migrations/" + name
		sqlBytes, err := migrationFS.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read migration %s: %w", name, err)
		}
		out = append(out, migration{Version: parts[0], Number: number, Name: parts[1], Path: path, SQL: string(sqlBytes)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Number < out[j].Number })
	for i := 1; i < len(out); i++ {
		if out[i].Version == out[i-1].Version {
			return nil, fmt.Errorf("duplicate migration version %s", out[i].Version)
		}
	}
	return out, nil
}

func (s *Store) migrationApplied(version string) (bool, error) {
	var n int
	if err := s.db.QueryRow(`select count(*) from schema_migrations where version=?`, version).Scan(&n); err != nil {
		return false, fmt.Errorf("check migration %s: %w", version, err)
	}
	return n > 0, nil
}

func (s *Store) applyMigration(m migration) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", m.Version, err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(m.SQL); err != nil {
		return fmt.Errorf("apply migration %s %s: %w", m.Version, m.Name, err)
	}
	if _, err := tx.Exec(`insert into schema_migrations(version,name,applied_at) values(?,?,?)`, m.Version, m.Name, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return fmt.Errorf("record migration %s: %w", m.Version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", m.Version, err)
	}
	return nil
}
