// Package migrations runs Lancert's embedded SQLite migrations.
package migrations

import (
	"database/sql"
	"embed"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed registration/*.sql metrics/*.sql
var files embed.FS

// RunRegistration applies all pending registration database migrations.
func RunRegistration(db *sql.DB) error {
	return run(db, "registration")
}

// RunMetrics applies all pending metrics database migrations.
func RunMetrics(db *sql.DB) error {
	return run(db, "metrics")
}

func run(db *sql.DB, directory string) error {
	driver, err := sqlite.WithInstance(db, &sqlite.Config{})
	if err != nil {
		return fmt.Errorf("create database driver: %w", err)
	}
	source, err := iofs.New(files, directory)
	if err != nil {
		return fmt.Errorf("create migration source: %w", err)
	}
	migrator, err := migrate.NewWithInstance("iofs", source, "sqlite3", driver)
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}
	if err := migrator.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}
