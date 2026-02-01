package database

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/mutecomm/go-sqlcipher/v4"
)

type Config struct {
	Path          string
	EncryptionKey string
	MaxOpenConns  int
	MaxIdleConns  int
	MaxLifetime   time.Duration
	MaxIdleTime   time.Duration
}

// Connect establishes a secure connection to SQLite database
func Connect(cfg Config) (*sql.DB, error) {
	// Ensure data directory exists with secure permissions
	dataDir := "./data"
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Build connection string with encryption and secure settings
	dsn := fmt.Sprintf(
		"file:%s?_pragma_key=%s&_pragma_cipher_page_size=4096&_pragma_kdf_iter=256000&_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=ON",
		cfg.Path,
		cfg.EncryptionKey,
	)

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.MaxLifetime)
	db.SetConnMaxIdleTime(cfg.MaxIdleTime)

	// Verify connection and encryption
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to verify database connection: %w", err)
	}

	// Set secure PRAGMA settings
	if err := configureSecurePragmas(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to configure database: %w", err)
	}

	// Set secure file permissions
	if err := os.Chmod(cfg.Path, 0600); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to set file permissions: %w", err)
	}

	return db, nil
}

// configureSecurePragmas sets secure database settings
func configureSecurePragmas(db *sql.DB) error {
	pragmas := []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA secure_delete = ON",
		"PRAGMA synchronous = FULL",
		"PRAGMA auto_vacuum = INCREMENTAL",
		"PRAGMA temp_store = MEMORY",
		"PRAGMA journal_mode = WAL",
	}

	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			return fmt.Errorf("failed to execute %s: %w", pragma, err)
		}
	}

	return nil
}

// GetStats returns database connection pool statistics
func GetStats(db *sql.DB) sql.DBStats {
	return db.Stats()
}
