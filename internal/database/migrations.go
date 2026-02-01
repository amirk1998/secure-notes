package database

import (
	"database/sql"
	"fmt"
)

// Migrate runs database migrations
func Migrate(db *sql.DB) error {
	// Create users table
	usersSchema := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        is_active BOOLEAN DEFAULT 1,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until DATETIME
    );
    
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);
    `

	if _, err := db.Exec(usersSchema); err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	// Create notes table
	notesSchema := `
    CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        content_encrypted TEXT NOT NULL,
        category TEXT,
        is_favorite BOOLEAN DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    
    CREATE INDEX IF NOT EXISTS idx_notes_user_id ON notes(user_id);
    CREATE INDEX IF NOT EXISTS idx_notes_category ON notes(category);
    CREATE INDEX IF NOT EXISTS idx_notes_created ON notes(created_at);
    `

	if _, err := db.Exec(notesSchema); err != nil {
		return fmt.Errorf("failed to create notes table: %w", err)
	}

	// Create sessions table for tracking active sessions
	sessionsSchema := `
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        session_token TEXT UNIQUE NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        is_active BOOLEAN DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    
    CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token);
    CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(is_active);
    `

	if _, err := db.Exec(sessionsSchema); err != nil {
		return fmt.Errorf("failed to create sessions table: %w", err)
	}

	return nil
}
