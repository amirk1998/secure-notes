package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/amirk1998/secure-notes/internal/models"
	"github.com/amirk1998/secure-notes/pkg/errors"
)

type UserRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create creates a new user
func (r *UserRepository) Create(user *models.User) error {
	query := `
        INSERT INTO users (username, email, password_hash, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
    `

	now := time.Now()
	result, err := r.db.Exec(query,
		user.Username,
		user.Email,
		user.PasswordHash,
		now,
		now,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get user ID: %w", err)
	}

	user.ID = int(id)
	user.CreatedAt = now
	user.UpdatedAt = now
	user.IsActive = true

	return nil
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(id int) (*models.User, error) {
	query := `
        SELECT id, username, email, password_hash, created_at, updated_at,
               last_login, is_active, failed_login_attempts, locked_until
        FROM users
        WHERE id = ?
    `

	user := &models.User{}
	err := r.db.QueryRow(query, id).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLogin,
		&user.IsActive,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
	)

	if err == sql.ErrNoRows {
		return nil, errors.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

// GetByUsername retrieves a user by username
func (r *UserRepository) GetByUsername(username string) (*models.User, error) {
	query := `
        SELECT id, username, email, password_hash, created_at, updated_at,
               last_login, is_active, failed_login_attempts, locked_until
        FROM users
        WHERE username = ?
    `

	user := &models.User{}
	err := r.db.QueryRow(query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastLogin,
		&user.IsActive,
		&user.FailedLoginAttempts,
		&user.LockedUntil,
	)

	if err == sql.ErrNoRows {
		return nil, errors.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

// UpdateLastLogin updates user's last login time
func (r *UserRepository) UpdateLastLogin(userID int) error {
	query := `
        UPDATE users
        SET last_login = ?, failed_login_attempts = 0, locked_until = NULL
        WHERE id = ?
    `

	_, err := r.db.Exec(query, time.Now(), userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// IncrementFailedLogins increments failed login attempts
func (r *UserRepository) IncrementFailedLogins(userID int) error {
	query := `
        UPDATE users
        SET failed_login_attempts = failed_login_attempts + 1
        WHERE id = ?
    `

	_, err := r.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to increment failed logins: %w", err)
	}

	return nil
}

// LockAccount locks user account for specified duration
func (r *UserRepository) LockAccount(userID int, duration time.Duration) error {
	lockedUntil := time.Now().Add(duration)

	query := `
        UPDATE users
        SET locked_until = ?
        WHERE id = ?
    `

	_, err := r.db.Exec(query, lockedUntil, userID)
	if err != nil {
		return fmt.Errorf("failed to lock account: %w", err)
	}

	return nil
}

// IsAccountLocked checks if account is locked
func (r *UserRepository) IsAccountLocked(userID int) (bool, error) {
	query := `
        SELECT locked_until
        FROM users
        WHERE id = ?
    `

	var lockedUntil *time.Time
	err := r.db.QueryRow(query, userID).Scan(&lockedUntil)
	if err != nil {
		return false, fmt.Errorf("failed to check lock status: %w", err)
	}

	if lockedUntil == nil {
		return false, nil
	}

	return time.Now().Before(*lockedUntil), nil
}

// Delete deletes a user (soft delete by setting is_active to false)
func (r *UserRepository) Delete(userID int) error {
	query := `
        UPDATE users
        SET is_active = 0
        WHERE id = ?
    `

	result, err := r.db.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if rows == 0 {
		return errors.ErrUserNotFound
	}

	return nil
}
