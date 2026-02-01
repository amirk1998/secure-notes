package models

import (
	"time"
)

type User struct {
	ID                  int        `json:"id"`
	Username            string     `json:"username"`
	Email               string     `json:"email"`
	PasswordHash        string     `json:"-"` // Never expose in JSON
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
	LastLogin           *time.Time `json:"last_login,omitempty"`
	IsActive            bool       `json:"is_active"`
	FailedLoginAttempts int        `json:"-"`
	LockedUntil         *time.Time `json:"-"`
}

type CreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	User         *User     `json:"user"`
	SessionToken string    `json:"session_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}
