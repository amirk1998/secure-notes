package errors

import (
	"errors"
	"fmt"
)

// Custom error types for better error handling
var (
	// Authentication errors
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrUnauthorized       = errors.New("unauthorized access")

	// Validation errors
	ErrInvalidInput    = errors.New("invalid input")
	ErrWeakPassword    = errors.New("password does not meet requirements")
	ErrInvalidEmail    = errors.New("invalid email format")
	ErrInvalidUsername = errors.New("invalid username format")

	// Database errors
	ErrDatabaseConnection = errors.New("database connection failed")
	ErrTransactionFailed  = errors.New("transaction failed")
	ErrRecordNotFound     = errors.New("record not found")

	// Encryption errors
	ErrEncryptionFailed = errors.New("encryption failed")
	ErrDecryptionFailed = errors.New("decryption failed")
	ErrInvalidKey       = errors.New("invalid encryption key")

	// Rate limiting errors
	ErrRateLimitExceeded = errors.New("rate limit exceeded")

	// Backup errors
	ErrBackupFailed  = errors.New("backup operation failed")
	ErrRestoreFailed = errors.New("restore operation failed")
)

// AppError wraps errors with additional context
type AppError struct {
	Err     error
	Message string
	Code    int
}

func (e *AppError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Err.Error()
}

func (e *AppError) Unwrap() error {
	return e.Err
}

// NewAppError creates a new application error
func NewAppError(err error, message string, code int) *AppError {
	return &AppError{
		Err:     err,
		Message: message,
		Code:    code,
	}
}
