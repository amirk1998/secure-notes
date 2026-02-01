package validator

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/amirk1998/secure-notes/pkg/errors"
)

var (
	// Username: 3-20 alphanumeric characters and underscores
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`)

	// Email: basic email validation
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

	// SQL injection keywords to block
	sqlKeywords = []string{
		"SELECT", "INSERT", "UPDATE", "DELETE", "DROP",
		"UNION", "WHERE", "OR", "AND", "--", "/*", "*/",
	}
)

type Validator struct{}

func New() *Validator {
	return &Validator{}
}

// ValidateUsername checks if username is valid and safe
func (v *Validator) ValidateUsername(username string) error {
	if len(username) < 3 || len(username) > 20 {
		return errors.ErrInvalidUsername
	}

	if !usernameRegex.MatchString(username) {
		return errors.ErrInvalidUsername
	}

	// Check for SQL injection attempts
	upperUsername := strings.ToUpper(username)
	for _, keyword := range sqlKeywords {
		if strings.Contains(upperUsername, keyword) {
			return errors.ErrInvalidUsername
		}
	}

	return nil
}

// ValidateEmail checks if email format is valid
func (v *Validator) ValidateEmail(email string) error {
	if len(email) == 0 || len(email) > 255 {
		return errors.ErrInvalidEmail
	}

	if !emailRegex.MatchString(email) {
		return errors.ErrInvalidEmail
	}

	return nil
}

// ValidatePassword checks password strength
func (v *Validator) ValidatePassword(password string) error {
	if len(password) < 12 {
		return errors.ErrWeakPassword
	}

	if len(password) > 128 {
		return errors.ErrWeakPassword
	}

	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
		return errors.ErrWeakPassword
	}

	return nil
}

// SanitizeString removes dangerous characters and null bytes
func (v *Validator) SanitizeString(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Trim whitespace
	input = strings.TrimSpace(input)

	return input
}

// ValidateNoteTitle validates note title
func (v *Validator) ValidateNoteTitle(title string) error {
	title = strings.TrimSpace(title)

	if len(title) == 0 {
		return errors.NewAppError(errors.ErrInvalidInput, "title cannot be empty", 400)
	}

	if len(title) > 255 {
		return errors.NewAppError(errors.ErrInvalidInput, "title too long (max 255 characters)", 400)
	}

	return nil
}

// ValidateNoteContent validates note content
func (v *Validator) ValidateNoteContent(content string) error {
	if len(content) > 1048576 { // 1MB max
		return errors.NewAppError(errors.ErrInvalidInput, "content too long (max 1MB)", 400)
	}

	return nil
}
