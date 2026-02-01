package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// Argon2id parameters (OWASP recommendations)
	argon2Time      = 3
	argon2Memory    = 64 * 1024 // 64 MB
	argon2Threads   = 2
	argon2KeyLength = 32
	saltLength      = 16
)

type PasswordHasher struct {
	time      uint32
	memory    uint32
	threads   uint8
	keyLength uint32
}

func NewPasswordHasher() *PasswordHasher {
	return &PasswordHasher{
		time:      argon2Time,
		memory:    argon2Memory,
		threads:   argon2Threads,
		keyLength: argon2KeyLength,
	}
}

// Hash generates a secure hash from password using Argon2id
func (ph *PasswordHasher) Hash(password string) (string, error) {
	// Generate random salt
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate hash using Argon2id
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		ph.time,
		ph.memory,
		ph.threads,
		ph.keyLength,
	)

	// Encode hash with parameters for verification
	encodedHash := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		ph.memory,
		ph.time,
		ph.threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encodedHash, nil
}

// Verify checks if password matches the hash
func (ph *PasswordHasher) Verify(password, encodedHash string) (bool, error) {
	// Parse the encoded hash
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, fmt.Errorf("invalid hash format")
	}

	// Extract parameters
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("failed to parse version: %w", err)
	}

	if version != argon2.Version {
		return false, fmt.Errorf("incompatible argon2 version")
	}

	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, fmt.Errorf("failed to parse parameters: %w", err)
	}

	// Decode salt
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	// Decode hash
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	// Generate hash from provided password with same parameters
	testHash := argon2.IDKey(
		[]byte(password),
		salt,
		time,
		memory,
		threads,
		uint32(len(hash)),
	)

	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare(hash, testHash) == 1, nil
}
