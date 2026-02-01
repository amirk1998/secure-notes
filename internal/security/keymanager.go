package security

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

type KeyManager struct {
	dbKey  []byte
	appKey []byte
}

// NewKeyManager creates a new key manager
func NewKeyManager(dbKeyStr, appKeyStr string) (*KeyManager, error) {
	// Derive 32-byte keys from provided strings
	dbKey := deriveKey(dbKeyStr)
	appKey := deriveKey(appKeyStr)

	return &KeyManager{
		dbKey:  dbKey,
		appKey: appKey,
	}, nil
}

// GetDBKey returns the database encryption key
func (km *KeyManager) GetDBKey() string {
	return string(km.dbKey)
}

// GetAppKey returns the application encryption key
func (km *KeyManager) GetAppKey() []byte {
	return km.appKey
}

// deriveKey derives a 32-byte key from a string using SHA-256
func deriveKey(keyStr string) []byte {
	hash := sha256.Sum256([]byte(keyStr))
	return hash[:]
}

// LoadKeyFromEnv loads encryption key from environment variable
func LoadKeyFromEnv(envVar string) (string, error) {
	key := os.Getenv(envVar)
	if key == "" {
		return "", fmt.Errorf("environment variable %s not set", envVar)
	}

	if len(key) < 32 {
		return "", fmt.Errorf("key too short (minimum 32 characters)")
	}

	return key, nil
}

// SecureCompareKeys compares two keys in constant time
func SecureCompareKeys(key1, key2 []byte) bool {
	if len(key1) != len(key2) {
		return false
	}

	hash1 := sha256.Sum256(key1)
	hash2 := sha256.Sum256(key2)

	return hex.EncodeToString(hash1[:]) == hex.EncodeToString(hash2[:])
}
