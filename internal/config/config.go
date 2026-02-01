package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	// Database configuration
	DBPath          string
	DBEncryptionKey string

	// Application encryption
	AppEncryptionKey string

	// Backup configuration
	BackupDir           string
	BackupEncryptionKey string
	BackupInterval      time.Duration
	BackupRetentionDays int

	// Audit configuration
	AuditLogPath   string
	AuditAsyncMode bool

	// Rate limiting
	RateLimitRPS   int
	RateLimitBurst int

	// Application settings
	Environment string
	LogLevel    string
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	// Load .env file if exists (not required in production)
	godotenv.Load()

	config := &Config{
		DBPath:              getEnv("DB_PATH", "./data/secure_notes.db"),
		DBEncryptionKey:     getEnv("DB_ENCRYPTION_KEY", ""),
		AppEncryptionKey:    getEnv("APP_ENCRYPTION_KEY", ""),
		BackupDir:           getEnv("BACKUP_DIR", "./backups"),
		BackupEncryptionKey: getEnv("BACKUP_ENCRYPTION_KEY", ""),
		BackupInterval:      time.Duration(getEnvAsInt("BACKUP_INTERVAL_HOURS", 24)) * time.Hour,
		BackupRetentionDays: getEnvAsInt("BACKUP_RETENTION_DAYS", 30),
		AuditLogPath:        getEnv("AUDIT_LOG_PATH", "./logs/audit.log"),
		AuditAsyncMode:      getEnvAsBool("AUDIT_ASYNC_MODE", true),
		RateLimitRPS:        getEnvAsInt("RATE_LIMIT_REQUESTS_PER_SECOND", 10),
		RateLimitBurst:      getEnvAsInt("RATE_LIMIT_BURST", 20),
		Environment:         getEnv("APP_ENV", "development"),
		LogLevel:            getEnv("LOG_LEVEL", "info"),
	}

	// Validate critical configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// Validate ensures all required configuration is present
func (c *Config) Validate() error {
	if c.DBEncryptionKey == "" {
		return fmt.Errorf("DB_ENCRYPTION_KEY is required")
	}

	if len(c.DBEncryptionKey) < 32 {
		return fmt.Errorf("DB_ENCRYPTION_KEY must be at least 32 characters")
	}

	if c.AppEncryptionKey == "" {
		return fmt.Errorf("APP_ENCRYPTION_KEY is required")
	}

	if len(c.AppEncryptionKey) < 32 {
		return fmt.Errorf("APP_ENCRYPTION_KEY must be at least 32 characters")
	}

	if c.BackupEncryptionKey == "" {
		return fmt.Errorf("BACKUP_ENCRYPTION_KEY is required")
	}

	return nil
}

// Helper functions to read environment variables
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}

	return value
}

func getEnvAsBool(key string, defaultValue bool) bool {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}

	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		return defaultValue
	}

	return value
}
