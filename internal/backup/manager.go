package backup

import (
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type Manager struct {
	db            *sql.DB
	backupDir     string
	encryptionKey []byte
	retentionDays int
}

// NewManager creates a new backup manager
func NewManager(db *sql.DB, backupDir string, encryptionKey string, retentionDays int) (*Manager, error) {
	// Derive encryption key
	keyHash := sha256.Sum256([]byte(encryptionKey))

	// Ensure backup directory exists with secure permissions
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	return &Manager{
		db:            db,
		backupDir:     backupDir,
		encryptionKey: keyHash[:],
		retentionDays: retentionDays,
	}, nil
}

// CreateBackup creates an encrypted backup
func (m *Manager) CreateBackup() (string, error) {
	timestamp := time.Now().Format("20060102_150405")
	backupFileName := fmt.Sprintf("backup_%s.db", timestamp)
	backupPath := filepath.Join(m.backupDir, backupFileName)

	// Use VACUUM INTO to create backup
	vacuumQuery := fmt.Sprintf("VACUUM INTO '%s'", backupPath)
	if _, err := m.db.Exec(vacuumQuery); err != nil {
		return "", fmt.Errorf("failed to create backup: %w", err)
	}

	// Encrypt and compress the backup
	encryptedPath := backupPath + ".enc.gz"
	if err := m.encryptAndCompressFile(backupPath, encryptedPath); err != nil {
		os.Remove(backupPath)
		return "", fmt.Errorf("failed to encrypt backup: %w", err)
	}

	// Remove unencrypted backup
	os.Remove(backupPath)

	// Set secure file permissions
	if err := os.Chmod(encryptedPath, 0600); err != nil {
		return "", fmt.Errorf("failed to set file permissions: %w", err)
	}

	// Create checksum file
	if err := m.createChecksumFile(encryptedPath); err != nil {
		return "", fmt.Errorf("failed to create checksum: %w", err)
	}

	fmt.Printf("[Backup] Created: %s\n", encryptedPath)
	return encryptedPath, nil
}

// encryptAndCompressFile encrypts and compresses a file
func (m *Manager) encryptAndCompressFile(srcPath, dstPath string) error {
	// Read source file
	plaintext, err := os.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to read source file: %w", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(m.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt data
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Create destination file with compression
	dstFile, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dstFile.Close()

	// Compress encrypted data
	gzWriter := gzip.NewWriter(dstFile)
	defer gzWriter.Close()

	if _, err := gzWriter.Write(ciphertext); err != nil {
		return fmt.Errorf("failed to write compressed data: %w", err)
	}

	return nil
}

// createChecksumFile creates SHA-256 checksum file
func (m *Manager) createChecksumFile(filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	hash := sha256.Sum256(data)
	checksumPath := filePath + ".sha256"

	return os.WriteFile(checksumPath, []byte(fmt.Sprintf("%x", hash)), 0600)
}

// VerifyBackup verifies backup integrity
func (m *Manager) VerifyBackup(backupPath string) error {
	checksumPath := backupPath + ".sha256"

	// Read stored checksum
	storedChecksum, err := os.ReadFile(checksumPath)
	if err != nil {
		return fmt.Errorf("failed to read checksum file: %w", err)
	}

	// Calculate current checksum
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("failed to read backup file: %w", err)
	}

	hash := sha256.Sum256(data)
	currentChecksum := fmt.Sprintf("%x", hash)

	if currentChecksum != string(storedChecksum) {
		return fmt.Errorf("checksum mismatch: backup file may be corrupted")
	}

	return nil
}

// CleanOldBackups removes old backups based on retention policy
func (m *Manager) CleanOldBackups() error {
	cutoffTime := time.Now().AddDate(0, 0, -m.retentionDays)

	entries, err := os.ReadDir(m.backupDir)
	if err != nil {
		return fmt.Errorf("failed to read backup directory: %w", err)
	}

	deletedCount := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Delete old backups
		if info.ModTime().Before(cutoffTime) {
			filePath := filepath.Join(m.backupDir, entry.Name())
			if err := os.Remove(filePath); err != nil {
				fmt.Printf("[Backup] Warning: failed to delete %s: %v\n", filePath, err)
				continue
			}
			deletedCount++
		}
	}

	if deletedCount > 0 {
		fmt.Printf("[Backup] Cleaned %d old backup files\n", deletedCount)
	}

	return nil
}

// StartAutomatedBackups starts automated backup scheduler
func (m *Manager) StartAutomatedBackups(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	fmt.Printf("[Backup] Automated backups started (interval: %v)\n", interval)

	for {
		select {
		case <-ctx.Done():
			fmt.Println("[Backup] Stopping automated backups")
			return
		case <-ticker.C:
			fmt.Println("[Backup] Starting scheduled backup...")
			if _, err := m.CreateBackup(); err != nil {
				fmt.Printf("[Backup] Scheduled backup failed: %v\n", err)
			}

			// Clean old backups
			if err := m.CleanOldBackups(); err != nil {
				fmt.Printf("[Backup] Cleanup failed: %v\n", err)
			}
		}
	}
}
