package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/amirk1998/secure-notes/internal/audit"
	"github.com/amirk1998/secure-notes/internal/models"
	"github.com/amirk1998/secure-notes/internal/ratelimit"
	"github.com/amirk1998/secure-notes/internal/repository"
	"github.com/amirk1998/secure-notes/internal/security"
	"github.com/amirk1998/secure-notes/pkg/errors"
	"github.com/amirk1998/secure-notes/pkg/validator"
)

const (
	maxFailedLoginAttempts = 5
	accountLockDuration    = 30 * time.Minute
	sessionDuration        = 24 * time.Hour
)

type AuthService struct {
	userRepo    *repository.UserRepository
	hasher      *security.PasswordHasher
	validator   *validator.Validator
	rateLimiter *ratelimit.RateLimiter
	auditLogger *audit.Logger
}

// NewAuthService creates a new authentication service
func NewAuthService(
	userRepo *repository.UserRepository,
	rateLimiter *ratelimit.RateLimiter,
	auditLogger *audit.Logger,
) *AuthService {
	return &AuthService{
		userRepo:    userRepo,
		hasher:      security.NewPasswordHasher(),
		validator:   validator.New(),
		rateLimiter: rateLimiter,
		auditLogger: auditLogger,
	}
}

// Register registers a new user
func (s *AuthService) Register(ctx context.Context, req *models.CreateUserRequest) (*models.User, error) {
	// Rate limiting
	if err := s.rateLimiter.CheckLimit("register"); err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelWarning,
			Action:   "REGISTER_RATE_LIMITED",
			Resource: "auth",
			Success:  false,
			ErrorMsg: "rate limit exceeded",
		})
		return nil, err
	}

	// Validate input
	req.Username = s.validator.SanitizeString(req.Username)
	req.Email = s.validator.SanitizeString(req.Email)

	if err := s.validator.ValidateUsername(req.Username); err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelWarning,
			Action:   "REGISTER_INVALID_USERNAME",
			Resource: "auth",
			Success:  false,
			ErrorMsg: err.Error(),
		})
		return nil, err
	}

	if err := s.validator.ValidateEmail(req.Email); err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelWarning,
			Action:   "REGISTER_INVALID_EMAIL",
			Resource: "auth",
			Success:  false,
			ErrorMsg: err.Error(),
		})
		return nil, err
	}

	if err := s.validator.ValidatePassword(req.Password); err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelWarning,
			Action:   "REGISTER_WEAK_PASSWORD",
			Resource: "auth",
			Success:  false,
			ErrorMsg: err.Error(),
		})
		return nil, err
	}

	// Check if user already exists
	if _, err := s.userRepo.GetByUsername(req.Username); err == nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelWarning,
			Action:   "REGISTER_DUPLICATE_USERNAME",
			Resource: "auth",
			Success:  false,
			ErrorMsg: "username already exists",
		})
		return nil, errors.ErrUserAlreadyExists
	}

	// Hash password
	passwordHash, err := s.hasher.Hash(req.Password)
	if err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelError,
			Action:   "REGISTER_HASH_FAILED",
			Resource: "auth",
			Success:  false,
			ErrorMsg: err.Error(),
		})
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &models.User{
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: passwordHash,
	}

	if err := s.userRepo.Create(user); err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelError,
			Action:   "REGISTER_DB_ERROR",
			Resource: "auth",
			Success:  false,
			ErrorMsg: err.Error(),
		})
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Audit log
	s.auditLogger.Log(&audit.Event{
		Level:    audit.LevelInfo,
		UserID:   &user.ID,
		Action:   "REGISTER_SUCCESS",
		Resource: "auth",
		Success:  true,
	})

	return user, nil
}

// Login authenticates a user
func (s *AuthService) Login(ctx context.Context, req *models.LoginRequest) (*models.LoginResponse, error) {
	// Rate limiting per username
	rateLimitKey := fmt.Sprintf("login:%s", req.Username)
	if err := s.rateLimiter.CheckLimit(rateLimitKey); err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelWarning,
			Action:   "LOGIN_RATE_LIMITED",
			Resource: "auth",
			Success:  false,
			ErrorMsg: "rate limit exceeded",
			Metadata: req.Username,
		})
		return nil, err
	}

	// Get user
	user, err := s.userRepo.GetByUsername(req.Username)
	if err != nil {
		// Use constant time to prevent user enumeration
		s.hasher.Verify(req.Password, "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$somehash")

		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelWarning,
			Action:   "LOGIN_USER_NOT_FOUND",
			Resource: "auth",
			Success:  false,
			Metadata: req.Username,
		})
		return nil, errors.ErrInvalidCredentials
	}

	// Check if account is locked
	locked, err := s.userRepo.IsAccountLocked(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to check lock status: %w", err)
	}

	if locked {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelWarning,
			UserID:   &user.ID,
			Action:   "LOGIN_ACCOUNT_LOCKED",
			Resource: "auth",
			Success:  false,
		})
		return nil, fmt.Errorf("account is temporarily locked due to too many failed login attempts")
	}

	// Check if account is active
	if !user.IsActive {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelWarning,
			UserID:   &user.ID,
			Action:   "LOGIN_ACCOUNT_INACTIVE",
			Resource: "auth",
			Success:  false,
		})
		return nil, errors.ErrInvalidCredentials
	}

	// Verify password
	valid, err := s.hasher.Verify(req.Password, user.PasswordHash)
	if err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelError,
			UserID:   &user.ID,
			Action:   "LOGIN_VERIFY_ERROR",
			Resource: "auth",
			Success:  false,
			ErrorMsg: err.Error(),
		})
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	if !valid {
		// Increment failed login attempts
		s.userRepo.IncrementFailedLogins(user.ID)

		// Lock account if too many attempts
		if user.FailedLoginAttempts+1 >= maxFailedLoginAttempts {
			s.userRepo.LockAccount(user.ID, accountLockDuration)

			s.auditLogger.Log(&audit.Event{
				Level:    audit.LevelCritical,
				UserID:   &user.ID,
				Action:   "LOGIN_ACCOUNT_LOCKED_AUTO",
				Resource: "auth",
				Success:  false,
				ErrorMsg: fmt.Sprintf("account locked after %d failed attempts", maxFailedLoginAttempts),
			})
		}

		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelWarning,
			UserID:   &user.ID,
			Action:   "LOGIN_INVALID_PASSWORD",
			Resource: "auth",
			Success:  false,
		})

		return nil, errors.ErrInvalidCredentials
	}

	// Update last login
	if err := s.userRepo.UpdateLastLogin(user.ID); err != nil {
		return nil, fmt.Errorf("failed to update last login: %w", err)
	}

	// Generate session token
	sessionToken, err := s.generateSessionToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session token: %w", err)
	}

	expiresAt := time.Now().Add(sessionDuration)

	// Audit log
	s.auditLogger.Log(&audit.Event{
		Level:    audit.LevelInfo,
		UserID:   &user.ID,
		Action:   "LOGIN_SUCCESS",
		Resource: "auth",
		Success:  true,
	})

	return &models.LoginResponse{
		User:         user,
		SessionToken: sessionToken,
		ExpiresAt:    expiresAt,
	}, nil
}

// generateSessionToken generates a secure random session token
func (s *AuthService) generateSessionToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
