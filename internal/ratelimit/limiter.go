package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/amirk1998/secure-notes/pkg/errors"
)

type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rps      rate.Limit
	burst    int
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rps int, burst int) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rps:      rate.Limit(rps),
		burst:    burst,
	}
}

// GetLimiter returns a limiter for the given key (user ID, IP, etc.)
func (rl *RateLimiter) GetLimiter(key string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.limiters[key]
	if !exists {
		limiter = rate.NewLimiter(rl.rps, rl.burst)
		rl.limiters[key] = limiter
	}

	return limiter
}

// Allow checks if the request is allowed
func (rl *RateLimiter) Allow(key string) bool {
	limiter := rl.GetLimiter(key)
	return limiter.Allow()
}

// Wait waits until the request is allowed or context is cancelled
func (rl *RateLimiter) Wait(ctx context.Context, key string) error {
	limiter := rl.GetLimiter(key)
	if err := limiter.Wait(ctx); err != nil {
		return fmt.Errorf("rate limit wait failed: %w", err)
	}
	return nil
}

// CheckLimit checks rate limit and returns error if exceeded
func (rl *RateLimiter) CheckLimit(key string) error {
	if !rl.Allow(key) {
		return errors.ErrRateLimitExceeded
	}
	return nil
}

// Cleanup removes old limiters to prevent memory leaks
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Simple cleanup: clear all if map gets too large
	if len(rl.limiters) > 10000 {
		rl.limiters = make(map[string]*rate.Limiter)
	}
}

// StartCleanupWorker starts a background worker to cleanup old limiters
func (rl *RateLimiter) StartCleanupWorker(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.Cleanup()
		}
	}
}
