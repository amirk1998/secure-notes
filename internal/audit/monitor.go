package audit

import (
	"fmt"
	"log"
	"time"
)

type Monitor struct {
	logger *Logger
}

// NewMonitor creates a new security monitor
func NewMonitor(logger *Logger) *Monitor {
	return &Monitor{
		logger: logger,
	}
}

// DetectFailedLogins detects multiple failed login attempts
func (m *Monitor) DetectFailedLogins() error {
	now := time.Now()
	fiveMinutesAgo := now.Add(-5 * time.Minute)

	filters := QueryFilters{
		StartTime: &fiveMinutesAgo,
		EndTime:   &now,
		Action:    "LOGIN",
		Limit:     1000,
	}

	events, err := m.logger.QueryLogs(filters)
	if err != nil {
		return fmt.Errorf("failed to query audit logs: %w", err)
	}

	// Count failed attempts per user
	failedAttempts := make(map[int]int)

	for _, event := range events {
		if !event.Success && event.UserID != nil {
			failedAttempts[*event.UserID]++
			if failedAttempts[*event.UserID] >= 5 {
				log.Printf("SECURITY ALERT: User %d has %d failed login attempts in last 5 minutes",
					*event.UserID, failedAttempts[*event.UserID])

				// Log critical security event
				m.logger.Log(&Event{
					Level:    LevelCritical,
					UserID:   event.UserID,
					Action:   "FAILED_LOGIN_THRESHOLD",
					Resource: "authentication",
					Success:  false,
					ErrorMsg: fmt.Sprintf("%d failed attempts detected", failedAttempts[*event.UserID]),
				})
			}
		}
	}

	return nil
}

// DetectSuspiciousActivity runs all security checks
func (m *Monitor) DetectSuspiciousActivity() error {
	if err := m.DetectFailedLogins(); err != nil {
		log.Printf("Failed to detect failed logins: %v", err)
	}

	// Additional security checks can be added here

	return nil
}
