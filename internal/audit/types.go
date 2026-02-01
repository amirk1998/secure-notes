package audit

import "time"

type LogLevel string

const (
	LevelInfo     LogLevel = "INFO"
	LevelWarning  LogLevel = "WARNING"
	LevelError    LogLevel = "ERROR"
	LevelCritical LogLevel = "CRITICAL"
)

type Event struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Level     LogLevel  `json:"level"`
	UserID    *int      `json:"user_id,omitempty"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	IPAddress string    `json:"ip_address,omitempty"`
	Success   bool      `json:"success"`
	ErrorMsg  string    `json:"error_msg,omitempty"`
	Metadata  string    `json:"metadata,omitempty"`
}

type QueryFilters struct {
	StartTime *time.Time
	EndTime   *time.Time
	UserID    *int
	Action    string
	Level     LogLevel
	Limit     int
}
