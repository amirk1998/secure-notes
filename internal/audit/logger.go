package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

type Logger struct {
	db         *sql.DB
	logFile    *os.File
	asyncMode  bool
	eventQueue chan *Event
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewLogger creates a new audit logger
func NewLogger(db *sql.DB, logFilePath string, asyncMode bool) (*Logger, error) {
	// Initialize audit log table
	schema := `
    CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME NOT NULL,
        level TEXT NOT NULL,
        user_id INTEGER,
        action TEXT NOT NULL,
        resource TEXT NOT NULL,
        ip_address TEXT,
        success BOOLEAN NOT NULL,
        error_msg TEXT,
        metadata TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    );
    
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_log(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
    CREATE INDEX IF NOT EXISTS idx_audit_level ON audit_log(level);
    `

	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to create audit log table: %w", err)
	}

	// Ensure log directory exists
	if err := os.MkdirAll("./logs", 0700); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file
	logFile, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	logger := &Logger{
		db:        db,
		logFile:   logFile,
		asyncMode: asyncMode,
		ctx:       ctx,
		cancel:    cancel,
	}

	if asyncMode {
		logger.eventQueue = make(chan *Event, 1000)
		logger.startAsyncLogger()
	}

	return logger, nil
}

// Log logs an audit event
func (al *Logger) Log(event *Event) error {
	event.Timestamp = time.Now()

	if al.asyncMode {
		select {
		case al.eventQueue <- event:
			return nil
		default:
			return fmt.Errorf("audit log queue is full")
		}
	}

	return al.writeEvent(event)
}

// writeEvent writes event to database and file
func (al *Logger) writeEvent(event *Event) error {
	// Write to database
	query := `
        INSERT INTO audit_log (
            timestamp, level, user_id, action, resource,
            ip_address, success, error_msg, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `

	result, err := al.db.Exec(query,
		event.Timestamp,
		event.Level,
		event.UserID,
		event.Action,
		event.Resource,
		event.IPAddress,
		event.Success,
		event.ErrorMsg,
		event.Metadata,
	)

	if err != nil {
		log.Printf("Failed to write audit log to database: %v", err)
		// Continue to write to file even if DB write fails
	} else {
		event.ID, _ = result.LastInsertId()
	}

	// Write to file (JSON format)
	jsonData, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	if _, err := al.logFile.Write(append(jsonData, '\n')); err != nil {
		return fmt.Errorf("failed to write to log file: %w", err)
	}

	return nil
}

// startAsyncLogger starts async logging worker
func (al *Logger) startAsyncLogger() {
	al.wg.Add(1)
	go func() {
		defer al.wg.Done()
		for {
			select {
			case event := <-al.eventQueue:
				if err := al.writeEvent(event); err != nil {
					log.Printf("Failed to write audit event: %v", err)
				}
			case <-al.ctx.Done():
				// Drain remaining events
				for len(al.eventQueue) > 0 {
					event := <-al.eventQueue
					al.writeEvent(event)
				}
				return
			}
		}
	}()
}

// QueryLogs queries audit logs with filters
func (al *Logger) QueryLogs(filters QueryFilters) ([]*Event, error) {
	query := `
        SELECT id, timestamp, level, user_id, action, resource,
               ip_address, success, error_msg, metadata
        FROM audit_log
        WHERE 1=1
    `

	args := []interface{}{}

	if filters.StartTime != nil {
		query += " AND timestamp >= ?"
		args = append(args, filters.StartTime)
	}

	if filters.EndTime != nil {
		query += " AND timestamp <= ?"
		args = append(args, filters.EndTime)
	}

	if filters.UserID != nil {
		query += " AND user_id = ?"
		args = append(args, filters.UserID)
	}

	if filters.Action != "" {
		query += " AND action = ?"
		args = append(args, filters.Action)
	}

	if filters.Level != "" {
		query += " AND level = ?"
		args = append(args, filters.Level)
	}

	query += " ORDER BY timestamp DESC LIMIT ?"
	if filters.Limit <= 0 {
		filters.Limit = 100
	}
	args = append(args, filters.Limit)

	rows, err := al.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit logs: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		event := &Event{}
		err := rows.Scan(
			&event.ID,
			&event.Timestamp,
			&event.Level,
			&event.UserID,
			&event.Action,
			&event.Resource,
			&event.IPAddress,
			&event.Success,
			&event.ErrorMsg,
			&event.Metadata,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}
		events = append(events, event)
	}

	return events, nil
}

// Close closes the audit logger
func (al *Logger) Close() error {
	if al.asyncMode {
		al.cancel()
		al.wg.Wait()
		close(al.eventQueue)
	}

	return al.logFile.Close()
}
