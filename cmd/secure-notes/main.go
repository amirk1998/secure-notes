package main

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/amirk1998/secure-notes/internal/audit"
	"github.com/amirk1998/secure-notes/internal/backup"
	"github.com/amirk1998/secure-notes/internal/config"
	"github.com/amirk1998/secure-notes/internal/database"
	"github.com/amirk1998/secure-notes/internal/models"
	"github.com/amirk1998/secure-notes/internal/ratelimit"
	"github.com/amirk1998/secure-notes/internal/repository"
	"github.com/amirk1998/secure-notes/internal/security"
	"github.com/amirk1998/secure-notes/internal/service"
)

type Application struct {
	config       *config.Config
	db           *sql.DB
	authService  *service.AuthService
	noteService  *service.NoteService
	auditLogger  *audit.Logger
	auditMonitor *audit.Monitor
	backupMgr    *backup.Manager
	rateLimiter  *ratelimit.RateLimiter
	currentUser  *models.User
}

func main() {
	fmt.Println("===========================================")
	fmt.Println("  Secure Notes - SQLite Security Demo")
	fmt.Println("===========================================")
	fmt.Println()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize application
	app, err := initializeApplication(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}
	defer app.cleanup()

	fmt.Println("[OK] Application initialized successfully")
	fmt.Println("[OK] Database encrypted with SQLCipher")
	fmt.Println("[OK] Audit logging enabled")
	fmt.Println("[OK] Rate limiting active")
	fmt.Println()

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n\n[Shutdown] Received shutdown signal...")
		cancel()
	}()

	// Start automated backups in background
	go app.backupMgr.StartAutomatedBackups(ctx, cfg.BackupInterval)

	// Start rate limiter cleanup worker
	go app.rateLimiter.StartCleanupWorker(ctx, 1*time.Hour)

	// Start security monitoring in background
	go app.startSecurityMonitoring(ctx)

	// Run interactive CLI
	app.runCLI(ctx)
}

// initializeApplication sets up all application components
func initializeApplication(cfg *config.Config) (*Application, error) {
	// Connect to encrypted database
	dbConfig := database.Config{
		Path:          cfg.DBPath,
		EncryptionKey: cfg.DBEncryptionKey,
		MaxOpenConns:  25,
		MaxIdleConns:  5,
		MaxLifetime:   1 * time.Hour,
		MaxIdleTime:   10 * time.Minute,
	}

	db, err := database.Connect(dbConfig)
	if err != nil {
		return nil, fmt.Errorf("database connection failed: %w", err)
	}

	// Run migrations
	if err := database.Migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	// Initialize audit logger
	auditLogger, err := audit.NewLogger(db, cfg.AuditLogPath, cfg.AuditAsyncMode)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize audit logger: %w", err)
	}

	// Initialize security monitor
	auditMonitor := audit.NewMonitor(auditLogger)

	// Initialize rate limiter
	rateLimiter := ratelimit.NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst)

	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	noteRepo := repository.NewNoteRepository(db)

	// Initialize field encryptor for notes
	keyManager, err := security.NewKeyManager(cfg.DBEncryptionKey, cfg.AppEncryptionKey)
	if err != nil {
		db.Close()
		auditLogger.Close()
		return nil, fmt.Errorf("failed to initialize key manager: %w", err)
	}

	fieldEncryptor, err := security.NewFieldEncryptor(keyManager.GetAppKey())
	if err != nil {
		db.Close()
		auditLogger.Close()
		return nil, fmt.Errorf("failed to initialize field encryptor: %w", err)
	}

	// Initialize services
	authService := service.NewAuthService(userRepo, rateLimiter, auditLogger)
	noteService := service.NewNoteService(noteRepo, fieldEncryptor, rateLimiter, auditLogger)

	// Initialize backup manager
	backupMgr, err := backup.NewManager(db, cfg.BackupDir, cfg.BackupEncryptionKey, cfg.BackupRetentionDays)
	if err != nil {
		db.Close()
		auditLogger.Close()
		return nil, fmt.Errorf("failed to initialize backup manager: %w", err)
	}

	return &Application{
		config:       cfg,
		db:           db,
		authService:  authService,
		noteService:  noteService,
		auditLogger:  auditLogger,
		auditMonitor: auditMonitor,
		backupMgr:    backupMgr,
		rateLimiter:  rateLimiter,
	}, nil
}

// cleanup performs cleanup operations
func (app *Application) cleanup() {
	fmt.Println("\n[Cleanup] Shutting down gracefully...")

	if app.auditLogger != nil {
		app.auditLogger.Close()
	}

	if app.db != nil {
		app.db.Close()
	}

	fmt.Println("[Cleanup] Done")
}

// startSecurityMonitoring runs security monitoring in background
func (app *Application) startSecurityMonitoring(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := app.auditMonitor.DetectSuspiciousActivity(); err != nil {
				log.Printf("[Security] Monitoring error: %v", err)
			}
		}
	}
}

// runCLI runs the interactive command-line interface
func (app *Application) runCLI(ctx context.Context) {
	scanner := bufio.NewScanner(os.Stdin)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			if app.currentUser == nil {
				app.showAuthMenu()
			} else {
				app.showMainMenu()
			}

			fmt.Print("\nSelect option: ")
			if !scanner.Scan() {
				return
			}

			choice := strings.TrimSpace(scanner.Text())
			fmt.Println()

			if app.currentUser == nil {
				app.handleAuthChoice(ctx, choice, scanner)
			} else {
				app.handleMainChoice(ctx, choice, scanner)
			}
		}
	}
}

// showAuthMenu displays authentication menu
func (app *Application) showAuthMenu() {
	fmt.Println("\n--- Authentication Menu ---")
	fmt.Println("1. Register")
	fmt.Println("2. Login")
	fmt.Println("3. Exit")
}

// showMainMenu displays main menu
func (app *Application) showMainMenu() {
	fmt.Printf("\n--- Main Menu (User: %s) ---\n", app.currentUser.Username)
	fmt.Println("1. Create Note")
	fmt.Println("2. List Notes")
	fmt.Println("3. View Note")
	fmt.Println("4. Update Note")
	fmt.Println("5. Delete Note")
	fmt.Println("6. Create Backup")
	fmt.Println("7. View Audit Logs")
	fmt.Println("8. Logout")
	fmt.Println("9. Exit")
}

// handleAuthChoice handles authentication menu choices
func (app *Application) handleAuthChoice(ctx context.Context, choice string, scanner *bufio.Scanner) {
	switch choice {
	case "1":
		app.handleRegister(ctx, scanner)
	case "2":
		app.handleLogin(ctx, scanner)
	case "3":
		fmt.Println("Goodbye!")
		os.Exit(0)
	default:
		fmt.Println("Invalid option")
	}
}

// handleMainChoice handles main menu choices
func (app *Application) handleMainChoice(ctx context.Context, choice string, scanner *bufio.Scanner) {
	switch choice {
	case "1":
		app.handleCreateNote(ctx, scanner)
	case "2":
		app.handleListNotes(ctx)
	case "3":
		app.handleViewNote(ctx, scanner)
	case "4":
		app.handleUpdateNote(ctx, scanner)
	case "5":
		app.handleDeleteNote(ctx, scanner)
	case "6":
		app.handleCreateBackup(ctx)
	case "7":
		app.handleViewAuditLogs(ctx, scanner)
	case "8":
		app.handleLogout(ctx)
	case "9":
		fmt.Println("Goodbye!")
		os.Exit(0)
	default:
		fmt.Println("Invalid option")
	}
}

// handleRegister handles user registration
func (app *Application) handleRegister(ctx context.Context, scanner *bufio.Scanner) {
	fmt.Println("=== User Registration ===")

	fmt.Print("Username: ")
	scanner.Scan()
	username := strings.TrimSpace(scanner.Text())

	fmt.Print("Email: ")
	scanner.Scan()
	email := strings.TrimSpace(scanner.Text())

	fmt.Print("Password: ")
	scanner.Scan()
	password := strings.TrimSpace(scanner.Text())

	req := &models.CreateUserRequest{
		Username: username,
		Email:    email,
		Password: password,
	}

	user, err := app.authService.Register(ctx, req)
	if err != nil {
		fmt.Printf("Registration failed: %v\n", err)
		return
	}

	fmt.Printf("✓ User registered successfully! (ID: %d)\n", user.ID)
}

// handleLogin handles user login
func (app *Application) handleLogin(ctx context.Context, scanner *bufio.Scanner) {
	fmt.Println("=== User Login ===")

	fmt.Print("Username: ")
	scanner.Scan()
	username := strings.TrimSpace(scanner.Text())

	fmt.Print("Password: ")
	scanner.Scan()
	password := strings.TrimSpace(scanner.Text())

	req := &models.LoginRequest{
		Username: username,
		Password: password,
	}

	resp, err := app.authService.Login(ctx, req)
	if err != nil {
		fmt.Printf("Login failed: %v\n", err)
		return
	}

	app.currentUser = resp.User
	fmt.Printf("✓ Login successful! Welcome, %s\n", app.currentUser.Username)
}

// handleLogout handles user logout
func (app *Application) handleLogout(ctx context.Context) {
	fmt.Printf("✓ Goodbye, %s!\n", app.currentUser.Username)
	app.currentUser = nil
}

// handleCreateNote handles note creation
func (app *Application) handleCreateNote(ctx context.Context, scanner *bufio.Scanner) {
	fmt.Println("=== Create New Note ===")

	fmt.Print("Title: ")
	scanner.Scan()
	title := strings.TrimSpace(scanner.Text())

	fmt.Print("Content: ")
	scanner.Scan()
	content := strings.TrimSpace(scanner.Text())

	fmt.Print("Category (optional): ")
	scanner.Scan()
	category := strings.TrimSpace(scanner.Text())

	req := &models.CreateNoteRequest{
		Title:    title,
		Content:  content,
		Category: category,
	}

	note, err := app.noteService.Create(ctx, app.currentUser.ID, req)
	if err != nil {
		fmt.Printf("Failed to create note: %v\n", err)
		return
	}

	fmt.Printf("✓ Note created successfully! (ID: %d)\n", note.ID)
}

// handleListNotes handles listing all notes
func (app *Application) handleListNotes(ctx context.Context) {
	filters := models.NoteListFilters{
		UserID: app.currentUser.ID,
		Limit:  100,
	}

	notes, err := app.noteService.List(ctx, filters)
	if err != nil {
		fmt.Printf("Failed to list notes: %v\n", err)
		return
	}

	if len(notes) == 0 {
		fmt.Println("No notes found")
		return
	}

	fmt.Println("=== Your Notes ===")
	for _, note := range notes {
		fmt.Printf("\n[ID: %d] %s\n", note.ID, note.Title)
		fmt.Printf("Category: %s | Favorite: %v\n", note.Category, note.IsFavorite)
		fmt.Printf("Created: %s\n", note.CreatedAt.Format("2006-01-02 15:04:05"))

		// Show truncated content
		content := note.Content
		if len(content) > 100 {
			content = content[:100] + "..."
		}
		fmt.Printf("Content: %s\n", content)
		fmt.Println("---")
	}
}

// handleViewNote handles viewing a specific note
func (app *Application) handleViewNote(ctx context.Context, scanner *bufio.Scanner) {
	fmt.Print("Enter Note ID: ")
	scanner.Scan()
	idStr := strings.TrimSpace(scanner.Text())

	noteID, err := strconv.Atoi(idStr)
	if err != nil {
		fmt.Println("Invalid note ID")
		return
	}

	note, err := app.noteService.GetByID(ctx, app.currentUser.ID, noteID)
	if err != nil {
		fmt.Printf("Failed to get note: %v\n", err)
		return
	}

	fmt.Println("\n=== Note Details ===")
	fmt.Printf("ID: %d\n", note.ID)
	fmt.Printf("Title: %s\n", note.Title)
	fmt.Printf("Category: %s\n", note.Category)
	fmt.Printf("Favorite: %v\n", note.IsFavorite)
	fmt.Printf("Created: %s\n", note.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Updated: %s\n", note.UpdatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("\nContent:\n%s\n", note.Content)
}

// handleUpdateNote handles updating a note
func (app *Application) handleUpdateNote(ctx context.Context, scanner *bufio.Scanner) {
	fmt.Print("Enter Note ID: ")
	scanner.Scan()
	idStr := strings.TrimSpace(scanner.Text())

	noteID, err := strconv.Atoi(idStr)
	if err != nil {
		fmt.Println("Invalid note ID")
		return
	}

	fmt.Print("New Title (press Enter to skip): ")
	scanner.Scan()
	title := strings.TrimSpace(scanner.Text())

	fmt.Print("New Content (press Enter to skip): ")
	scanner.Scan()
	content := strings.TrimSpace(scanner.Text())

	req := &models.UpdateNoteRequest{}
	if title != "" {
		req.Title = &title
	}
	if content != "" {
		req.Content = &content
	}

	_, err = app.noteService.Update(ctx, app.currentUser.ID, noteID, req)
	if err != nil {
		fmt.Printf("Failed to update note: %v\n", err)
		return
	}

	fmt.Println("✓ Note updated successfully!")
}

// handleDeleteNote handles deleting a note
func (app *Application) handleDeleteNote(ctx context.Context, scanner *bufio.Scanner) {
	fmt.Print("Enter Note ID: ")
	scanner.Scan()
	idStr := strings.TrimSpace(scanner.Text())

	noteID, err := strconv.Atoi(idStr)
	if err != nil {
		fmt.Println("Invalid note ID")
		return
	}

	fmt.Print("Are you sure? (yes/no): ")
	scanner.Scan()
	confirm := strings.ToLower(strings.TrimSpace(scanner.Text()))

	if confirm != "yes" {
		fmt.Println("Cancelled")
		return
	}

	err = app.noteService.Delete(ctx, app.currentUser.ID, noteID)
	if err != nil {
		fmt.Printf("Failed to delete note: %v\n", err)
		return
	}

	fmt.Println("✓ Note deleted successfully!")
}

// handleCreateBackup handles manual backup creation
func (app *Application) handleCreateBackup(ctx context.Context) {
	fmt.Println("Creating encrypted backup...")

	backupPath, err := app.backupMgr.CreateBackup()
	if err != nil {
		fmt.Printf("Backup failed: %v\n", err)
		return
	}

	fmt.Printf("✓ Backup created successfully: %s\n", backupPath)

	// Verify backup
	if err := app.backupMgr.VerifyBackup(backupPath); err != nil {
		fmt.Printf("Warning: Backup verification failed: %v\n", err)
		return
	}

	fmt.Println("✓ Backup verified successfully")
}

// handleViewAuditLogs handles viewing audit logs
func (app *Application) handleViewAuditLogs(ctx context.Context, scanner *bufio.Scanner) {
	fmt.Println("=== Recent Audit Logs ===")

	filters := audit.QueryFilters{
		UserID: &app.currentUser.ID,
		Limit:  20,
	}

	events, err := app.auditLogger.QueryLogs(filters)
	if err != nil {
		fmt.Printf("Failed to query logs: %v\n", err)
		return
	}

	if len(events) == 0 {
		fmt.Println("No audit logs found")
		return
	}

	for _, event := range events {
		fmt.Printf("\n[%s] %s - %s\n",
			event.Timestamp.Format("2006-01-02 15:04:05"),
			event.Level,
			event.Action,
		)
		fmt.Printf("Resource: %s | Success: %v\n", event.Resource, event.Success)
		if event.ErrorMsg != "" {
			fmt.Printf("Error: %s\n", event.ErrorMsg)
		}
		if event.Metadata != "" {
			fmt.Printf("Metadata: %s\n", event.Metadata)
		}
		fmt.Println("---")
	}
}
