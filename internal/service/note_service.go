package service

import (
	"context"
	"fmt"

	"github.com/amirk1998/secure-notes/internal/audit"
	"github.com/amirk1998/secure-notes/internal/models"
	"github.com/amirk1998/secure-notes/internal/ratelimit"
	"github.com/amirk1998/secure-notes/internal/repository"
	"github.com/amirk1998/secure-notes/internal/security"
	"github.com/amirk1998/secure-notes/pkg/validator"
)

type NoteService struct {
	noteRepo    *repository.NoteRepository
	encryptor   *security.FieldEncryptor
	validator   *validator.Validator
	rateLimiter *ratelimit.RateLimiter
	auditLogger *audit.Logger
}

// NewNoteService creates a new note service
func NewNoteService(
	noteRepo *repository.NoteRepository,
	encryptor *security.FieldEncryptor,
	rateLimiter *ratelimit.RateLimiter,
	auditLogger *audit.Logger,
) *NoteService {
	return &NoteService{
		noteRepo:    noteRepo,
		encryptor:   encryptor,
		validator:   validator.New(),
		rateLimiter: rateLimiter,
		auditLogger: auditLogger,
	}
}

// Create creates a new note
func (s *NoteService) Create(ctx context.Context, userID int, req *models.CreateNoteRequest) (*models.Note, error) {
	// Rate limiting
	rateLimitKey := fmt.Sprintf("note_create:%d", userID)
	if err := s.rateLimiter.CheckLimit(rateLimitKey); err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelWarning,
			UserID:   &userID,
			Action:   "NOTE_CREATE_RATE_LIMITED",
			Resource: "notes",
			Success:  false,
		})
		return nil, err
	}

	// Validate input
	req.Title = s.validator.SanitizeString(req.Title)

	if err := s.validator.ValidateNoteTitle(req.Title); err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelWarning,
			UserID:   &userID,
			Action:   "NOTE_CREATE_INVALID_TITLE",
			Resource: "notes",
			Success:  false,
			ErrorMsg: err.Error(),
		})
		return nil, err
	}

	if err := s.validator.ValidateNoteContent(req.Content); err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelWarning,
			UserID:   &userID,
			Action:   "NOTE_CREATE_INVALID_CONTENT",
			Resource: "notes",
			Success:  false,
			ErrorMsg: err.Error(),
		})
		return nil, err
	}

	// Encrypt content
	encryptedContent, err := s.encryptor.Encrypt(req.Content)
	if err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelError,
			UserID:   &userID,
			Action:   "NOTE_CREATE_ENCRYPTION_FAILED",
			Resource: "notes",
			Success:  false,
			ErrorMsg: err.Error(),
		})
		return nil, fmt.Errorf("failed to encrypt content: %w", err)
	}

	// Create note
	note := &models.Note{
		UserID:           userID,
		Title:            req.Title,
		ContentEncrypted: encryptedContent,
		Category:         req.Category,
		IsFavorite:       req.IsFavorite,
	}

	if err := s.noteRepo.Create(note); err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelError,
			UserID:   &userID,
			Action:   "NOTE_CREATE_DB_ERROR",
			Resource: "notes",
			Success:  false,
			ErrorMsg: err.Error(),
		})
		return nil, fmt.Errorf("failed to create note: %w", err)
	}

	// Decrypt for response
	note.Content = req.Content

	// Audit log
	s.auditLogger.Log(&audit.Event{
		Level:    audit.LevelInfo,
		UserID:   &userID,
		Action:   "NOTE_CREATED",
		Resource: "notes",
		Success:  true,
		Metadata: fmt.Sprintf("note_id=%d", note.ID),
	})

	return note, nil
}

// GetByID retrieves a note by ID
func (s *NoteService) GetByID(ctx context.Context, userID int, noteID int) (*models.Note, error) {
	// Rate limiting
	rateLimitKey := fmt.Sprintf("note_get:%d", userID)
	if err := s.rateLimiter.CheckLimit(rateLimitKey); err != nil {
		return nil, err
	}

	// Get note
	note, err := s.noteRepo.GetByID(noteID, userID)
	if err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelWarning,
			UserID:   &userID,
			Action:   "NOTE_GET_FAILED",
			Resource: "notes",
			Success:  false,
			ErrorMsg: err.Error(),
			Metadata: fmt.Sprintf("note_id=%d", noteID),
		})
		return nil, err
	}

	// Decrypt content
	decryptedContent, err := s.encryptor.Decrypt(note.ContentEncrypted)
	if err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelError,
			UserID:   &userID,
			Action:   "NOTE_DECRYPTION_FAILED",
			Resource: "notes",
			Success:  false,
			ErrorMsg: err.Error(),
			Metadata: fmt.Sprintf("note_id=%d", noteID),
		})
		return nil, fmt.Errorf("failed to decrypt content: %w", err)
	}

	note.Content = decryptedContent

	// Audit log
	s.auditLogger.Log(&audit.Event{
		Level:    audit.LevelInfo,
		UserID:   &userID,
		Action:   "NOTE_ACCESSED",
		Resource: "notes",
		Success:  true,
		Metadata: fmt.Sprintf("note_id=%d", noteID),
	})

	return note, nil
}

// List retrieves all notes for a user
func (s *NoteService) List(ctx context.Context, filters models.NoteListFilters) ([]*models.Note, error) {
	// Rate limiting
	rateLimitKey := fmt.Sprintf("note_list:%d", filters.UserID)
	if err := s.rateLimiter.CheckLimit(rateLimitKey); err != nil {
		return nil, err
	}

	// Get notes
	notes, err := s.noteRepo.List(filters)
	if err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelError,
			UserID:   &filters.UserID,
			Action:   "NOTE_LIST_FAILED",
			Resource: "notes",
			Success:  false,
			ErrorMsg: err.Error(),
		})
		return nil, err
	}

	// Decrypt content for all notes
	for _, note := range notes {
		decryptedContent, err := s.encryptor.Decrypt(note.ContentEncrypted)
		if err != nil {
			// Log error but continue with other notes
			s.auditLogger.Log(&audit.Event{
				Level:    audit.LevelError,
				UserID:   &filters.UserID,
				Action:   "NOTE_DECRYPTION_FAILED",
				Resource: "notes",
				Success:  false,
				ErrorMsg: err.Error(),
				Metadata: fmt.Sprintf("note_id=%d", note.ID),
			})
			continue
		}
		note.Content = decryptedContent
	}

	// Audit log
	s.auditLogger.Log(&audit.Event{
		Level:    audit.LevelInfo,
		UserID:   &filters.UserID,
		Action:   "NOTE_LIST_ACCESSED",
		Resource: "notes",
		Success:  true,
		Metadata: fmt.Sprintf("count=%d", len(notes)),
	})

	return notes, nil
}

// Update updates a note
func (s *NoteService) Update(ctx context.Context, userID int, noteID int, req *models.UpdateNoteRequest) (*models.Note, error) {
	// Rate limiting
	rateLimitKey := fmt.Sprintf("note_update:%d", userID)
	if err := s.rateLimiter.CheckLimit(rateLimitKey); err != nil {
		return nil, err
	}

	// Get existing note
	note, err := s.noteRepo.GetByID(noteID, userID)
	if err != nil {
		return nil, err
	}

	// Update fields
	if req.Title != nil {
		*req.Title = s.validator.SanitizeString(*req.Title)
		if err := s.validator.ValidateNoteTitle(*req.Title); err != nil {
			return nil, err
		}
		note.Title = *req.Title
	}

	if req.Content != nil {
		if err := s.validator.ValidateNoteContent(*req.Content); err != nil {
			return nil, err
		}

		encryptedContent, err := s.encryptor.Encrypt(*req.Content)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt content: %w", err)
		}
		note.ContentEncrypted = encryptedContent
	}

	if req.Category != nil {
		note.Category = *req.Category
	}

	if req.IsFavorite != nil {
		note.IsFavorite = *req.IsFavorite
	}

	// Update in database
	if err := s.noteRepo.Update(note); err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelError,
			UserID:   &userID,
			Action:   "NOTE_UPDATE_FAILED",
			Resource: "notes",
			Success:  false,
			ErrorMsg: err.Error(),
			Metadata: fmt.Sprintf("note_id=%d", noteID),
		})
		return nil, err
	}

	// Decrypt content for response
	if req.Content != nil {
		note.Content = *req.Content
	} else {
		decryptedContent, _ := s.encryptor.Decrypt(note.ContentEncrypted)
		note.Content = decryptedContent
	}

	// Audit log
	s.auditLogger.Log(&audit.Event{
		Level:    audit.LevelInfo,
		UserID:   &userID,
		Action:   "NOTE_UPDATED",
		Resource: "notes",
		Success:  true,
		Metadata: fmt.Sprintf("note_id=%d", noteID),
	})

	return note, nil
}

// Delete deletes a note
func (s *NoteService) Delete(ctx context.Context, userID int, noteID int) error {
	// Rate limiting
	rateLimitKey := fmt.Sprintf("note_delete:%d", userID)
	if err := s.rateLimiter.CheckLimit(rateLimitKey); err != nil {
		return err
	}

	// Delete note
	if err := s.noteRepo.Delete(noteID, userID); err != nil {
		s.auditLogger.Log(&audit.Event{
			Level:    audit.LevelError,
			UserID:   &userID,
			Action:   "NOTE_DELETE_FAILED",
			Resource: "notes",
			Success:  false,
			ErrorMsg: err.Error(),
			Metadata: fmt.Sprintf("note_id=%d", noteID),
		})
		return err
	}

	// Audit log
	s.auditLogger.Log(&audit.Event{
		Level:    audit.LevelInfo,
		UserID:   &userID,
		Action:   "NOTE_DELETED",
		Resource: "notes",
		Success:  true,
		Metadata: fmt.Sprintf("note_id=%d", noteID),
	})

	return nil
}
