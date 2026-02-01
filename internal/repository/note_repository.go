package repository

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/amirk1998/secure-notes/internal/models"
	"github.com/amirk1998/secure-notes/pkg/errors"
)

type NoteRepository struct {
	db *sql.DB
}

// NewNoteRepository creates a new note repository
func NewNoteRepository(db *sql.DB) *NoteRepository {
	return &NoteRepository{db: db}
}

// Create creates a new note
func (r *NoteRepository) Create(note *models.Note) error {
	query := `
        INSERT INTO notes (user_id, title, content_encrypted, category, is_favorite, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `

	now := time.Now()
	result, err := r.db.Exec(query,
		note.UserID,
		note.Title,
		note.ContentEncrypted,
		note.Category,
		note.IsFavorite,
		now,
		now,
	)

	if err != nil {
		return fmt.Errorf("failed to create note: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get note ID: %w", err)
	}

	note.ID = int(id)
	note.CreatedAt = now
	note.UpdatedAt = now

	return nil
}

// GetByID retrieves a note by ID
func (r *NoteRepository) GetByID(id int, userID int) (*models.Note, error) {
	query := `
        SELECT id, user_id, title, content_encrypted, category, is_favorite, created_at, updated_at
        FROM notes
        WHERE id = ? AND user_id = ?
    `

	note := &models.Note{}
	err := r.db.QueryRow(query, id, userID).Scan(
		&note.ID,
		&note.UserID,
		&note.Title,
		&note.ContentEncrypted,
		&note.Category,
		&note.IsFavorite,
		&note.CreatedAt,
		&note.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.ErrRecordNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get note: %w", err)
	}

	return note, nil
}

// List retrieves notes with filters
func (r *NoteRepository) List(filters models.NoteListFilters) ([]*models.Note, error) {
	query := `
        SELECT id, user_id, title, content_encrypted, category, is_favorite, created_at, updated_at
        FROM notes
        WHERE user_id = ?
    `

	args := []interface{}{filters.UserID}

	if filters.Category != "" {
		query += " AND category = ?"
		args = append(args, filters.Category)
	}

	if filters.IsFavorite != nil {
		query += " AND is_favorite = ?"
		args = append(args, *filters.IsFavorite)
	}

	query += " ORDER BY created_at DESC"

	if filters.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filters.Limit)

		if filters.Offset > 0 {
			query += " OFFSET ?"
			args = append(args, filters.Offset)
		}
	}

	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list notes: %w", err)
	}
	defer rows.Close()

	var notes []*models.Note
	for rows.Next() {
		note := &models.Note{}
		err := rows.Scan(
			&note.ID,
			&note.UserID,
			&note.Title,
			&note.ContentEncrypted,
			&note.Category,
			&note.IsFavorite,
			&note.CreatedAt,
			&note.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan note: %w", err)
		}
		notes = append(notes, note)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return notes, nil
}

// Update updates a note
func (r *NoteRepository) Update(note *models.Note) error {
	query := `
        UPDATE notes
        SET title = ?, content_encrypted = ?, category = ?, is_favorite = ?, updated_at = ?
        WHERE id = ? AND user_id = ?
    `

	result, err := r.db.Exec(query,
		note.Title,
		note.ContentEncrypted,
		note.Category,
		note.IsFavorite,
		time.Now(),
		note.ID,
		note.UserID,
	)

	if err != nil {
		return fmt.Errorf("failed to update note: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if rows == 0 {
		return errors.ErrRecordNotFound
	}

	note.UpdatedAt = time.Now()

	return nil
}

// Delete deletes a note
func (r *NoteRepository) Delete(id int, userID int) error {
	query := `
        DELETE FROM notes
        WHERE id = ? AND user_id = ?
    `

	result, err := r.db.Exec(query, id, userID)
	if err != nil {
		return fmt.Errorf("failed to delete note: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get affected rows: %w", err)
	}

	if rows == 0 {
		return errors.ErrRecordNotFound
	}

	return nil
}

// Count returns total number of notes for a user
func (r *NoteRepository) Count(userID int) (int, error) {
	query := `
        SELECT COUNT(*)
        FROM notes
        WHERE user_id = ?
    `

	var count int
	err := r.db.QueryRow(query, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count notes: %w", err)
	}

	return count, nil
}
