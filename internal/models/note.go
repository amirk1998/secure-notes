package models

import (
	"time"
)

type Note struct {
	ID               int       `json:"id"`
	UserID           int       `json:"user_id"`
	Title            string    `json:"title"`
	Content          string    `json:"content"` // Decrypted content
	ContentEncrypted string    `json:"-"`       // Never expose encrypted content
	Category         string    `json:"category,omitempty"`
	IsFavorite       bool      `json:"is_favorite"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type CreateNoteRequest struct {
	Title      string `json:"title"`
	Content    string `json:"content"`
	Category   string `json:"category,omitempty"`
	IsFavorite bool   `json:"is_favorite"`
}

type UpdateNoteRequest struct {
	Title      *string `json:"title,omitempty"`
	Content    *string `json:"content,omitempty"`
	Category   *string `json:"category,omitempty"`
	IsFavorite *bool   `json:"is_favorite,omitempty"`
}

type NoteListFilters struct {
	UserID     int
	Category   string
	IsFavorite *bool
	Limit      int
	Offset     int
}
