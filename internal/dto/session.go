package dto

import "time"

// Session is an opaque server-side session. The cookie the browser
// holds is a random token; only its SHA-256 hash is ever stored here,
// so a leaked database dump can't be replayed as a login (same
// principle as password hashing, applied to session tokens).
type Session struct {
	ID        uint   `gorm:"primaryKey" json:"-"`
	TokenHash string `gorm:"uniqueIndex;not null" json:"-"`
	UserID    uint   `gorm:"index;not null" json:"-"`

	// CSRFSecret backs the double-submit CSRF check: issued once at
	// login, handed to the browser in a readable (non-HttpOnly)
	// cookie, and compared against the X-CSRF-Token header on every
	// mutating request. An attacker who can only ride the session
	// cookie cross-site (the browser attaches it automatically) can't
	// also read this cookie to forge the header.
	CSRFSecret string `gorm:"not null" json:"-"`

	UserAgent string `json:"-"`
	IP        string `json:"-"`

	CreatedAt    time.Time `json:"-"`
	LastSeenAt   time.Time `json:"-"`
	ExpiresAt    time.Time `json:"-"` // absolute ceiling
	IdleExpiresAt time.Time `json:"-"` // rolling idle window, refreshed on use
}

func (Session) TableName() string { return "sessions" }
