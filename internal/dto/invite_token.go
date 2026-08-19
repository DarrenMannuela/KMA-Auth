package dto

import "time"

// InviteToken is the one-time "set your password" link an admin-created
// account gets emailed instead of a plaintext temporary password. Same
// principle as Session: the raw token is emailed to the user and never
// stored — only its SHA-256 hash lives here, so a leaked DB dump can't
// be used to claim an outstanding invite (same reasoning as
// Session.TokenHash and User.PasswordHash — see those files' own
// comments).
type InviteToken struct {
	ID        uint   `gorm:"primaryKey" json:"-"`
	TokenHash string `gorm:"uniqueIndex;not null" json:"-"`
	UserID    uint   `gorm:"index;not null" json:"-"`

	CreatedAt time.Time `json:"-"`
	ExpiresAt time.Time `json:"-"`
	// Nil until the invite is actually used to set a password — kept
	// (rather than deleting the row) as the one-line auditable answer
	// to "did this person ever accept their invite, and when" without
	// needing a separate history table. UsedAt is checked separately
	// from ExpiresAt so an already-used link fails with a distinct,
	// slightly more specific outcome than a merely-expired one if this
	// is ever surfaced to an admin (currently AcceptInvite treats both
	// as the same generic failure to the end user — see its own
	// comment for why).
	UsedAt *time.Time `json:"-"`
}

func (InviteToken) TableName() string { return "invite_tokens" }
