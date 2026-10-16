package dto

import "time"

// PendingMFA records that a login's password step has already succeeded
// for UserID, and is waiting on a TOTP code (or a recovery code) to
// actually get a session — created at the point Login would otherwise
// have called createSession, and deleted (not just left to expire) the
// moment the matching /totp/login call succeeds or fails. Deliberately
// not a Session: it carries no CSRF secret, isn't accepted by
// RequireSession, and expires in minutes rather than hours, so it can
// only ever be redeemed for the one thing it's for.
type PendingMFA struct {
	ID        uint   `gorm:"primaryKey" json:"-"`
	TokenHash string `gorm:"uniqueIndex;not null" json:"-"`
	UserID    uint   `gorm:"index;not null" json:"-"`

	CreatedAt time.Time `json:"-"`
	ExpiresAt time.Time `json:"-"`
}

func (PendingMFA) TableName() string { return "pending_mfas" }
