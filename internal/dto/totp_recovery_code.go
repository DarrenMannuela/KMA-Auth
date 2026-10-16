package dto

import "time"

// TOTPRecoveryCode is one of a fixed batch of single-use codes handed to
// a user when they enable 2FA, for the case their authenticator device
// is lost or unreachable. Only the SHA-256 hash is ever stored (same
// reasoning as Session.TokenHash) — the plaintext codes are shown to the
// user exactly once, right after Verify, and never persisted or logged.
// UsedAt distinguishes a spent code from a live one without deleting the
// row, so "N of 8 codes remaining" can still be shown accurately.
type TOTPRecoveryCode struct {
	ID       uint   `gorm:"primaryKey" json:"-"`
	UserID   uint   `gorm:"index;not null" json:"-"`
	CodeHash string `gorm:"uniqueIndex;not null" json:"-"`
	UsedAt   *time.Time `json:"-"`

	CreatedAt time.Time `json:"-"`
}

func (TOTPRecoveryCode) TableName() string { return "totp_recovery_codes" }
