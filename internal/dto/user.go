package dto

import "time"

// User is the sole identity record this service owns. It deliberately
// knows nothing about orders/clients/etc — the main KMA backend maps
// UserID -> its own permissions/roles as needed.
type User struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	Email        string `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash string `gorm:"not null" json:"-"`
	Name         string `json:"name"`
	Role         string `gorm:"default:staff" json:"role"` // e.g. admin, staff
	Active       bool   `gorm:"default:true" json:"active"`

	// Brute-force tracking lives on the user row (not just per-IP) so a
	// distributed attempt against one account is still caught even if
	// it comes from many different IPs.
	FailedAttempts int        `gorm:"default:0" json:"-"`
	LockedUntil    *time.Time `json:"-"`

	// Bumped on password change / "log out everywhere" — every
	// outstanding session for this user is checked against this value
	// implicitly by being deleted when it's bumped (see AuthHandler).
	PasswordChangedAt time.Time `json:"-"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (User) TableName() string { return "users" }
