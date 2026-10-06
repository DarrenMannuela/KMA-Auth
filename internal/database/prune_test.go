package database

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/DarrenMannuela/KMA-auth/internal/config"
	"github.com/DarrenMannuela/KMA-auth/internal/dto"
)

func TestPruneExpiredKeepsWhatCanStillBeUsed(t *testing.T) {
	db, err := Connect(config.Config{DBPath: filepath.Join(t.TempDir(), "auth.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	hour, monthAndABit := time.Hour, 40*24*time.Hour
	sessions := []dto.Session{
		{TokenHash: "live", UserID: 1, ExpiresAt: now.Add(hour), IdleExpiresAt: now.Add(hour)},
		{TokenHash: "past-absolute", UserID: 1, ExpiresAt: now.Add(-hour), IdleExpiresAt: now.Add(hour)},
		{TokenHash: "past-idle", UserID: 1, ExpiresAt: now.Add(hour), IdleExpiresAt: now.Add(-hour)},
	}
	used := now.Add(-monthAndABit)
	usedRecently := now.Add(-hour)
	invites := []dto.InviteToken{
		{TokenHash: "open", UserID: 2, ExpiresAt: now.Add(hour)},
		{TokenHash: "used-long-ago", UserID: 2, ExpiresAt: now.Add(-monthAndABit), UsedAt: &used},
		{TokenHash: "expired-long-ago", UserID: 2, ExpiresAt: now.Add(-monthAndABit)},
		{TokenHash: "used-today", UserID: 2, ExpiresAt: now.Add(hour), UsedAt: &usedRecently},
	}
	if err := db.Create(&sessions).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&invites).Error; err != nil {
		t.Fatal(err)
	}

	s, i, err := PruneExpired(db)
	if err != nil {
		t.Fatal(err)
	}
	if s != 2 || i != 2 {
		t.Errorf("pruned %d sessions and %d invites, want 2 and 2", s, i)
	}
	var left []string
	db.Model(&dto.Session{}).Pluck("token_hash", &left)
	if len(left) != 1 || left[0] != "live" {
		t.Errorf("sessions left: %v, want [live]", left)
	}
	left = nil
	db.Model(&dto.InviteToken{}).Order("token_hash").Pluck("token_hash", &left)
	if len(left) != 2 || left[0] != "open" || left[1] != "used-today" {
		t.Errorf("invites left: %v, want [open used-today]", left)
	}
}
