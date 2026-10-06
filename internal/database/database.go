package database

import (
	"log"
	"time"

	"github.com/DarrenMannuela/KMA-auth/internal/config"
	"github.com/DarrenMannuela/KMA-auth/internal/dto"
	"github.com/DarrenMannuela/KMA-auth/internal/util"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

// Connect opens the auth service's own sqlite file, runs migrations,
// and — only if the users table is completely empty — seeds a single
// bootstrap admin so a fresh deployment is never locked out. Same
// shape as the main KMA backend's AutoMigrate, kept separate on
// purpose: this service should be deployable/restartable/backed-up
// independently of the business-data database.
func Connect(cfg config.Config) (*gorm.DB, error) {
	// Every API request the main backend gets is checked here
	// (/internal/validate), and each check also writes (it slides the
	// session's idle expiry), so this file sees bursts of concurrent
	// writes: a page load fires five or six at once.
	//   - _journal_mode=WAL lets those checks read while another writes,
	//     instead of readers and the writer blocking each other.
	//   - _busy_timeout=5000 waits up to 5s for the write lock rather
	//     than failing at once with "database is locked".
	//   - _txlock=immediate takes the write lock when a write transaction
	//     starts, so two of them can't both read first and then deadlock
	//     trying to upgrade (SQLite fails one of those at once, without
	//     waiting out the busy timeout).
	// Same reasoning as the main backend's Connect().
	db, err := gorm.Open(sqlite.Open(cfg.DBPath+"?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	if err := db.AutoMigrate(&dto.User{}, &dto.Session{}, &dto.InviteToken{}); err != nil {
		return nil, err
	}

	DB = db

	if err := bootstrapAdmin(db, cfg); err != nil {
		return nil, err
	}

	return db, nil
}

func bootstrapAdmin(db *gorm.DB, cfg config.Config) error {
	var count int64
	if err := db.Model(&dto.User{}).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	if cfg.BootstrapEmail == "" || cfg.BootstrapPassword == "" {
		log.Println("[auth] WARNING: users table is empty and AUTH_BOOTSTRAP_EMAIL/PASSWORD are unset — no admin account was created. Set them and restart, or insert one manually.")
		return nil
	}

	hash, err := util.HashPassword(cfg.BootstrapPassword)
	if err != nil {
		return err
	}
	admin := dto.User{
		Email:             cfg.BootstrapEmail,
		PasswordHash:      hash,
		Name:              "Administrator",
		Role:              "admin",
		Active:            true,
		PasswordChangedAt: time.Now(),
	}
	if err := db.Create(&admin).Error; err != nil {
		return err
	}
	log.Printf("[auth] bootstrap admin created for %s — log in and change the password immediately.", cfg.BootstrapEmail)
	return nil
}

// PruneExpired deletes sessions past either expiry, which can never be
// used again (RequireSession and Validate refuse them, and only remove the
// ones someone happens to present), and invite links used or expired more
// than 30 days ago. Without it, both tables only ever grow.
func PruneExpired(db *gorm.DB) (sessions, invites int64, err error) {
	now := time.Now()
	res := db.Where("expires_at < ? OR idle_expires_at < ?", now, now).Delete(&dto.Session{})
	if res.Error != nil {
		return 0, 0, res.Error
	}
	monthAgo := now.AddDate(0, 0, -30)
	res2 := db.Where("expires_at < ? OR (used_at IS NOT NULL AND used_at < ?)", monthAgo, monthAgo).Delete(&dto.InviteToken{})
	return res.RowsAffected, res2.RowsAffected, res2.Error
}
