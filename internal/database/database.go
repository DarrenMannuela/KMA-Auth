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
	db, err := gorm.Open(sqlite.Open(cfg.DBPath+"?_foreign_keys=on"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	if err := db.AutoMigrate(&dto.User{}, &dto.Session{}); err != nil {
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
		Email:              cfg.BootstrapEmail,
		PasswordHash:       hash,
		Name:               "Administrator",
		Role:               "admin",
		Active:             true,
		PasswordChangedAt:  time.Now(),
	}
	if err := db.Create(&admin).Error; err != nil {
		return err
	}
	log.Printf("[auth] bootstrap admin created for %s — log in and change the password immediately.", cfg.BootstrapEmail)
	return nil
}
