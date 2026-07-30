package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port        string
	IsProd      bool
	DBPath      string
	CookieDomain      string
	AllowedOrigins    []string
	SessionIdleTTL    time.Duration
	SessionAbsoluteTTL time.Duration
	MaxFailedAttempts int
	LockoutDuration   time.Duration
	InternalKey       string
	BootstrapEmail    string
	BootstrapPassword string
}

func mustGetEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func Load() Config {
	env := mustGetEnv("AUTH_ENV", "development")

	origins := mustGetEnv("AUTH_ALLOWED_ORIGINS", "http://localhost:5173")
	originList := strings.Split(origins, ",")
	for i := range originList {
		originList[i] = strings.TrimSpace(originList[i])
	}

	cfg := Config{
		Port:               mustGetEnv("AUTH_PORT", "8001"),
		IsProd:             env == "production",
		DBPath:             mustGetEnv("AUTH_DB_PATH", "./db_data/auth.sqlite"),
		CookieDomain:       os.Getenv("AUTH_COOKIE_DOMAIN"),
		AllowedOrigins:     originList,
		SessionIdleTTL:     time.Duration(envInt("AUTH_SESSION_IDLE_TTL_HOURS", 12)) * time.Hour,
		SessionAbsoluteTTL: time.Duration(envInt("AUTH_SESSION_ABSOLUTE_TTL_HOURS", 168)) * time.Hour,
		MaxFailedAttempts:  envInt("AUTH_MAX_FAILED_ATTEMPTS", 5),
		LockoutDuration:    time.Duration(envInt("AUTH_LOCKOUT_MINUTES", 15)) * time.Minute,
		InternalKey:        os.Getenv("AUTH_INTERNAL_KEY"),
		BootstrapEmail:     os.Getenv("AUTH_BOOTSTRAP_EMAIL"),
		BootstrapPassword:  os.Getenv("AUTH_BOOTSTRAP_PASSWORD"),
	}

	return cfg
}
