package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port               string
	IsProd             bool
	DBPath             string
	CookieDomain       string
	AllowedOrigins     []string
	SessionIdleTTL     time.Duration
	SessionAbsoluteTTL time.Duration
	MaxFailedAttempts  int
	LockoutDuration    time.Duration
	InternalKey        string
	BootstrapEmail     string
	BootstrapPassword  string

	// ── Invite email (Gmail SMTP) ──────────────────────────────────────
	// Used by CreateUser to send a "set your password" link instead of
	// an admin having to hand a temp password to the new hire directly.
	// SMTPAppPassword is a Gmail "App Password" (requires 2-Step
	// Verification on the sending account) — NOT the account's normal
	// login password; Gmail rejects SMTP auth with the real password
	// once 2FA is on, which is the whole reason app passwords exist.
	SMTPHost        string
	SMTPPort        string
	SMTPUsername    string
	SMTPAppPassword string
	// Address (and optionally "Display Name <addr>") invite emails are
	// sent from. Usually the same as SMTPUsername, but kept separate in
	// case the sending account and the visible From address ever differ.
	SMTPFrom string

	// AppBaseURL is the frontend's own origin (e.g.
	// "https://kma.example.com") — needed to build an absolute
	// "…/set-password?token=…" link inside the email body, since a
	// relative path means nothing outside a browser tab already on the
	// site.
	AppBaseURL string

	// How long a "set your password" link stays valid before the admin
	// has to create a fresh one. Short enough that a stale, unused
	// invite isn't sitting around indefinitely as a standing way into
	// the account; long enough that "I'll get to it after lunch" doesn't
	// force a resend.
	InviteTokenTTL time.Duration
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
		Port:           mustGetEnv("AUTH_PORT", "8001"),
		IsProd:         env == "production",
		DBPath:         mustGetEnv("AUTH_DB_PATH", "./db_data/auth.sqlite"),
		CookieDomain:   os.Getenv("AUTH_COOKIE_DOMAIN"),
		AllowedOrigins: originList,
		// Idle TTL still exists as its own knob (kicks someone out sooner
		// if they go quiet), but with the absolute ceiling now at 6h,
		// leaving idle at the old 12h default means idle never actually
		// fires first — Validate's own clamp (see internal_handler.go:
		// "if sess.IdleExpiresAt.After(sess.ExpiresAt)") always pulls it
		// back down to match the absolute expiry instead. Left as-is for
		// now since only the hard ceiling was asked for; drop
		// AUTH_SESSION_IDLE_TTL_HOURS below 6 if inactivity should end a
		// session faster than a still-active one hitting the ceiling.
		SessionIdleTTL: time.Duration(envInt("AUTH_SESSION_IDLE_TTL_HOURS", 12)) * time.Hour,
		// Hard ceiling on a session's total lifetime, enforced in
		// Validate/RequireSession regardless of activity — a tab left
		// open and in active use for the whole 6 hours still gets
		// logged out at the 6-hour mark, not just an idle one. Was 168h
		// (7 days), which is far too long for an internal tool handling
		// order/finance data.
		SessionAbsoluteTTL: time.Duration(envInt("AUTH_SESSION_ABSOLUTE_TTL_HOURS", 6)) * time.Hour,
		MaxFailedAttempts:  envInt("AUTH_MAX_FAILED_ATTEMPTS", 5),
		LockoutDuration:    time.Duration(envInt("AUTH_LOCKOUT_MINUTES", 15)) * time.Minute,
		InternalKey:        os.Getenv("AUTH_INTERNAL_KEY"),
		BootstrapEmail:     os.Getenv("AUTH_BOOTSTRAP_EMAIL"),
		BootstrapPassword:  os.Getenv("AUTH_BOOTSTRAP_PASSWORD"),

		SMTPHost:        mustGetEnv("AUTH_SMTP_HOST", "smtp.gmail.com"),
		SMTPPort:        mustGetEnv("AUTH_SMTP_PORT", "587"),
		SMTPUsername:    os.Getenv("AUTH_SMTP_USERNAME"),
		SMTPAppPassword: os.Getenv("AUTH_SMTP_APP_PASSWORD"),
		SMTPFrom:        mustGetEnv("AUTH_SMTP_FROM", os.Getenv("AUTH_SMTP_USERNAME")),
		AppBaseURL:      mustGetEnv("AUTH_APP_BASE_URL", "http://localhost:5173"),
		InviteTokenTTL:  time.Duration(envInt("AUTH_INVITE_TOKEN_TTL_HOURS", 48)) * time.Hour,
	}

	return cfg
}
