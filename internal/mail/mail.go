package mail

// Package mail sends the one transactional email this service needs —
// the "set your password" invite link. Deliberately built on stdlib
// net/smtp rather than a third-party mail library: this is a single
// plain-text email with no attachments/templates/tracking, so pulling
// in a dependency for it would be more surface area than the feature
// warrants. net/smtp.SendMail also handles STARTTLS automatically
// whenever the server advertises it (which smtp.gmail.com:587 does),
// so this doesn't need to hand-roll the TLS upgrade itself.

import (
	"fmt"
	"net/smtp"
	"time"

	"github.com/DarrenMannuela/KMA-auth/internal/config"
)

// SendInviteEmail emails a "set your password" link to a newly created
// user. toName is used only for the email's greeting line — the link
// itself carries no PII, just the opaque token (see CreateUser/
// AcceptInvite in user_handler.go for how that token is generated and
// checked).
func SendInviteEmail(cfg config.Config, toEmail, toName, link string) error {
	if cfg.SMTPUsername == "" || cfg.SMTPAppPassword == "" {
		// Fails loudly rather than silently no-op'ing — a misconfigured
		// SMTP setup should surface as "user creation failed, tell the
		// admin", not as an invite that was quietly never sent and now
		// nobody knows why the new hire can't log in.
		return fmt.Errorf("smtp is not configured (AUTH_SMTP_USERNAME / AUTH_SMTP_APP_PASSWORD missing)")
	}

	subject := "You've been added to KMA — set your password"
	ttlHours := int(cfg.InviteTokenTTL / time.Hour)
	body := fmt.Sprintf(
		"Hi %s,\r\n\r\n"+
			"An administrator has created an account for you on KMA.\r\n\r\n"+
			"Set your password here to finish setting up your account:\r\n%s\r\n\r\n"+
			"This link expires in %d hours and can only be used once. If you weren't expecting this, you can ignore this email.\r\n",
		toName, link, ttlHours,
	)

	// Bare CRLF-joined headers + body, matching the minimal RFC 5322
	// shape net/smtp expects to be handed as-is — SendMail doesn't
	// build headers for you.
	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\r\n%s",
		cfg.SMTPFrom, toEmail, subject, body,
	)

	auth := smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPAppPassword, cfg.SMTPHost)
	addr := cfg.SMTPHost + ":" + cfg.SMTPPort
	return smtp.SendMail(addr, auth, cfg.SMTPUsername, []string{toEmail}, []byte(msg))
}
