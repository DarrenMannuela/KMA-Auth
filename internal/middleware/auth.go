package middleware

import (
	"log"
	"net/http"
	"time"

	"github.com/DarrenMannuela/KMA-auth/internal/config"
	"github.com/DarrenMannuela/KMA-auth/internal/dto"
	"github.com/DarrenMannuela/KMA-auth/internal/util"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const SessionCookieName = "kma_session"
const CSRFCookieName = "kma_csrf"

const ctxUserKey = "auth_user"
const ctxSessionKey = "auth_session"

// RequireSession reads the session cookie, looks up the hashed token,
// and rejects the request if it's missing, expired (idle or
// absolute), or belongs to a deactivated user. On success it refreshes
// the rolling idle window and stores the user + session on the Gin
// context for handlers/CSRF middleware to use.
func RequireSession(db *gorm.DB, cfg config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, err := c.Cookie(SessionCookieName)
		if err != nil || raw == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
			return
		}

		var sess dto.Session
		if err := db.Where("token_hash = ?", util.HashToken(raw)).First(&sess).Error; err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session invalid"})
			return
		}

		now := time.Now()
		if now.After(sess.ExpiresAt) || now.After(sess.IdleExpiresAt) {
			if err := db.Delete(&sess).Error; err != nil {
				log.Printf("[auth] warning: failed to delete expired session %d: %v", sess.ID, err)
			}
			ClearSessionCookies(c, cfg)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session expired"})
			return
		}

		var user dto.User
		if err := db.First(&user, sess.UserID).Error; err != nil || !user.Active {
			if err := db.Delete(&sess).Error; err != nil {
				log.Printf("[auth] warning: failed to delete session %d for invalid/inactive user: %v", sess.ID, err)
			}
			ClearSessionCookies(c, cfg)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session invalid"})
			return
		}

		// Sliding expiry: every authenticated request pushes the idle
		// deadline back out, capped by the absolute expiry set at login.
		sess.IdleExpiresAt = now.Add(cfg.SessionIdleTTL)
		if sess.IdleExpiresAt.After(sess.ExpiresAt) {
			sess.IdleExpiresAt = sess.ExpiresAt
		}
		sess.LastSeenAt = now
		// Best-effort: a failed refresh here just means the idle window
		// doesn't get pushed out this request — the session is still
		// valid against its last-saved expiry, so the request proceeds
		// rather than failing a read because a housekeeping write failed.
		if err := db.Save(&sess).Error; err != nil {
			log.Printf("[auth] warning: failed to refresh session %d idle expiry: %v", sess.ID, err)
		}

		c.Set(ctxUserKey, user)
		c.Set(ctxSessionKey, sess)
		c.Next()
	}
}

// RequireRole gates a route to specific roles. Call after RequireSession.
func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(c *gin.Context) {
		user := CurrentUser(c)
		if user == nil || !allowed[user.Role] {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			return
		}
		c.Next()
	}
}

func CurrentUser(c *gin.Context) *dto.User {
	v, ok := c.Get(ctxUserKey)
	if !ok {
		return nil
	}
	u := v.(dto.User)
	return &u
}

func CurrentSession(c *gin.Context) *dto.Session {
	v, ok := c.Get(ctxSessionKey)
	if !ok {
		return nil
	}
	s := v.(dto.Session)
	return &s
}

// ClearSessionCookies expires both auth cookies. Exported so handlers
// (Logout, LogoutAll, ChangePassword) can reuse the exact same
// attributes this middleware uses when it clears cookies itself,
// rather than each call site re-declaring them and risking drift.
func ClearSessionCookies(c *gin.Context, cfg config.Config) {
	// Explicit on every cookie this service sets/clears — see
	// setSessionCookies in auth_handler.go for why Lax rather than
	// Strict, and for why this must be set before the first SetCookie
	// call in the request (gin applies whatever SameSite was set most
	// recently on the context to every cookie written after it).
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(SessionCookieName, "", -1, "/", cfg.CookieDomain, cfg.IsProd, true)
	c.SetCookie(CSRFCookieName, "", -1, "/", cfg.CookieDomain, cfg.IsProd, false)
}
