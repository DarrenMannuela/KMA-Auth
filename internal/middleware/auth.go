package middleware

import (
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
			db.Delete(&sess)
			clearSessionCookies(c, cfg)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session expired"})
			return
		}

		var user dto.User
		if err := db.First(&user, sess.UserID).Error; err != nil || !user.Active {
			db.Delete(&sess)
			clearSessionCookies(c, cfg)
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
		db.Save(&sess)

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

func clearSessionCookies(c *gin.Context, cfg config.Config) {
	c.SetCookie(SessionCookieName, "", -1, "/", cfg.CookieDomain, cfg.IsProd, true)
	c.SetCookie(CSRFCookieName, "", -1, "/", cfg.CookieDomain, cfg.IsProd, false)
}
