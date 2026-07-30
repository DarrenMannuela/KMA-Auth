package handler

import (
	"net/http"
	"time"

	"github.com/DarrenMannuela/KMA-auth/internal/dto"
	"github.com/DarrenMannuela/KMA-auth/internal/util"

	"github.com/gin-gonic/gin"
)

type validateRequest struct {
	// The raw session cookie value, forwarded verbatim by the caller
	// (it never leaves the browser -> main-backend -> auth-service
	// path, and never gets logged — see main.go's logger config).
	Token string `json:"token" binding:"required"`
}

// Validate lets the main KMA backend (a different service, same
// network) ask "is this session cookie currently valid, and who is
// it?" without needing to know how sessions are stored or share this
// service's database. Access to this route is gated by requireInternalKey
// in main.go, not by RequireSession — the caller here is a backend, not
// a browser.
func (h *AuthHandler) Validate(c *gin.Context) {
	var req validateRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token is required"})
		return
	}

	var sess dto.Session
	if err := h.DB.Where("token_hash = ?", util.HashToken(req.Token)).First(&sess).Error; err != nil {
		c.JSON(http.StatusOK, gin.H{"valid": false})
		return
	}

	now := time.Now()
	if now.After(sess.ExpiresAt) || now.After(sess.IdleExpiresAt) {
		c.JSON(http.StatusOK, gin.H{"valid": false})
		return
	}

	var user dto.User
	if err := h.DB.First(&user, sess.UserID).Error; err != nil || !user.Active {
		c.JSON(http.StatusOK, gin.H{"valid": false})
		return
	}

	// Refresh idle window here too, so a user active only via the main
	// backend's API (not calling this service directly) doesn't get
	// silently timed out.
	sess.IdleExpiresAt = now.Add(h.Cfg.SessionIdleTTL)
	if sess.IdleExpiresAt.After(sess.ExpiresAt) {
		sess.IdleExpiresAt = sess.ExpiresAt
	}
	sess.LastSeenAt = now
	h.DB.Save(&sess)

	c.JSON(http.StatusOK, gin.H{
		"valid": true,
		"user":  publicUser(user),
	})
}
