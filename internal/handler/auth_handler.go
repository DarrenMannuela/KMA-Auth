package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/DarrenMannuela/KMA-auth/internal/config"
	"github.com/DarrenMannuela/KMA-auth/internal/dto"
	mw "github.com/DarrenMannuela/KMA-auth/internal/middleware"
	"github.com/DarrenMannuela/KMA-auth/internal/util"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AuthHandler struct {
	DB  *gorm.DB
	Cfg config.Config
}

func NewAuthHandler(db *gorm.DB, cfg config.Config) *AuthHandler {
	return &AuthHandler{DB: db, Cfg: cfg}
}

type loginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// Login is intentionally generic in its failure responses — "invalid
// email or password" whether the account doesn't exist, is locked, or
// the password is wrong. Distinguishing those in the response lets an
// attacker enumerate valid emails; the account-lock state is only
// ever revealed to the account owner via a successful-auth path
// (there isn't one here on purpose).
func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email and password are required"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))

	var user dto.User
	err := h.DB.Where("email = ?", email).First(&user).Error

	genericFail := func() {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
	}

	if err != nil {
		// Still run bcrypt against a dummy hash so a nonexistent-user
		// response doesn't return measurably faster than a
		// wrong-password one (timing side channel for user enumeration).
		util.CheckPassword("$2a$12$C6UzMDM.H6dfI/f/IKcEeO4X0M.7fmXPTgD3M6X4FGeaP.O1S8jCS", req.Password)
		genericFail()
		return
	}

	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		genericFail()
		return
	}

	if !user.Active || !util.CheckPassword(user.PasswordHash, req.Password) {
		h.registerFailedAttempt(&user)
		genericFail()
		return
	}

	// Success — reset any failure count and issue a fresh session.
	user.FailedAttempts = 0
	user.LockedUntil = nil
	h.DB.Model(&user).Select("FailedAttempts", "LockedUntil").Updates(map[string]interface{}{
		"failed_attempts": 0,
		"locked_until":    nil,
	})

	session, rawToken, err := h.createSession(user.ID, c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not start session"})
		return
	}

	h.setSessionCookies(c, rawToken, session.CSRFSecret, session.ExpiresAt)
	c.JSON(http.StatusOK, gin.H{
		"user": publicUser(user),
	})
}

func (h *AuthHandler) registerFailedAttempt(user *dto.User) {
	user.FailedAttempts++
	updates := map[string]interface{}{"failed_attempts": user.FailedAttempts}
	if user.FailedAttempts >= h.Cfg.MaxFailedAttempts {
		lockUntil := time.Now().Add(h.Cfg.LockoutDuration)
		updates["locked_until"] = lockUntil
	}
	h.DB.Model(user).Updates(updates)
}

func (h *AuthHandler) createSession(userID uint, c *gin.Context) (*dto.Session, string, error) {
	rawToken, err := util.GenerateToken()
	if err != nil {
		return nil, "", err
	}
	csrfSecret, err := util.GenerateToken()
	if err != nil {
		return nil, "", err
	}

	now := time.Now()
	sess := dto.Session{
		TokenHash:     util.HashToken(rawToken),
		UserID:        userID,
		CSRFSecret:    csrfSecret,
		UserAgent:     c.Request.UserAgent(),
		IP:            c.ClientIP(),
		CreatedAt:     now,
		LastSeenAt:    now,
		ExpiresAt:     now.Add(h.Cfg.SessionAbsoluteTTL),
		IdleExpiresAt: now.Add(h.Cfg.SessionIdleTTL),
	}
	if err := h.DB.Create(&sess).Error; err != nil {
		return nil, "", err
	}
	return &sess, rawToken, nil
}

func (h *AuthHandler) setSessionCookies(c *gin.Context, rawToken, csrfSecret string, expires time.Time) {
	maxAge := int(time.Until(expires).Seconds())
	// HttpOnly session cookie: never readable by JS, closing off the
	// most common exfiltration path (XSS reading document.cookie).
	c.SetCookie(mw.SessionCookieName, rawToken, maxAge, "/", h.Cfg.CookieDomain, h.Cfg.IsProd, true)
	// CSRF cookie is deliberately readable by JS — the frontend reads
	// it and echoes it back as a header; see middleware/csrf.go.
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(mw.CSRFCookieName, csrfSecret, maxAge, "/", h.Cfg.CookieDomain, h.Cfg.IsProd, false)
}

// Logout destroys the current session server-side and clears cookies.
// Requires RequireSession to have already run.
func (h *AuthHandler) Logout(c *gin.Context) {
	sess := mw.CurrentSession(c)
	if sess != nil {
		h.DB.Delete(sess)
	}
	c.SetCookie(mw.SessionCookieName, "", -1, "/", h.Cfg.CookieDomain, h.Cfg.IsProd, true)
	c.SetCookie(mw.CSRFCookieName, "", -1, "/", h.Cfg.CookieDomain, h.Cfg.IsProd, false)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// LogoutAll revokes every session for the current user — the
// "log out everywhere" button, also useful to call right after a
// password change.
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	user := mw.CurrentUser(c)
	h.DB.Where("user_id = ?", user.ID).Delete(&dto.Session{})
	c.SetCookie(mw.SessionCookieName, "", -1, "/", h.Cfg.CookieDomain, h.Cfg.IsProd, true)
	c.SetCookie(mw.CSRFCookieName, "", -1, "/", h.Cfg.CookieDomain, h.Cfg.IsProd, false)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// Me returns the caller's identity — the frontend calls this on load
// to figure out whether it already has a valid session.
func (h *AuthHandler) Me(c *gin.Context) {
	user := mw.CurrentUser(c)
	c.JSON(http.StatusOK, gin.H{"user": publicUser(*user)})
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
}

func (h *AuthHandler) ChangePassword(c *gin.Context) {
	user := mw.CurrentUser(c)

	var req changePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "current_password and new_password are required"})
		return
	}
	if !util.CheckPassword(user.PasswordHash, req.CurrentPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is incorrect"})
		return
	}
	if err := util.ValidatePasswordStrength(req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hash, err := util.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not update password"})
		return
	}
	h.DB.Model(&dto.User{}).Where("id = ?", user.ID).Updates(map[string]interface{}{
		"password_hash":       hash,
		"password_changed_at": time.Now(),
	})

	// Invalidate every session including this one — the new password
	// means the caller re-authenticates and gets a fresh session, and
	// any other device/browser that had the old session gets kicked
	// off too (important if the change was prompted by a suspected
	// compromise).
	h.DB.Where("user_id = ?", user.ID).Delete(&dto.Session{})
	c.SetCookie(mw.SessionCookieName, "", -1, "/", h.Cfg.CookieDomain, h.Cfg.IsProd, true)
	c.SetCookie(mw.CSRFCookieName, "", -1, "/", h.Cfg.CookieDomain, h.Cfg.IsProd, false)

	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "password changed, please log in again"})
}

func publicUser(u dto.User) gin.H {
	return gin.H{
		"id":    u.ID,
		"email": u.Email,
		"name":  u.Name,
		"role":  u.Role,
	}
}
