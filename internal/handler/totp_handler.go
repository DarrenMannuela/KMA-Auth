package handler

import (
	"log"
	"net/http"
	"time"

	"github.com/DarrenMannuela/KMA-auth/internal/dto"
	mw "github.com/DarrenMannuela/KMA-auth/internal/middleware"
	"github.com/DarrenMannuela/KMA-auth/internal/util"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// Two-factor authentication (TOTP): Setup/Verify/Disable manage a
// user's own second factor (all require an existing session, via
// RequireSession in main.go); MFALogin is the public counterpart to
// Login that redeems a PendingMFA row for a real session once the code
// checks out — see Login's own comment in auth_handler.go for why
// password success alone doesn't create a session when TOTPEnabled is
// true.

const mfaPendingCookieName = "kma_mfa_pending"
const mfaPendingTTL = 5 * time.Minute

type setupTOTPRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
}

// SetupTOTP issues a fresh secret and QR-code URL, stored only in
// TOTPPendingSecret until Verify confirms the user's authenticator app
// actually has it — see User's own comment for why. Requires the
// current password so a hijacked session alone can't enroll an
// attacker's own device as a trusted second factor (Verify and Disable
// share the same concern, and the same guard).
func (h *AuthHandler) SetupTOTP(c *gin.Context) {
	if h.Cfg.TOTPEncryptionKey == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "two-factor setup isn't configured on this server yet"})
		return
	}
	user := mw.CurrentUser(c)

	var req setupTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "current_password is required"})
		return
	}
	if !util.CheckPassword(user.PasswordHash, req.CurrentPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is incorrect"})
		return
	}
	if user.TOTPEnabled {
		c.JSON(http.StatusConflict, gin.H{"error": "two-factor authentication is already enabled — disable it first to set up a new device"})
		return
	}

	secret, otpauthURL, err := util.GenerateTOTPKey(user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate a two-factor secret"})
		return
	}
	encrypted, err := util.EncryptTOTPSecret(secret, h.Cfg.TOTPEncryptionKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate a two-factor secret"})
		return
	}
	if err := h.DB.Model(&dto.User{}).Where("id = ?", user.ID).Update("totp_pending_secret", encrypted).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not save the two-factor secret"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"otpauth_url": otpauthURL})
}

type verifyTOTPRequest struct {
	Code string `json:"code" binding:"required"`
}

// VerifyTOTP confirms the code from Setup's QR actually works, which is
// what turns TOTPEnabled on — see Setup's comment. On success, also
// issues a fresh batch of recovery codes: the plaintext is returned
// exactly this once in the response and never stored or logged, only
// each one's hash (see dto.TOTPRecoveryCode).
func (h *AuthHandler) VerifyTOTP(c *gin.Context) {
	if h.Cfg.TOTPEncryptionKey == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "two-factor setup isn't configured on this server yet"})
		return
	}
	user := mw.CurrentUser(c)

	var req verifyTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code is required"})
		return
	}
	if user.TOTPPendingSecret == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "start two-factor setup first"})
		return
	}
	secret, err := util.DecryptTOTPSecret(user.TOTPPendingSecret, h.Cfg.TOTPEncryptionKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not verify the code"})
		return
	}
	if !util.ValidateTOTPCode(secret, req.Code) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "that code didn't match — check your authenticator app and try again"})
		return
	}

	codes, hashes, err := generateRecoveryCodeBatch()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate recovery codes"})
		return
	}

	err = h.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&dto.User{}).Where("id = ?", user.ID).Updates(map[string]interface{}{
			"totp_secret":         user.TOTPPendingSecret,
			"totp_pending_secret": "",
			"totp_enabled":        true,
		}).Error; err != nil {
			return err
		}
		// Replace any codes left over from an earlier enable/disable cycle.
		if err := tx.Where("user_id = ?", user.ID).Delete(&dto.TOTPRecoveryCode{}).Error; err != nil {
			return err
		}
		rows := make([]dto.TOTPRecoveryCode, len(hashes))
		for i, hash := range hashes {
			rows[i] = dto.TOTPRecoveryCode{UserID: user.ID, CodeHash: hash}
		}
		return tx.Create(&rows).Error
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not enable two-factor authentication"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"recovery_codes": codes})
}

type disableTOTPRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
}

// DisableTOTP removes the second factor entirely, along with every
// recovery code. Requires the current password for the same reason as
// Setup — an attacker only riding a hijacked session shouldn't be able
// to strip the real owner's 2FA protection off their account.
func (h *AuthHandler) DisableTOTP(c *gin.Context) {
	user := mw.CurrentUser(c)

	var req disableTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "current_password is required"})
		return
	}
	if !util.CheckPassword(user.PasswordHash, req.CurrentPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is incorrect"})
		return
	}

	err := h.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&dto.User{}).Where("id = ?", user.ID).Updates(map[string]interface{}{
			"totp_secret":         "",
			"totp_pending_secret": "",
			"totp_enabled":        false,
		}).Error; err != nil {
			return err
		}
		return tx.Where("user_id = ?", user.ID).Delete(&dto.TOTPRecoveryCode{}).Error
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not disable two-factor authentication"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type mfaLoginRequest struct {
	Code         string `json:"code"`
	RecoveryCode string `json:"recovery_code"`
}

// MFALogin is Login's second step for an account with TOTPEnabled: it
// redeems the kma_mfa_pending cookie Login set (proving the password
// step already passed, for this specific attempt, within the last few
// minutes) against either a live TOTP code or one of the account's
// recovery codes, and on success issues the real session exactly as
// Login would have. No session/CSRF required to call it — like Login
// and AcceptInvite, the whole point of calling it is to get one.
func (h *AuthHandler) MFALogin(c *gin.Context) {
	raw, err := c.Cookie(mfaPendingCookieName)
	if err != nil || raw == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "that login attempt has expired — please sign in again"})
		return
	}

	var pending dto.PendingMFA
	err = h.DB.Where("token_hash = ?", util.HashToken(raw)).First(&pending).Error
	if err != nil || time.Now().After(pending.ExpiresAt) {
		clearMFAPendingCookie(c, h.Cfg.IsProd, h.Cfg.CookieDomain)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "that login attempt has expired — please sign in again"})
		return
	}

	var req mfaLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "code or recovery_code is required"})
		return
	}

	var user dto.User
	if err := h.DB.First(&user, pending.UserID).Error; err != nil || !user.Active || !user.TOTPEnabled {
		clearMFAPendingCookie(c, h.Cfg.IsProd, h.Cfg.CookieDomain)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}

	ok := false
	usedRecoveryCode := false
	switch {
	case req.Code != "":
		secret, decErr := util.DecryptTOTPSecret(user.TOTPSecret, h.Cfg.TOTPEncryptionKey)
		ok = decErr == nil && util.ValidateTOTPCode(secret, req.Code)
	case req.RecoveryCode != "":
		ok = h.redeemRecoveryCode(user.ID, req.RecoveryCode)
		usedRecoveryCode = ok
	}
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "that code didn't match — check your authenticator app, or use a recovery code"})
		return
	}

	if err := h.DB.Delete(&pending).Error; err != nil {
		log.Printf("[auth] warning: failed to delete redeemed pending-mfa row %d: %v", pending.ID, err)
	}
	clearMFAPendingCookie(c, h.Cfg.IsProd, h.Cfg.CookieDomain)

	session, rawToken, err := h.createSession(user.ID, c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not start session"})
		return
	}
	h.setSessionCookies(c, rawToken, session.CSRFSecret, session.ExpiresAt)

	resp := gin.H{"user": publicUser(user)}
	if usedRecoveryCode {
		remaining, _ := h.countRemainingRecoveryCodes(user.ID)
		resp["recovery_code_used"] = true
		resp["recovery_codes_remaining"] = remaining
	}
	c.JSON(http.StatusOK, resp)
}

// redeemRecoveryCode marks one matching, not-yet-used code as used and
// reports whether it found one — a hashed lookup, same as checking a
// password, so the stored value is never compared in plaintext.
func (h *AuthHandler) redeemRecoveryCode(userID uint, code string) bool {
	hash := util.HashRecoveryCode(code)
	res := h.DB.Model(&dto.TOTPRecoveryCode{}).
		Where("user_id = ? AND code_hash = ? AND used_at IS NULL", userID, hash).
		Update("used_at", time.Now())
	return res.Error == nil && res.RowsAffected == 1
}

func (h *AuthHandler) countRemainingRecoveryCodes(userID uint) (int64, error) {
	var n int64
	err := h.DB.Model(&dto.TOTPRecoveryCode{}).Where("user_id = ? AND used_at IS NULL", userID).Count(&n).Error
	return n, err
}

func generateRecoveryCodeBatch() (codes []string, hashes []string, err error) {
	codes = make([]string, util.RecoveryCodeCount)
	hashes = make([]string, util.RecoveryCodeCount)
	for i := range codes {
		code, genErr := util.GenerateRecoveryCode()
		if genErr != nil {
			return nil, nil, genErr
		}
		codes[i] = code
		hashes[i] = util.HashRecoveryCode(code)
	}
	return codes, hashes, nil
}

func clearMFAPendingCookie(c *gin.Context, isProd bool, cookieDomain string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(mfaPendingCookieName, "", -1, "/", cookieDomain, isProd, true)
}
