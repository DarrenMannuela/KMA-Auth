package handler

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/DarrenMannuela/KMA-auth/internal/dto"
	"github.com/DarrenMannuela/KMA-auth/internal/mail"
	"github.com/DarrenMannuela/KMA-auth/internal/util"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// This is an internal business tool (order/production/finance
// management) — there's a fixed, small staff list, not open
// self-signup. So account creation is admin-only, gated behind
// RequireSession + RequireRole("admin") in main.go, rather than a
// public /register endpoint.

type createUserRequest struct {
	Email string `json:"email" binding:"required,email"`
	Name  string `json:"name" binding:"required"`
	Role  string `json:"role"`
}

// CreateUser no longer takes a password from the admin at all — it
// creates the account locked (an unguessable random hash nobody, not
// even the admin, ever sees) and emails the new user a one-time
// "set your password" link instead. Replaces the previous flow where
// an admin typed a temporary password and had to relay it out of band
// (Slack, in person, etc) — that meant a real password briefly existed
// outside this system's control, and relied on the admin actually
// getting it to the right person securely. Nothing sensitive travels
// by email now: the token is single-use, expires (see
// cfg.InviteTokenTTL), and by itself grants nothing but the chance to
// set a password — see AcceptInvite below for the other half of this.
func (h *AuthHandler) CreateUser(c *gin.Context) {
	var req createUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email and name are required"})
		return
	}
	role := req.Role
	if role == "" {
		role = "staff"
	}
	if role != "admin" && role != "staff" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "role must be admin or staff"})
		return
	}

	// A random, never-shown password — the account exists and is
	// Active, but CheckPassword can never match anything a person could
	// type, so Login is a dead end for this account until AcceptInvite
	// replaces this hash with one the user actually chose. Errors from
	// GenerateToken are only realistic if the OS CSPRNG itself is
	// broken, in which case nothing else here would be safe to proceed
	// with either — hence the hard bail rather than falling back to
	// something weaker.
	lockedRaw, err := util.GenerateToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create user"})
		return
	}
	lockedHash, err := util.HashPassword(lockedRaw)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create user"})
		return
	}

	// MustChangePassword stays true here too — belt-and-suspenders with
	// AcceptInvite already clearing it on success; if a row somehow
	// exists in this locked state without ever going through
	// AcceptInvite, this keeps it correctly marked as not yet usable.
	user := dto.User{
		Email:              strings.ToLower(strings.TrimSpace(req.Email)),
		Name:               req.Name,
		PasswordHash:       lockedHash,
		Role:               role,
		Active:             true,
		MustChangePassword: true,
	}
	if err := h.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "a user with that email already exists"})
		return
	}

	link, err := h.createInviteToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create invite token"})
		return
	}

	if err := mail.SendInviteEmail(h.Cfg, user.Email, user.Name, link); err != nil {
		// The user row and its invite token both already exist at this
		// point — deliberately NOT rolled back on a send failure. An
		// admin whose email attempt failed (bad SMTP creds, Gmail rate
		// limit, etc) still has a valid account + token sitting in the
		// DB; the fix is resending, not recreating the user from
		// scratch (which would just collide on the unique email index
		// anyway). Surfaced as an error so the admin knows to follow up
		// rather than assuming the invite went out.
		c.JSON(http.StatusCreated, gin.H{
			"user":  publicUser(user),
			"error": "user created, but the invite email could not be sent: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"user": publicUser(user)})
}

// createInviteToken issues a fresh invite token for user and returns the
// full "…/set-password?token=…" link to email them. Kept as its own
// method (rather than inlined in CreateUser) so a future "resend invite"
// admin action can call it directly against an existing user without
// duplicating this logic.
func (h *AuthHandler) createInviteToken(user dto.User) (string, error) {
	raw, err := util.GenerateToken()
	if err != nil {
		return "", err
	}
	token := dto.InviteToken{
		TokenHash: util.HashToken(raw),
		UserID:    user.ID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(h.Cfg.InviteTokenTTL),
	}
	if err := h.DB.Create(&token).Error; err != nil {
		return "", err
	}
	// QueryEscape rather than trusting raw's own base64url alphabet to
	// always be URL-safe as-is — cheap insurance if GenerateToken's
	// encoding ever changes later, and correct regardless either way.
	return h.Cfg.AppBaseURL + "/set-password?token=" + url.QueryEscape(raw), nil
}

type acceptInviteRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// AcceptInvite is the public counterpart to CreateUser's emailed link —
// no session/CSRF required, since the whole point is letting someone
// with no prior session in. The token itself IS the credential proving
// they're the intended recipient (see dto.InviteToken's comment for why
// only its hash is stored), same trust model as a password-reset link
// anywhere else.
func (h *AuthHandler) AcceptInvite(c *gin.Context) {
	var req acceptInviteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "token and new_password are required"})
		return
	}

	var invite dto.InviteToken
	err := h.DB.Where("token_hash = ?", util.HashToken(req.Token)).First(&invite).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "this invite link is invalid or has already been used"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not verify invite"})
		return
	}
	// Expired and already-used are deliberately reported identically to
	// the caller — both just mean "this link won't work, ask for a new
	// one" from the end user's point of view, and neither should hint
	// at which case it was (e.g. distinguishing them could tell someone
	// probing a guessed/leaked token whether it was ever valid at all).
	if invite.UsedAt != nil || time.Now().After(invite.ExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "this invite link is invalid or has already been used"})
		return
	}

	if err := util.ValidatePasswordStrength(req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user dto.User
	if err := h.DB.First(&user, invite.UserID).Error; err != nil || !user.Active {
		// Covers the account being deactivated between invite and
		// acceptance — same generic message as above rather than
		// distinguishing "deactivated" from "invalid token", for the
		// same non-disclosure reasoning.
		c.JSON(http.StatusBadRequest, gin.H{"error": "this invite link is invalid or has already been used"})
		return
	}

	hash, err := util.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not set password"})
		return
	}

	now := time.Now()
	err = h.DB.Model(&user).Updates(map[string]interface{}{
		"password_hash":        hash,
		"must_change_password": false,
		"password_changed_at":  now,
		"failed_attempts":      0,
		"locked_until":         nil,
	}).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not set password"})
		return
	}

	invite.UsedAt = &now
	h.DB.Save(&invite)

	// Straight into a real session — unlike ChangePassword (which
	// revokes sessions because it's changing a password that was
	// already in active use, possibly under duress/compromise), there's
	// no prior session here to be suspicious of: this IS the first
	// login. Making them then type the same password right back into
	// /login would just be friction with no security benefit.
	session, rawToken, err := h.createSession(user.ID, c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "password set, but could not start session — please log in"})
		return
	}
	h.setSessionCookies(c, rawToken, session.CSRFSecret, session.ExpiresAt)

	c.JSON(http.StatusOK, gin.H{"user": publicUser(user)})
}

func (h *AuthHandler) ListUsers(c *gin.Context) {
	var users []dto.User
	if err := h.DB.Order("created_at asc").Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not list users"})
		return
	}
	out := make([]gin.H, 0, len(users))
	for _, u := range users {
		out = append(out, publicUser(u))
	}
	c.JSON(http.StatusOK, gin.H{"users": out})
}

func (h *AuthHandler) DeactivateUser(c *gin.Context) {
	id := c.Param("id")
	if err := h.DB.Model(&dto.User{}).Where("id = ?", id).Update("active", false).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not deactivate user"})
		return
	}
	// Kill every outstanding session for that user immediately — an
	// admin deactivating an account expects it to lose access now,
	// not whenever that user's sessions happen to expire.
	h.DB.Where("user_id = ?", id).Delete(&dto.Session{})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ReactivateUser undoes a deactivation. It also clears any leftover
// failed-attempt count and lockout from before the account was
// deactivated — those don't apply to a fresh return to service, and
// leaving a stale locked_until in place could lock the person out
// again for no reason the admin (or the user) can see. It does not
// create a session; the user still logs in normally afterward.
func (h *AuthHandler) ReactivateUser(c *gin.Context) {
	id := c.Param("id")
	err := h.DB.Model(&dto.User{}).Where("id = ?", id).Updates(map[string]interface{}{
		"active":          true,
		"failed_attempts": 0,
		"locked_until":    nil,
	}).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not reactivate user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
