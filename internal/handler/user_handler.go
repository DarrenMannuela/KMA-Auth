package handler

import (
	"net/http"
	"strings"

	"github.com/DarrenMannuela/KMA-auth/internal/dto"
	"github.com/DarrenMannuela/KMA-auth/internal/util"

	"github.com/gin-gonic/gin"
)

// This is an internal business tool (order/production/finance
// management) — there's a fixed, small staff list, not open
// self-signup. So account creation is admin-only, gated behind
// RequireSession + RequireRole("admin") in main.go, rather than a
// public /register endpoint.

type createUserRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Name     string `json:"name" binding:"required"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role"`
}

func (h *AuthHandler) CreateUser(c *gin.Context) {
	var req createUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email, name, and password are required"})
		return
	}
	if err := util.ValidatePasswordStrength(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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

	hash, err := util.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create user"})
		return
	}

	// MustChangePassword starts true here explicitly (rather than
	// relying on the column default) — this is an admin-set password,
	// so the new hire is forced through the change-password flow on
	// their first login. See dto.User's comment for the flag's full
	// meaning.
	user := dto.User{
		Email:              strings.ToLower(strings.TrimSpace(req.Email)),
		Name:               req.Name,
		PasswordHash:       hash,
		Role:               role,
		Active:             true,
		MustChangePassword: true,
	}
	if err := h.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "a user with that email already exists"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"user": publicUser(user)})
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
