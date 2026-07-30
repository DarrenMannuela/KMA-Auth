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

	user := dto.User{
		Email:        strings.ToLower(strings.TrimSpace(req.Email)),
		Name:         req.Name,
		PasswordHash: hash,
		Role:         role,
		Active:       true,
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
