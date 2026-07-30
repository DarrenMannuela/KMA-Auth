// Drop this file into the main KMA backend, e.g. internal/middleware/authguard.go
// (adjust the package name to match wherever your other middleware lives).
//
// It does NOT duplicate any session/password logic — it just asks the
// auth service "is this cookie currently valid?" on every request via
// the internal-only /internal/validate endpoint, and rejects the
// request if not. This is what makes it safe to run auth as a
// genuinely separate service: this backend never touches a password
// hash or a session table.
package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)

const authSessionCookieName = "kma_session"

type validateResponse struct {
	Valid bool `json:"valid"`
	User  struct {
		ID    uint   `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
		Role  string `json:"role"`
	} `json:"user"`
}

// authServiceClient is a short-timeout HTTP client — a slow/down auth
// service should fail fast (and fail closed, i.e. reject the request)
// rather than hang every business-API request behind it.
var authServiceClient = &http.Client{Timeout: 2 * time.Second}

// RequireAuth validates the caller's session cookie against the
// separate auth service and, on success, stores the identified user
// on the Gin context (read it back with middleware.CurrentUser(c)).
//
// Env vars needed on THIS backend:
//   AUTH_SERVICE_URL  e.g. http://auth-backend:8001 (use the Docker
//                     service name — see docker-compose.yaml)
//   AUTH_INTERNAL_KEY same shared secret as the auth service's
//                     AUTH_INTERNAL_KEY
func RequireAuth() gin.HandlerFunc {
	authServiceURL := os.Getenv("AUTH_SERVICE_URL")
	internalKey := os.Getenv("AUTH_INTERNAL_KEY")

	return func(c *gin.Context) {
		if authServiceURL == "" || internalKey == "" {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "auth is not configured"})
			return
		}

		token, err := c.Cookie(authSessionCookieName)
		if err != nil || token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
			return
		}

		payload, _ := json.Marshal(map[string]string{"token": token})
		req, err := http.NewRequest(http.MethodPost, authServiceURL+"/internal/validate", bytes.NewReader(payload))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "auth check failed"})
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Internal-Key", internalKey)

		resp, err := authServiceClient.Do(req)
		if err != nil {
			// Fail closed: if the auth service is unreachable, nobody
			// gets in, rather than silently letting requests through.
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "auth service unavailable"})
			return
		}
		defer resp.Body.Close()

		var out validateResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || !out.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session invalid"})
			return
		}

		c.Set("current_user_id", out.User.ID)
		c.Set("current_user_role", out.User.Role)
		c.Set("current_user_email", out.User.Email)
		c.Next()
	}
}

// RequireAdmin gates a route to the admin role — call after RequireAuth().
func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get("current_user_role")
		if role != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin only"})
			return
		}
		c.Next()
	}
}
