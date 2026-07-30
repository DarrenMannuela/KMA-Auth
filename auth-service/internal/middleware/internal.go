package middleware

import (
	"net/http"

	"github.com/DarrenMannuela/KMA-auth/internal/config"
	"github.com/DarrenMannuela/KMA-auth/internal/util"
	"github.com/gin-gonic/gin"
)

// RequireInternalKey protects routes meant only for other backend
// services (currently: the main KMA API asking "is this cookie
// valid?"), never for browsers. This is a shared secret, not a
// session — it should be set from a real random value in production
// and never exposed to the frontend.
func RequireInternalKey(cfg config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cfg.InternalKey == "" {
			// Fail closed: an unset key must never mean "open to
			// everyone" — that would make the internal endpoint
			// unauthenticated by accident in a misconfigured deploy.
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "internal auth not configured"})
			return
		}
		key := c.GetHeader("X-Internal-Key")
		if key == "" || !util.ConstantTimeEqual(key, cfg.InternalKey) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Next()
	}
}
