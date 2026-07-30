package middleware

import (
	"net/http"

	"github.com/DarrenMannuela/KMA-auth/internal/util"
	"github.com/gin-gonic/gin"
)

// RequireCSRF implements the double-submit cookie pattern, bound to
// the session (not just any matching pair of cookies): the value the
// client must echo back is the session's own CSRFSecret, which only
// JS running on an origin allowed to read the response could have
// gotten hold of. Cross-site form posts / <img>/<script> tricks can
// make the browser SEND the session cookie automatically, but they
// can't READ the CSRF cookie to put its value in a custom header —
// that's what actually blocks the forgery.
//
// Must run after RequireSession, since it checks the CSRF secret
// against the session that was just loaded.
func RequireCSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		sess := CurrentSession(c)
		if sess == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
			return
		}

		header := c.GetHeader("X-CSRF-Token")
		if header == "" || !util.ConstantTimeEqual(header, sess.CSRFSecret) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "invalid or missing CSRF token"})
			return
		}
		c.Next()
	}
}
