package main

import (
	"log"
	"net/http"
	"time"

	"github.com/DarrenMannuela/KMA-auth/internal/config"
	"github.com/DarrenMannuela/KMA-auth/internal/database"
	"github.com/DarrenMannuela/KMA-auth/internal/handler"
	mw "github.com/DarrenMannuela/KMA-auth/internal/middleware"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()

	db, err := database.Connect(cfg)
	if err != nil {
		log.Fatalf("[auth] failed to connect to database: %v", err)
	}

	if cfg.InternalKey == "" {
		log.Println("[auth] WARNING: AUTH_INTERNAL_KEY is not set — the /internal/validate endpoint will refuse all requests until it is.")
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestLogger())

	// Behind a reverse proxy (nginx/traefik/etc) in production, set
	// this to that proxy's actual address instead of nil, or
	// ClientIP()-based rate limiting can be spoofed via
	// X-Forwarded-For. nil disables trusting any proxy headers, which
	// is the safe default for direct/local exposure.
	r.SetTrustedProxies(nil)

	r.Use(corsMiddleware(cfg))
	r.Use(securityHeaders())

	authHandler := handler.NewAuthHandler(db, cfg)

	v1 := r.Group("/api/v1/auth")
	{
		v1.POST("/login", mw.RateLimitAuth(), authHandler.Login)

		authed := v1.Group("")
		authed.Use(mw.RequireSession(db, cfg))
		{
			authed.GET("/me", authHandler.Me)
			authed.POST("/logout", mw.RequireCSRF(), authHandler.Logout)
			authed.POST("/logout-all", mw.RequireCSRF(), authHandler.LogoutAll)
			authed.POST("/change-password", mw.RequireCSRF(), authHandler.ChangePassword)

			admin := authed.Group("/users")
			admin.Use(mw.RequireRole("admin"))
			{
				admin.GET("", authHandler.ListUsers)
				admin.POST("", mw.RequireCSRF(), authHandler.CreateUser)
				admin.POST("/:id/deactivate", mw.RequireCSRF(), authHandler.DeactivateUser)
			}
		}
	}

	// Server-to-server only — never exposed to the frontend, gated by
	// a shared secret instead of a session/CSRF cookie.
	internalGroup := r.Group("/internal")
	internalGroup.Use(mw.RequireInternalKey(cfg))
	{
		internalGroup.POST("/validate", authHandler.Validate)
	}

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	log.Printf("[auth] listening on :%s (env=%s)", cfg.Port, envLabel(cfg))
	if err := r.Run(":" + cfg.Port); err != nil {
		log.Fatalf("[auth] server failed: %v", err)
	}
}

func envLabel(cfg config.Config) string {
	if cfg.IsProd {
		return "production"
	}
	return "development"
}

// corsMiddleware only allows configured origins, and echoes that
// specific origin back (never "*") because credentialed requests
// (cookies) are forbidden by browsers from working with a wildcard
// origin anyway — being explicit here is both required and safer.
func corsMiddleware(cfg config.Config) gin.HandlerFunc {
	allowed := make(map[string]bool, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		if o != "" {
			allowed[o] = true
		}
	}
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" && allowed[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token")
			c.Header("Vary", "Origin")
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("Referrer-Policy", "same-origin")
		c.Header("Cache-Control", "no-store")
		c.Next()
	}
}

// requestLogger is a minimal access log that deliberately never
// prints request bodies or cookie values — the default gin.Logger()
// is fine for a public app, but this service handles passwords and
// session tokens, so a custom (quieter) logger avoids ever writing
// those to disk by accident.
func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		log.Printf("[auth] %s %s %d %s", c.Request.Method, c.Request.URL.Path, c.Writer.Status(), time.Since(start))
	}
}
