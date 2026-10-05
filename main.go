package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/DarrenMannuela/KMA-auth/internal/config"
	"github.com/DarrenMannuela/KMA-auth/internal/database"
	"github.com/DarrenMannuela/KMA-auth/internal/handler"
	mw "github.com/DarrenMannuela/KMA-auth/internal/middleware"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()

	// Force release mode whenever cfg.IsProd is true, regardless of
	// whether the GIN_MODE env var happens to be set correctly —
	// debug mode logs full route tables and is chattier in general,
	// which isn't something we want to depend on remembering to set
	// via a separate env var. AUTH_ENV=production (already required
	// for cfg.IsProd to be true) is the single source of truth now.
	if cfg.IsProd {
		gin.SetMode(gin.ReleaseMode)
	}

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
		// Public like /login, for the same reason — the person hitting
		// this has no session yet (that's the entire point: it's how
		// they get one for the first time). Reuses RateLimitAuth rather
		// than a separate limiter — a token-guessing attempt against
		// this endpoint is the same class of abuse (repeated auth-
		// adjacent POSTs from one source) that RateLimitAuth already
		// exists to slow down.
		v1.POST("/accept-invite", mw.RateLimitAuth(), authHandler.AcceptInvite)

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
				admin.POST("/:id/reactivate", mw.RequireCSRF(), authHandler.ReactivateUser)
			}
		}
	}

	// Server-to-server only — never exposed to the frontend, gated by
	// a shared secret instead of a session/CSRF cookie. RateLimitInternal
	// caps how fast this can be hit even if AUTH_INTERNAL_KEY ever
	// leaks — the key itself has no throttling of its own.
	internalGroup := r.Group("/internal")
	internalGroup.Use(mw.RateLimitInternal(), mw.RequireInternalKey(cfg))
	{
		internalGroup.POST("/validate", authHandler.Validate)
	}

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// An http.Server rather than r.Run, so a stop can be graceful:
	// Docker sends SIGTERM on every stop, restart and update, and before
	// this the process was simply killed by it (exit code 2), cutting off
	// a login or password change half way through. Now it stops taking
	// new requests, lets the ones in flight finish (up to 20s; compose's
	// stop_grace_period gives it 30s), then closes the database.
	// ReadHeaderTimeout stops a client that never finishes sending its
	// headers from holding a connection open forever.
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}
	stop, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[auth] server failed: %v", err)
		}
	}()
	log.Printf("[auth] listening on :%s (env=%s)", cfg.Port, envLabel(cfg))

	<-stop.Done()
	log.Println("[auth] stopping: finishing the requests in progress")
	ctx, done := context.WithTimeout(context.Background(), 20*time.Second)
	defer done()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("[auth] stopped before every request finished: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		if err := sqlDB.Close(); err != nil {
			log.Printf("[auth] closing the database: %v", err)
		}
	}
	log.Println("[auth] stopped cleanly")
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
