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
	if cfg.TOTPEncryptionKey == nil {
		log.Println("[auth] WARNING: AUTH_TOTP_ENCRYPTION_KEY is not set (or isn't a 64-char hex string) — two-factor setup will refuse all requests until it is.")
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(requestLogger())

	// Every real request reaches this service through nginx (see
	// KMA-Frontend/nginx.conf's /auth/ location), which does set
	// X-Forwarded-For/X-Real-IP correctly — but Gin only trusts those
	// headers from addresses in this list; anything else falls back to
	// the raw TCP peer address. cfg.TrustedProxies defaults to Docker's
	// bridge-network pool (see config.go), which covers nginx's
	// container. Getting this wrong in either direction is bad: nil
	// (or an empty/wrong list) makes ClientIP() return nginx's own
	// address for every request — identical for every real user AND
	// any attacker, which silently turns the per-IP rate limiters
	// below into one shared global bucket instead of a per-source cap.
	if err := r.SetTrustedProxies(cfg.TrustedProxies); err != nil {
		log.Fatalf("[auth] invalid AUTH_TRUSTED_PROXIES: %v", err)
	}

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
		// Login's second step for an account with 2FA on — same public,
		// rate-limited treatment as /login and /accept-invite, and for
		// the same brute-force reason it matters even more here: a
		// 6-digit code is a much smaller space to guess than a password.
		v1.POST("/totp/login", mw.RateLimitAuth(), authHandler.MFALogin)

		authed := v1.Group("")
		authed.Use(mw.RequireSession(db, cfg))
		{
			authed.GET("/me", authHandler.Me)
			authed.POST("/logout", mw.RequireCSRF(), authHandler.Logout)
			// Sent by a tab as it closes (see Closing for why it doesn't
			// just log out).
			authed.POST("/closing", mw.RequireCSRF(), authHandler.Closing)
			authed.POST("/logout-all", mw.RequireCSRF(), authHandler.LogoutAll)
			// Rate-limited like /login: this one also checks the account's
			// real password, so it's just as guessable a target even though
			// it requires a live session to reach at all.
			authed.POST("/change-password", mw.RateLimitAuth(), mw.RequireCSRF(), authHandler.ChangePassword)

			// A user's own 2FA device — distinct from /users below, which
			// is an admin managing *other* accounts entirely. All three are
			// rate-limited: /verify confirms a 6-digit code against a
			// pending secret (small guess space, same reasoning as
			// /totp/login), and /setup and /disable both re-check the
			// account's real password like /change-password above.
			authed.POST("/totp/setup", mw.RateLimitAuth(), mw.RequireCSRF(), authHandler.SetupTOTP)
			authed.POST("/totp/verify", mw.RateLimitAuth(), mw.RequireCSRF(), authHandler.VerifyTOTP)
			authed.POST("/totp/disable", mw.RateLimitAuth(), mw.RequireCSRF(), authHandler.DisableTOTP)

			admin := authed.Group("/users")
			admin.Use(mw.RequireRole("admin"))
			{
				admin.GET("", authHandler.ListUsers)
				admin.POST("", mw.RequireCSRF(), authHandler.CreateUser)
				admin.POST("/:id/deactivate", mw.RequireCSRF(), authHandler.DeactivateUser)
				admin.POST("/:id/reactivate", mw.RequireCSRF(), authHandler.ReactivateUser)
				admin.DELETE("/:id", mw.RequireCSRF(), authHandler.DeleteUser)
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
	// ReadHeaderTimeout/ReadTimeout stop a client that never finishes
	// sending its request from holding a connection open forever; both
	// can be short since nothing here accepts file uploads. WriteTimeout
	// is more generous — CreateUser's invite email is sent synchronously
	// within the request, and a slow SMTP round-trip shouldn't trip a
	// tight response deadline. IdleTimeout bounds how long a kept-alive
	// connection sits open between requests.
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	stop, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[auth] server failed: %v", err)
		}
	}()
	log.Printf("[auth] listening on :%s (env=%s)", cfg.Port, envLabel(cfg))

	// Clear out expired sessions and old invite links: once at start, then
	// every hour, until the service stops. gin.Recovery() only covers HTTP
	// handlers, not this goroutine — prune has its own recover so one bad
	// cycle logs and skips instead of taking the whole process down with
	// it (it would otherwise, since an unrecovered panic in any goroutine
	// crashes the entire program, not just that goroutine).
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		prune := func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[auth] recovered from panic while pruning: %v", r)
				}
			}()
			if s, i, err := database.PruneExpired(db); err != nil {
				log.Printf("[auth] warning: pruning expired sessions: %v", err)
			} else if s+i > 0 {
				log.Printf("[auth] pruned %d expired sessions and %d old invite links", s, i)
			}
		}
		prune()
		for {
			select {
			case <-stop.Done():
				return
			case <-ticker.C:
				prune()
			}
		}
	}()

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
