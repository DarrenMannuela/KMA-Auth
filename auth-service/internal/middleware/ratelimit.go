package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// ipLimiter is a per-IP token bucket. This sits alongside (not instead
// of) the per-account lockout in the handler: the account lockout
// stops someone hammering ONE account from anywhere, this stops one
// IP hammering MANY accounts (credential stuffing) or just spamming
// the endpoint.
type ipLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

func newIPLimiter() *ipLimiter {
	l := &ipLimiter{limiters: make(map[string]*rate.Limiter)}
	go l.cleanupLoop()
	return l
}

func (l *ipLimiter) get(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lim, ok := l.limiters[ip]; ok {
		return lim
	}
	// 5 requests/minute steady state, burst of 8 — generous enough for
	// a real user mistyping a password a couple of times, tight enough
	// to blunt automated guessing.
	lim := rate.NewLimiter(rate.Every(12*time.Second), 8)
	l.limiters[ip] = lim
	return lim
}

// cleanupLoop prevents unbounded memory growth from one-off IPs. Not
// perfectly precise (a limiter can be evicted mid-life and restart
// fresh) — acceptable tradeoff for a lightweight in-process limiter.
// For multi-instance deployments, swap this for a Redis-backed
// limiter instead.
func (l *ipLimiter) cleanupLoop() {
	for {
		time.Sleep(10 * time.Minute)
		l.mu.Lock()
		for ip, lim := range l.limiters {
			if lim.Tokens() == 8 { // back at full burst == idle
				delete(l.limiters, ip)
			}
		}
		l.mu.Unlock()
	}
}

var loginLimiter = newIPLimiter()

// RateLimitAuth throttles by client IP. Trusts Gin's ClientIP(), which
// respects a configured trusted-proxy list — make sure that's set
// correctly in production (see main.go) or this can be bypassed via
// spoofed X-Forwarded-For.
func RateLimitAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		lim := loginLimiter.get(c.ClientIP())
		if !lim.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "too many attempts, please wait and try again",
			})
			return
		}
		c.Next()
	}
}
