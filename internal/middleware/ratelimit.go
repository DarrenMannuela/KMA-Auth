package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// ipLimiter is a per-IP token bucket. rate/burst are configurable per
// instance now (rather than hardcoded inside get()), so different
// endpoints can have different limits — login attempts need to be tight,
// server-to-server internal calls need to be generous enough not to
// throttle normal traffic.
type ipLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	r        rate.Limit
	burst    int
}

func newIPLimiter(r rate.Limit, burst int) *ipLimiter {
	l := &ipLimiter{limiters: make(map[string]*rate.Limiter), r: r, burst: burst}
	go l.cleanupLoop()
	return l
}

func (l *ipLimiter) get(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lim, ok := l.limiters[ip]; ok {
		return lim
	}
	lim := rate.NewLimiter(l.r, l.burst)
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
			if lim.Tokens() == float64(l.burst) { // back at full burst == idle
				delete(l.limiters, ip)
			}
		}
		l.mu.Unlock()
	}
}

// loginLimiter: 5 requests/minute steady state, burst of 8 — generous
// enough for a real user mistyping a password a couple of times, tight
// enough to blunt automated guessing. This sits alongside (not instead
// of) the per-account lockout in the handler: the account lockout stops
// someone hammering ONE account from anywhere, this stops one IP
// hammering MANY accounts (credential stuffing) or just spamming the
// endpoint.
var loginLimiter = newIPLimiter(rate.Every(12*time.Second), 8)

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

// internalLimiter: 20 requests/second steady state, burst of 40. Much
// more generous than the login limiter on purpose — /internal/validate
// is called by kma_backend on every authenticated API request it
// receives, potentially several times per second during normal usage,
// so this needs headroom for legitimate traffic. It's not meant to
// catch normal load; it's meant to cap how fast /internal/validate can
// be hammered if AUTH_INTERNAL_KEY is ever leaked or kma_backend is
// ever compromised — the key itself has no built-in throttling, so
// without this, a leaked key would let an attacker probe session
// tokens as fast as the network allows.
var internalLimiter = newIPLimiter(rate.Every(50*time.Millisecond), 40)

// RateLimitInternal throttles /internal/* routes by caller IP. Since
// this endpoint is never exposed to the browser/internet (only reached
// container-to-container within the Docker network), "IP" here
// effectively means "which container is calling" — still useful as a
// cap on request volume regardless of source.
func RateLimitInternal() gin.HandlerFunc {
	return func(c *gin.Context) {
		lim := internalLimiter.get(c.ClientIP())
		if !lim.Allow() {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "too many requests",
			})
			return
		}
		c.Next()
	}
}
