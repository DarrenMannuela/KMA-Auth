package util

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
)

// GenerateToken returns a URL-safe, 256-bit random token — used both
// for the session cookie value and the CSRF secret. crypto/rand is
// the OS CSPRNG; math/rand is never acceptable for anything
// security-sensitive.
func GenerateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashToken returns the hex SHA-256 of a token, for storage/lookup.
// Session tokens are high-entropy (256 bits) and single-use-per-cookie,
// so a fast hash is fine here — this is not a password.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ConstantTimeEqual compares two strings without leaking timing info
// about where they first differ — used for the CSRF header/cookie
// comparison so that check can't be used as a side channel.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
