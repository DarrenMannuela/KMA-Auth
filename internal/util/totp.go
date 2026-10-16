package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// GenerateTOTPKey creates a fresh, random TOTP secret for accountEmail,
// returning both the secret to store (encrypted — see EncryptTOTPSecret)
// and the otpauth:// URL an authenticator app's QR scanner understands.
// Issuer is shown in the app alongside the account name, so a user with
// several TOTP entries can tell which one is this.
func GenerateTOTPKey(accountEmail string) (secret, otpauthURL string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "KMA",
		AccountName: accountEmail,
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.String(), nil
}

// ValidateTOTPCode checks a 6-digit code against secret, allowing the
// previous and next 30s windows too (otp's default Skew via Validate)
// so a slightly out-of-sync device clock doesn't lock someone out.
func ValidateTOTPCode(secret, code string) bool {
	ok, _ := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return ok
}

// ── Secret encryption at rest ────────────────────────────────────────
// A TOTP secret has to be reversible to check a code against it, unlike
// a password — so it can't just be hashed. Encrypting it with a key that
// lives only in AUTH_TOTP_ENCRYPTION_KEY (never in the database) means a
// stolen DB file or backup alone doesn't hand over working 2FA secrets.

// EncryptTOTPSecret AES-GCM-encrypts plain under key, returning a
// base64 blob (nonce + ciphertext) safe to store in a text column.
func EncryptTOTPSecret(plain string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// DecryptTOTPSecret reverses EncryptTOTPSecret.
func DecryptTOTPSecret(blob string, key []byte) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ── Recovery codes ──────────────────────────────────────────────────
// RecoveryCodeCount is how many codes a batch holds — enough that losing
// a couple over the account's lifetime (one used to actually recover,
// one mistyped and discarded) still leaves a real cushion, not so many
// that "which ones are left" becomes its own problem.
const RecoveryCodeCount = 8

// recoveryAlphabet excludes characters easy to mis-type or confuse when
// copied by hand off a screen (0/O, 1/I/L).
const recoveryAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

// GenerateRecoveryCode returns one code like "7K4P-QX2M" — 8 significant
// characters (~38 bits of entropy), grouped for readability. Called
// RecoveryCodeCount times by the TOTP handler for a full batch.
func GenerateRecoveryCode() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	var b strings.Builder
	for i, v := range buf {
		if i == 4 {
			b.WriteByte('-')
		}
		b.WriteByte(recoveryAlphabet[int(v)%len(recoveryAlphabet)])
	}
	return b.String(), nil
}

// HashRecoveryCode is a fast hash, not bcrypt — like session tokens
// (see HashToken), a recovery code is high-entropy and single-use, not
// a human-chosen password, so there's nothing a fast hash makes easier
// to brute-force that constant-time lookup-by-hash doesn't already rule
// out.
func HashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte(normalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}

// normalizeRecoveryCode upper-cases and strips surrounding whitespace, so
// a code pasted with stray spaces or typed in lowercase still matches —
// same tolerance a person gets when typing a TOTP code's digits.
func normalizeRecoveryCode(code string) string {
	return strings.ToUpper(strings.TrimSpace(code))
}
