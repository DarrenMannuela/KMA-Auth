package util

import (
	"errors"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

// Cost 12 is a deliberate step above bcrypt's default (10) — this
// service's only job is guarding logins, so the extra ~4x hashing
// cost per attempt is cheap insurance against offline cracking if the
// DB ever leaks, and login isn't a hot path that needs to be fast.
const bcryptCost = 12

func HashPassword(plain string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func CheckPassword(hash, plain string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// ValidatePasswordStrength enforces a floor, not a full policy debate.
// Length matters far more than character-class quotas (NIST 800-63B),
// so this asks for length + a little variety rather than mandatory
// "1 uppercase + 1 symbol" rules that push people toward "Password1!".
func ValidatePasswordStrength(pw string) error {
	if len(pw) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	if len(pw) > 128 {
		return errors.New("password must be at most 128 characters")
	}

	var hasLetter, hasDigitOrSymbol bool
	for _, r := range pw {
		switch {
		case unicode.IsLetter(r):
			hasLetter = true
		case unicode.IsDigit(r) || unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasDigitOrSymbol = true
		}
	}
	if !hasLetter || !hasDigitOrSymbol {
		return errors.New("password must mix letters with numbers or symbols")
	}
	return nil
}
