package util

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func testKey(t *testing.T) []byte {
	t.Helper()
	key := []byte("01234567890123456789012345678901") // 32 bytes, AES-256
	if len(key) != 32 {
		t.Fatalf("test key is %d bytes, want 32", len(key))
	}
	return key
}

func TestEncryptDecryptTOTPSecretRoundTrips(t *testing.T) {
	key := testKey(t)
	secret := "JBSWY3DPEHPK3PXP"

	blob, err := EncryptTOTPSecret(secret, key)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(blob, secret) {
		t.Fatal("ciphertext contains the plaintext secret")
	}

	got, err := DecryptTOTPSecret(blob, key)
	if err != nil {
		t.Fatal(err)
	}
	if got != secret {
		t.Errorf("decrypted %q, want %q", got, secret)
	}
}

func TestDecryptTOTPSecretFailsWithWrongKey(t *testing.T) {
	blob, err := EncryptTOTPSecret("JBSWY3DPEHPK3PXP", testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := []byte("98765432109876543210987654321098")[:32]
	if _, err := DecryptTOTPSecret(blob, wrongKey); err == nil {
		t.Error("decrypting with the wrong key should fail, not silently return garbage")
	}
}

func TestGenerateTOTPKeyProducesAValidatableSecret(t *testing.T) {
	secret, otpauthURL, err := GenerateTOTPKey("person@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" || otpauthURL == "" {
		t.Fatal("expected a non-empty secret and otpauth URL")
	}
	if !strings.Contains(otpauthURL, "KMA") {
		t.Errorf("otpauth URL %q should carry the KMA issuer", otpauthURL)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !ValidateTOTPCode(secret, code) {
		t.Error("a code generated from the same secret right now should validate")
	}
}

func TestValidateTOTPCodeRejectsWrongCode(t *testing.T) {
	secret, _, err := GenerateTOTPKey("person@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if ValidateTOTPCode(secret, "000000") {
		t.Error("an arbitrary 6-digit code should not validate (astronomically unlikely to collide)")
	}
	if ValidateTOTPCode(secret, "") {
		t.Error("an empty code should never validate")
	}
}

func TestGenerateRecoveryCodeFormatAndUniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		code, err := GenerateRecoveryCode()
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != 9 || code[4] != '-' {
			t.Errorf("code %q doesn't match the XXXX-XXXX shape", code)
		}
		if seen[code] {
			t.Fatalf("generated a duplicate code: %q", code)
		}
		seen[code] = true
	}
}

func TestHashRecoveryCodeIsCaseAndWhitespaceInsensitive(t *testing.T) {
	code, err := GenerateRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	base := HashRecoveryCode(code)
	variants := []string{
		strings.ToLower(code),
		"  " + code + "  ",
		strings.ToLower(strings.TrimSpace(code)),
	}
	for _, v := range variants {
		if got := HashRecoveryCode(v); got != base {
			t.Errorf("HashRecoveryCode(%q) = %q, want %q (should match the canonical form)", v, got, base)
		}
	}
	if HashRecoveryCode(code+"X") == base {
		t.Error("a different code should not hash to the same value")
	}
}
