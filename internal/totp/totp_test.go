package totp

import (
	"strings"
	"testing"
	"time"
)

// Test vectors from RFC 6238 Appendix B (HMAC-SHA1, 8 digits).
func TestRFC6238Vectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	vectors := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, v := range vectors {
		if got := CodeAt(secret, Step(time.Unix(v.unix, 0)), 8); got != v.want {
			t.Errorf("T=%d: got %s, want %s", v.unix, got, v.want)
		}
	}
}

func TestVerifyAcceptsOnceAndRejectsReplay(t *testing.T) {
	secret := NewSecret()
	now := time.Unix(1_800_000_000, 0)
	code := CodeAt(secret, Step(now), Digits)

	step, ok := Verify(secret, code, now, 0)
	if !ok || step != Step(now) {
		t.Fatalf("valid code rejected")
	}
	if _, ok := Verify(secret, code, now, step); ok {
		t.Fatal("the same code was accepted twice (replay)")
	}
}

func TestVerifyClockSkew(t *testing.T) {
	secret := NewSecret()
	now := time.Unix(1_800_000_000, 0)
	prev := CodeAt(secret, Step(now)-1, Digits)
	old := CodeAt(secret, Step(now)-3, Digits)
	if _, ok := Verify(secret, prev, now, 0); !ok {
		t.Error("code from the previous 30 s window rejected")
	}
	if _, ok := Verify(secret, old, now, 0); ok {
		t.Error("code from 90 s ago accepted")
	}
}

func TestVerifyRejectsWrongCode(t *testing.T) {
	secret := NewSecret()
	now := time.Now()
	good := CodeAt(secret, Step(now), Digits)
	bad := "000000"
	if bad == good {
		bad = "000001"
	}
	if _, ok := Verify(secret, bad, now, 0); ok {
		t.Error("wrong code accepted")
	}
	if _, ok := Verify(secret, "12345", now, 0); ok {
		t.Error("short code accepted")
	}
}

func TestSecretRoundTripAndURI(t *testing.T) {
	s := NewSecret()
	enc := EncodeSecret(s)
	dec, err := DecodeSecret(strings.ToLower(enc[:8]) + " " + enc[8:])
	if err != nil || string(dec) != string(s) {
		t.Fatalf("base32 round trip failed: %v", err)
	}
	uri := URI("CipherDrop", "admin", s)
	if !strings.HasPrefix(uri, "otpauth://totp/CipherDrop:admin?") || !strings.Contains(uri, "secret="+enc) {
		t.Errorf("unexpected URI %s", uri)
	}
}
