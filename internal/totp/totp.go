// Package totp implements time-based one-time passwords (RFC 6238), the
// scheme used by Google Authenticator, on top of HOTP (RFC 4226).
//
// A code is HMAC-SHA1(secret, floor(unixTime / 30)) truncated to 6 digits.
// SHA-1 is used because Google Authenticator reliably supports only SHA-1;
// HMAC-SHA1 remains a secure MAC because HMAC does not rely on the hash
// being collision resistant.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	// Digits is the length of a code.
	Digits = 6
	// Period is the lifetime of one code in seconds.
	Period = 30
	// SecretSize is 160 bits, the size RFC 4226 recommends for HMAC-SHA1.
	SecretSize = 20
	// Skew is how many steps before or after "now" are accepted, to absorb
	// clock drift between the server and the admin's phone.
	Skew = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a fresh random shared secret.
func NewSecret() []byte {
	s := make([]byte, SecretSize)
	rand.Read(s) // crypto/rand.Read never fails on supported platforms
	return s
}

// EncodeSecret returns the base32 form typed into an authenticator app.
func EncodeSecret(secret []byte) string { return b32.EncodeToString(secret) }

// DecodeSecret parses a base32 secret, ignoring spaces and case.
func DecodeSecret(s string) ([]byte, error) {
	return b32.DecodeString(strings.ToUpper(strings.ReplaceAll(s, " ", "")))
}

// Step returns the RFC 6238 time step that contains t.
func Step(t time.Time) int64 { return t.Unix() / Period }

// CodeAt computes the HOTP value (RFC 4226 §5.3) for one time step.
func CodeAt(secret []byte, step int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	// Dynamic truncation: the low 4 bits of the last byte pick an offset,
	// and 31 bits are read from there (the top bit is masked off).
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// Candidates returns the steps around now that may still be accepted: within
// ±Skew of now and strictly newer than lastUsed, so that every code can be
// used at most once (replay protection).
func Candidates(now time.Time, lastUsed int64) []int64 {
	cur := Step(now)
	var out []int64
	for s := cur - Skew; s <= cur+Skew; s++ {
		if s > lastUsed {
			out = append(out, s)
		}
	}
	return out
}

// Verify checks a typed code. It returns the matching step, which the caller
// must store as the new lastUsed value.
func Verify(secret []byte, code string, now time.Time, lastUsed int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != Digits {
		return 0, false
	}
	for _, s := range Candidates(now, lastUsed) {
		if subtle.ConstantTimeCompare([]byte(CodeAt(secret, s, Digits)), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}

// URI returns the otpauth:// URI that authenticator apps read from a QR code.
func URI(issuer, account string, secret []byte) string {
	q := url.Values{}
	q.Set("secret", EncodeSecret(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(Digits))
	q.Set("period", fmt.Sprint(Period))
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + q.Encode()
}
