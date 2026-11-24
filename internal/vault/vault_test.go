package vault

import (
	"errors"
	"testing"
)

// Cheap parameters keep the tests fast; production uses Default.
var fast = Params{Time: 1, MemoryKiB: 19 * 1024, Threads: 1}

func TestSealOpen(t *testing.T) {
	pw := []byte("correct horse battery staple")
	s, err := Seal(pw, []byte("totp seed"), fast)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Open(pw, s)
	if err != nil || string(pt) != "totp seed" {
		t.Fatalf("Open = %q, %v", pt, err)
	}
}

func TestWrongPassword(t *testing.T) {
	s, _ := Seal([]byte("correct horse battery staple"), []byte("x"), fast)
	if _, err := Open([]byte("correct horse battery stapl3"), s); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("wrong password: err = %v", err)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	pw := []byte("correct horse battery staple")
	cases := map[string]func(*Sealed){
		"ciphertext bit flip": func(s *Sealed) { s.Ciphertext[0] ^= 1 },
		"salt changed":        func(s *Sealed) { s.Salt[0] ^= 1 },
		"KDF weakened":        func(s *Sealed) { s.Params.Time++ }, // still >= minimum, so only the AD catches it
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := Seal(pw, []byte("secret"), fast)
			mutate(s)
			if _, err := Open(pw, s); err == nil {
				t.Fatal("tampered vault opened")
			}
		})
	}
}

func TestShortPasswordRefused(t *testing.T) {
	if _, err := Seal([]byte("short"), []byte("x"), fast); err == nil {
		t.Fatal("short password accepted")
	}
}
