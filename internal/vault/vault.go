// Package vault seals small secrets under a password.
//
// Argon2id (RFC 9106) stretches the password into a 256-bit key, and
// XChaCha20-Poly1305 encrypts and authenticates the secrets with it. The KDF
// parameters and salt are bound into the AEAD's associated data, so nobody
// can quietly weaken them in the file: any change makes decryption fail.
package vault

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Params are the Argon2id cost settings.
type Params struct {
	Time      uint32 `json:"t"`
	MemoryKiB uint32 `json:"m"`
	Threads   uint8  `json:"p"`
}

// Default is RFC 9106's second recommended option: t=3, m=64 MiB, p=4.
var Default = Params{Time: 3, MemoryKiB: 64 * 1024, Threads: 4}

// ErrWrongPassword is returned when the password is wrong or the file was tampered with.
var ErrWrongPassword = errors.New("wrong password, or the vault file was modified")

// Sealed is the on-disk form of a vault.
type Sealed struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Params     Params `json:"params"`
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func (s *Sealed) associatedData() []byte {
	p, _ := json.Marshal(s.Params)
	ad := []byte(fmt.Sprintf("cipherdrop-vault-v%d|%s|", s.Version, s.KDF))
	ad = append(ad, p...)
	return append(ad, s.Salt...)
}

func deriveKey(password []byte, salt []byte, p Params) []byte {
	return argon2.IDKey(password, salt, p.Time, p.MemoryKiB, p.Threads, chacha20poly1305.KeySize)
}

// Seal encrypts plaintext under password.
func Seal(password, plaintext []byte, p Params) (*Sealed, error) {
	if len(password) < 12 {
		return nil, errors.New("password must be at least 12 characters")
	}
	s := &Sealed{Version: 1, KDF: "argon2id", Params: p,
		Salt: make([]byte, 16), Nonce: make([]byte, chacha20poly1305.NonceSizeX)}
	rand.Read(s.Salt)
	rand.Read(s.Nonce) // 192-bit nonce: safe to pick at random
	aead, err := chacha20poly1305.NewX(deriveKey(password, s.Salt, p))
	if err != nil {
		return nil, err
	}
	s.Ciphertext = aead.Seal(nil, s.Nonce, plaintext, s.associatedData())
	return s, nil
}

// Open decrypts a sealed vault.
func Open(password []byte, s *Sealed) ([]byte, error) {
	if s.Version != 1 || s.KDF != "argon2id" {
		return nil, fmt.Errorf("unsupported vault format %d/%s", s.Version, s.KDF)
	}
	if s.Params.MemoryKiB < 19*1024 || s.Params.Time < 1 {
		return nil, errors.New("vault KDF parameters are below the safe minimum")
	}
	aead, err := chacha20poly1305.NewX(deriveKey(password, s.Salt, s.Params))
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, s.Nonce, s.Ciphertext, s.associatedData())
	if err != nil {
		return nil, ErrWrongPassword
	}
	return pt, nil
}

// SaveFile writes a sealed vault with mode 0600.
func SaveFile(path string, s *Sealed) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// LoadFile reads a sealed vault.
func LoadFile(path string) (*Sealed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Sealed
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}
