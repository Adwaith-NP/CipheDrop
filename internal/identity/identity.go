// Package identity creates and stores a device's long-term Ed25519 identity:
// the private key, the certificate signing request sent to the CA, and the
// device name that ends up in the certificate.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DomainSuffix is appended to a device name to form the DNS name in its
// certificate's subjectAltName, e.g. bob -> bob.cipherdrop.lan.
const DomainSuffix = "cipherdrop.lan"

// ErrExists is returned when an identity already exists and would be overwritten.
var ErrExists = errors.New("an identity already exists here; refusing to overwrite it")

// Same rule as scripts/pki/ca-sign.sh: 3-32 chars, lowercase letters, digits, hyphens.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$`)

// ValidateName checks that name is an acceptable device name.
func ValidateName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid device name %q: use 3-32 lowercase letters, digits or hyphens", name)
	}
	return nil
}

// HostName returns the DNS name the CA puts in the device certificate.
func HostName(name string) string { return name + "." + DomainSuffix }

var (
	adjectives = []string{"amber", "brave", "calm", "clever", "cosmic", "crisp", "dusty", "eager",
		"fuzzy", "gentle", "golden", "hidden", "icy", "jolly", "lucky", "mellow", "misty", "nimble",
		"quiet", "rapid", "rusty", "silent", "silver", "sleepy", "snowy", "solar", "swift", "tidy",
		"vivid", "wild", "witty", "zesty"}
	animals = []string{"badger", "bison", "crane", "dingo", "eagle", "falcon", "ferret", "gecko",
		"heron", "ibis", "jackal", "koala", "lemur", "lynx", "marten", "moose", "newt", "ocelot",
		"otter", "owl", "panda", "puffin", "quail", "raven", "seal", "stoat", "tapir", "tern",
		"viper", "walrus", "wombat", "yak"}
)

// RandomName returns a name such as "quiet-heron-08", chosen with the OS CSPRNG.
func RandomName() string {
	pick := func(n int) int {
		v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
		if err != nil {
			panic(err) // crypto/rand does not fail on supported platforms
		}
		return int(v.Int64())
	}
	return fmt.Sprintf("%s-%s-%02d", adjectives[pick(len(adjectives))], animals[pick(len(animals))], pick(100))
}

// GenerateKey creates a new Ed25519 device key.
func GenerateKey() (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

// CreateCSR builds a PEM certificate signing request for name, signed by key.
// The CA ignores everything except the subject CN and the public key, but the
// SAN is included so the request is self-describing.
func CreateCSR(name string, key ed25519.PrivateKey) ([]byte, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: name},
		DNSNames: []string{HostName(name)},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// Fingerprint returns the SHA-256 fingerprint of a certificate in the same
// format as `openssl x509 -noout -fingerprint -sha256`, so users can check one
// against the other.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// Store is the on-disk location of one device's identity.
type Store struct{ Dir string }

func (s Store) KeyPath() string   { return filepath.Join(s.Dir, "identity.key") }
func (s Store) CertPath() string  { return filepath.Join(s.Dir, "identity.crt") }
func (s Store) ChainPath() string { return filepath.Join(s.Dir, "chain.crt") }
func (s Store) CAPath() string    { return filepath.Join(s.Dir, "ca.crt") }

// Exists reports whether a private key is already stored here.
func (s Store) Exists() bool {
	_, err := os.Stat(s.KeyPath())
	return err == nil
}

// SaveKey writes the device key as PKCS#8 PEM with mode 0600. It never
// overwrites an existing key.
//
// The key is protected by file permissions and a dedicated service account.
// It is not passphrase-encrypted, because the CipherDrop service has to start
// unattended; see the report's key management section.
func (s Store) SaveKey(key ed25519.PrivateKey) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	return saveKey(s.KeyPath(), key)
}

// LoadKey reads the device key. Like ssh, it refuses a key file that other
// users can read.
func (s Store) LoadKey() (ed25519.PrivateKey, error) { return s.LoadKeyFrom(s.KeyPath()) }

// LoadKeyFrom reads an Ed25519 key file with the same checks as LoadKey.
func (s Store) LoadKeyFrom(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("no identity in %s; enrol this device first (cipherdrop enroll)", s.Dir)
		}
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("key file %s is accessible by other users (mode %04o); run: chmod 600 %s",
			path, info.Mode().Perm(), path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s: not a PEM PKCS#8 private key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: key is %T, CipherDrop requires Ed25519", path, parsed)
	}
	return key, nil
}

// ReplaceKey atomically swaps in a new device key (key rotation on
// renewal). The old key file is overwritten, not kept: a retired key that
// still exists is a key that can still be stolen.
func (s Store) ReplaceKey(key ed25519.PrivateKey) error {
	tmp := s.KeyPath() + ".new"
	os.Remove(tmp)
	if err := saveKey(tmp, key); err != nil {
		return err
	}
	return os.Rename(tmp, s.KeyPath())
}

func saveKey(path string, key ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrExists
		}
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
