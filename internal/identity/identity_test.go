package identity

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"regexp"
	"testing"
)

func TestValidateName(t *testing.T) {
	good := []string{"bob", "alice", "quiet-heron-08", "a1b", "x2345678901234567890123456789012"}
	bad := []string{"", "ab", "Bob", "-bob", "bob-", "bob.lan", "bob_1", "../etc", "x23456789012345678901234567890123", "böb"}
	for _, n := range good {
		if err := ValidateName(n); err != nil {
			t.Errorf("ValidateName(%q) = %v, want ok", n, err)
		}
	}
	for _, n := range bad {
		if ValidateName(n) == nil {
			t.Errorf("ValidateName(%q) accepted a bad name", n)
		}
	}
}

func TestRandomNameIsValid(t *testing.T) {
	for range 200 {
		if n := RandomName(); ValidateName(n) != nil {
			t.Fatalf("RandomName produced invalid name %q", n)
		}
	}
}

func TestCreateCSR(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := CreateCSR("bob", key)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR self-signature invalid: %v", err)
	}
	if csr.Subject.CommonName != "bob" || len(csr.DNSNames) != 1 || csr.DNSNames[0] != "bob.cipherdrop.lan" {
		t.Errorf("CSR subject/SAN = %q %v", csr.Subject.CommonName, csr.DNSNames)
	}
	if csr.SignatureAlgorithm != x509.PureEd25519 {
		t.Errorf("CSR signature algorithm = %v, want Ed25519", csr.SignatureAlgorithm)
	}
	if !key.Public().(ed25519.PublicKey).Equal(csr.PublicKey) {
		t.Error("CSR public key does not match the key")
	}
}

func TestSaveKeyIsPrivateAndNeverOverwrites(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	key, _ := GenerateKey()
	if err := s.SaveKey(key); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.KeyPath())
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %04o, want 0600", perm)
	}
	loaded, err := s.LoadKey()
	if err != nil || !loaded.Equal(key) {
		t.Fatalf("LoadKey: %v", err)
	}
	other, _ := GenerateKey()
	if err := s.SaveKey(other); !errors.Is(err, ErrExists) {
		t.Errorf("second SaveKey = %v, want ErrExists", err)
	}
}

func TestLoadKeyRefusesReadableKey(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	key, _ := GenerateKey()
	if err := s.SaveKey(key); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.KeyPath(), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadKey(); err == nil {
		t.Fatal("LoadKey accepted a world-readable key file")
	}
}

func TestFingerprintMatchesOpenSSLFormat(t *testing.T) {
	cert := &x509.Certificate{Raw: []byte("any bytes")}
	fp := Fingerprint(cert)
	if !regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`).MatchString(fp) {
		t.Errorf("fingerprint %q is not in OpenSSL's XX:XX:... format", fp)
	}
}
