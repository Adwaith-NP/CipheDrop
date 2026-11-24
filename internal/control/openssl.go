package control

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"

	"cipherdrop/internal/identity"
)

// Issuer signs device certificates. In production it is OpenSSL; tests use
// an in-memory CA.
type Issuer interface {
	IssueDevice(csrDER []byte, name, department string, days int) (*x509.Certificate, error)
}

// Superseder records that a renewed certificate replaced an older one.
type Superseder interface {
	RevokeSuperseded(serial string) error
}

// SerialHex formats a serial number the way OpenSSL names it in newcerts/
// (upper-case hex, even length).
func SerialHex(n *big.Int) string {
	s := fmt.Sprintf("%X", n)
	if len(s)%2 == 1 {
		s = "0" + s
	}
	return s
}

// OpenSSL drives the OpenSSL command-line CA ("openssl ca") for the issuing
// CA. OpenSSL owns the CA database (index.txt, serial numbers, CRL), so every
// certificate the control server issues is recorded exactly as a standard
// OpenSSL CA would record it, and can be inspected or revoked with OpenSSL.
type OpenSSL struct {
	Bin        string // usually "openssl"
	Config     string // path to scripts/pki/ca.cnf
	Dir        string // issuing CA directory (CA_HOME)
	Passphrase string // decrypts private/ca.key; lives only in the vault and in memory
	DeviceDays int

	mu sync.Mutex // openssl ca is not safe to run concurrently on one database
}

func (o *OpenSSL) keyPath() string  { return filepath.Join(o.Dir, "private", "ca.key") }
func (o *OpenSSL) certPath() string { return filepath.Join(o.Dir, "ca.crt") }

func (o *OpenSSL) run(deviceName string, args ...string) ([]byte, error) {
	bin := o.Bin
	if bin == "" {
		bin = "openssl"
	}
	cmd := exec.Command(bin, args...)
	if deviceName == "" {
		deviceName = "unused"
	}
	// The passphrase is passed through the environment of this one child
	// process (-passin env:CD_CA_PASS), never on the command line where
	// other users could read it from the process list.
	cmd.Env = append(os.Environ(), "CA_HOME="+o.Dir, "CD_DEVICE_NAME="+deviceName, "CD_CA_PASS="+o.Passphrase)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("openssl %s: %w\n%s", args[0], err, bytes.TrimSpace(out))
	}
	return out, nil
}

// CreateIssuingKey generates the issuing CA's Ed25519 key, encrypted with
// AES-256 under the vault-held passphrase, and writes a CSR for the root CA.
func (o *OpenSSL) CreateIssuingKey(csrOut string) error {
	if err := os.MkdirAll(filepath.Join(o.Dir, "private"), 0o700); err != nil {
		return err
	}
	if _, err := o.run("", "genpkey", "-algorithm", "ed25519", "-aes-256-cbc",
		"-pass", "env:CD_CA_PASS", "-out", o.keyPath()); err != nil {
		return err
	}
	_, err := o.run("", "req", "-new", "-config", o.Config, "-key", o.keyPath(),
		"-passin", "env:CD_CA_PASS", "-subj", "/O=CipherDrop/CN=CipherDrop Issuing CA 1", "-out", csrOut)
	return err
}

// KeyMatches checks that the issuing CA key on disk belongs to cert.
func (o *OpenSSL) KeyMatches(cert *x509.Certificate) error {
	der, err := o.run("", "pkey", "-in", o.keyPath(), "-passin", "env:CD_CA_PASS", "-pubout", "-outform", "DER")
	if err != nil {
		return err
	}
	if !bytes.Equal(der, cert.RawSubjectPublicKeyInfo) {
		return fmt.Errorf("the issuing CA certificate is not for this server's issuing key")
	}
	return nil
}

// InitDatabase installs the signed issuing CA certificate and creates the
// OpenSSL CA database files plus an initial (empty) CRL.
func (o *OpenSSL) InitDatabase(issuing *x509.Certificate) error {
	for _, d := range []string{"newcerts", "certs"} {
		if err := os.MkdirAll(filepath.Join(o.Dir, d), 0o700); err != nil {
			return err
		}
	}
	serial := make([]byte, 16)
	rand.Read(serial)
	files := map[string][]byte{
		"ca.crt":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuing.Raw}),
		"index.txt": nil,
		"serial":    []byte(hex.EncodeToString(serial) + "\n"),
		"crlnumber": []byte("1000\n"),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(o.Dir, name), data, 0o644); err != nil {
			return err
		}
	}
	_, err := o.run("", "ca", "-config", o.Config, "-gencrl", "-crlexts", "ext_crl",
		"-passin", "env:CD_CA_PASS", "-out", filepath.Join(o.Dir, "crl.pem"))
	return err
}

// IssueDevice signs a CSR with the issuing CA. The subject (name and
// department) comes from the admin's slot, never from the CSR; only the
// public key is taken from the request.
func (o *OpenSSL) IssueDevice(csrDER []byte, name, department string, days int) (*x509.Certificate, error) {
	if err := identity.ValidateName(name); err != nil {
		return nil, err
	}
	if err := ValidateDepartment(department); err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()

	tmp, err := os.MkdirTemp("", "cipherdrop-issue-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	in, out := filepath.Join(tmp, "req.csr"), filepath.Join(tmp, "cert.pem")
	if err := os.WriteFile(in, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), 0o600); err != nil {
		return nil, err
	}
	if days == 0 {
		days = o.DeviceDays
	}
	if days == 0 {
		days = 365
	}
	// Name uniqueness is enforced by the control server's slots; OpenSSL must
	// allow two certificates with one subject for the moment of a renewal.
	// (index.txt.attr overrides ca.cnf for CA databases created earlier.)
	os.WriteFile(filepath.Join(o.Dir, "index.txt.attr"), []byte("unique_subject = no\n"), 0o644)
	// Name and department are restricted to [a-z0-9-], so they cannot
	// inject extra fields into the -subj string.
	subj := "/O=CipherDrop/OU=" + department + "/CN=" + name
	if _, err := o.run(name, "ca", "-batch", "-notext", "-config", o.Config, "-extensions", "ext_device",
		"-days", strconv.Itoa(days), "-subj", subj, "-passin", "env:CD_CA_PASS", "-in", in, "-out", out); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(out)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("openssl produced no certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if cert.Subject.CommonName != name {
		return nil, fmt.Errorf("issued certificate has CN %q, expected %q", cert.Subject.CommonName, name)
	}
	return cert, nil
}

// RevokeSuperseded marks a renewed device's previous certificate as revoked
// with reason "superseded" in the OpenSSL database and publishes a new CRL.
func (o *OpenSSL) RevokeSuperseded(serial string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	file := filepath.Join(o.Dir, "newcerts", serial+".pem")
	if _, err := o.run("", "ca", "-config", o.Config, "-revoke", file, "-crl_reason", "superseded",
		"-passin", "env:CD_CA_PASS"); err != nil {
		return err
	}
	_, err := o.run("", "ca", "-config", o.Config, "-gencrl", "-crlexts", "ext_crl",
		"-passin", "env:CD_CA_PASS", "-out", filepath.Join(o.Dir, "crl.pem"))
	return err
}
