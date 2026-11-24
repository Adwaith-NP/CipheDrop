// Package trust decides which certificates CipherDrop accepts.
//
// The chain of trust has three levels:
//
//	CipherDrop Root CA      offline; its fingerprint is pinned in every device
//	  └ Issuing CA          on the control server; signs device certificates
//	      └ device          e.g. alice, one Ed25519 key per machine
package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"cipherdrop/internal/identity"
)

// ParseCertsPEM parses one or more PEM certificates.
func ParseCertsPEM(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(bytes.TrimSpace(data)) != 0 || len(out) == 0 {
		return nil, errors.New("not a PEM certificate file")
	}
	return out, nil
}

// LoadCertFile reads exactly one PEM certificate.
func LoadCertFile(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	certs, err := ParseCertsPEM(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("%s: expected one certificate, found %d", path, len(certs))
	}
	return certs[0], nil
}

// CheckRoot confirms that c is a self-signed CA certificate.
func CheckRoot(c *x509.Certificate) error {
	if !c.BasicConstraintsValid || !c.IsCA {
		return errors.New("root certificate is not a CA")
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		return fmt.Errorf("root certificate is not self-signed: %w", err)
	}
	return nil
}

// Pool returns a certificate pool containing certs.
func Pool(certs ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range certs {
		p.AddCert(c)
	}
	return p
}

// VerifyDevice applies CipherDrop's certificate policy to a device
// certificate: Ed25519 key, valid name, SAN matching the name, both TLS
// usages, and a chain through intermediates to roots that is valid at now.
func VerifyDevice(cert *x509.Certificate, roots, intermediates *x509.CertPool, now time.Time) error {
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		return fmt.Errorf("certificate key is %T, CipherDrop requires Ed25519", cert.PublicKey)
	}
	name := cert.Subject.CommonName
	if err := identity.ValidateName(name); err != nil {
		return err
	}
	for _, eku := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if !slices.Contains(cert.ExtKeyUsage, eku) {
			return errors.New("certificate must allow both serverAuth and clientAuth")
		}
	}
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       identity.HostName(name),
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

// Department returns the certificate's organisational unit, set by the CA
// from the enrolment slot.
func Department(c *x509.Certificate) string {
	if len(c.Subject.OrganizationalUnit) > 0 {
		return c.Subject.OrganizationalUnit[0]
	}
	return ""
}

// Local is this device's identity, ready for TLS.
type Local struct {
	Name       string
	Department string
	Cert       *x509.Certificate
	Chain      []*x509.Certificate // intermediates, leaf's issuer first
	Root       *x509.Certificate
	Roots      *x509.CertPool
	TLS        tls.Certificate // leaf + intermediates, sent in every handshake
}

// Fingerprint returns the SHA-256 fingerprint of the local certificate.
func (l *Local) Fingerprint() string { return identity.Fingerprint(l.Cert) }

func assemble(key ed25519.PrivateKey, leaf *x509.Certificate, chain []*x509.Certificate, root *x509.Certificate) (*Local, error) {
	if err := CheckRoot(root); err != nil {
		return nil, err
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return nil, errors.New("the certificate does not belong to this device's private key")
	}
	roots := Pool(root)
	if err := VerifyDevice(leaf, roots, Pool(chain...), time.Now()); err != nil {
		return nil, fmt.Errorf("device certificate rejected: %w", err)
	}
	raw := [][]byte{leaf.Raw}
	for _, c := range chain {
		raw = append(raw, c.Raw)
	}
	return &Local{
		Name:       leaf.Subject.CommonName,
		Department: Department(leaf),
		Cert:       leaf,
		Chain:      chain,
		Root:       root,
		Roots:      roots,
		TLS:        tls.Certificate{Certificate: raw, PrivateKey: key, Leaf: leaf},
	}, nil
}

// Install verifies a freshly issued identity and writes it to store: the
// private key (0600), the device certificate, the intermediate chain and the
// root. Nothing is written unless every check passes.
func Install(store identity.Store, key ed25519.PrivateKey, leaf *x509.Certificate, chain []*x509.Certificate, root *x509.Certificate) (*Local, error) {
	local, err := assemble(key, leaf, chain, root)
	if err != nil {
		return nil, err
	}
	if err := store.SaveKey(key); err != nil {
		return nil, err
	}
	if err := writeAtomic(store.CAPath(), pemCerts(root)); err != nil {
		return nil, err
	}
	if err := writeAtomic(store.ChainPath(), pemCerts(chain...)); err != nil {
		return nil, err
	}
	if err := writeAtomic(store.CertPath(), pemCerts(leaf)); err != nil {
		return nil, err
	}
	return local, nil
}

// Replace installs a renewed identity: new key (the old one is destroyed),
// new certificate and chain. The old certificate is kept in retired/ for
// the record, since evidence signed earlier names it.
func Replace(store identity.Store, key ed25519.PrivateKey, leaf *x509.Certificate, chain []*x509.Certificate, root *x509.Certificate) (*Local, error) {
	local, err := assemble(key, leaf, chain, root)
	if err != nil {
		return nil, err
	}
	if old, err := LoadCertFile(store.CertPath()); err == nil {
		dir := filepath.Join(store.Dir, "retired")
		os.MkdirAll(dir, 0o700)
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("%X.crt", old.SerialNumber)), pemCerts(old), 0o644)
	}
	if err := store.ReplaceKey(key); err != nil {
		return nil, err
	}
	if err := writeAtomic(store.ChainPath(), pemCerts(chain...)); err != nil {
		return nil, err
	}
	if err := writeAtomic(store.CertPath(), pemCerts(leaf)); err != nil {
		return nil, err
	}
	return local, nil
}

// LoadForRenewal loads the current key and certificate without checking
// expiry, because a device may need renewing after its certificate expired.
func LoadForRenewal(store identity.Store) (key ed25519.PrivateKey, cert, root *x509.Certificate, err error) {
	if key, err = store.LoadKey(); err != nil {
		return
	}
	if cert, err = LoadCertFile(store.CertPath()); err != nil {
		return
	}
	root, err = LoadCertFile(store.CAPath())
	return
}

// LoadLocal loads the installed identity and re-checks it, so an expired or
// mismatched certificate is caught at start-up rather than mid-handshake.
func LoadLocal(store identity.Store) (*Local, error) {
	key, err := store.LoadKey()
	if err != nil {
		return nil, err
	}
	root, err := LoadCertFile(store.CAPath())
	if err != nil {
		return nil, fmt.Errorf("no root CA installed (%w); enrol this device first", err)
	}
	leaf, err := LoadCertFile(store.CertPath())
	if err != nil {
		return nil, fmt.Errorf("no device certificate installed (%w); enrol this device first", err)
	}
	var chain []*x509.Certificate
	if data, err := os.ReadFile(store.ChainPath()); err == nil && len(bytes.TrimSpace(data)) > 0 {
		if chain, err = ParseCertsPEM(data); err != nil {
			return nil, fmt.Errorf("%s: %w", store.ChainPath(), err)
		}
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, fmt.Errorf("this device's certificate expired on %s. Ask the admin to renew it "+
			"(root> renew %s) and run the renewal link here: sudo cipherdrop-bootstrap '<link>'",
			leaf.NotAfter.Local().Format("Jan 2 2006 15:04"), leaf.Subject.CommonName)
	}
	return assemble(key, leaf, chain, root)
}

func pemCerts(certs ...*x509.Certificate) []byte {
	var b bytes.Buffer
	for _, c := range certs {
		pem.Encode(&b, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return b.Bytes()
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
