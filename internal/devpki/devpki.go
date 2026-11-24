// Package devpki builds throwaway certificate authorities and device
// certificates in memory. It is used by tests and by the attack tools in
// test/attacks; the real CAs are created with OpenSSL (scripts/pki and the
// control server).
package devpki

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"cipherdrop/internal/identity"
)

// CA is an in-memory certificate authority, either a root or an issuing CA.
type CA struct {
	Cert  *x509.Certificate
	Key   ed25519.PrivateKey
	Pool  *x509.CertPool      // the root this CA chains to
	Chain []*x509.Certificate // intermediates from this CA up to (excluding) the root
}

// Device is a certificate with its private key.
type Device struct {
	Cert *x509.Certificate
	TLS  tls.Certificate // leaf followed by the issuing chain
}

// NewCA creates a self-signed Ed25519 root CA, mirroring ext_root in ca.cnf.
func NewCA(commonName string) (*CA, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := caTemplate(commonName, 1)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &CA{Cert: cert, Key: priv, Pool: pool}, nil
}

// NewIssuing creates an issuing CA signed by ca, mirroring ext_issuing.
func (ca *CA) NewIssuing(commonName string) (*CA, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, caTemplate(commonName, 0), ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: priv, Pool: ca.Pool, Chain: append([]*x509.Certificate{cert}, ca.Chain...)}, nil
}

func caTemplate(cn string, pathLen int) *x509.Certificate {
	now := time.Now()
	// Like a real CA, valid long before and long after the devices it signs.
	return &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.AddDate(-1, 0, 0),
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            pathLen,
		MaxPathLenZero:        pathLen == 0,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
}

// Option changes a device certificate template before it is signed.
type Option func(*x509.Certificate)

// Expired makes the certificate's validity end in the past.
func Expired() Option {
	return func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-48 * time.Hour)
		c.NotAfter = time.Now().Add(-24 * time.Hour)
	}
}

// ValidDays sets the validity to end days from now (negative: already expired).
func ValidDays(days int) Option {
	return func(c *x509.Certificate) {
		c.NotAfter = time.Now().Add(time.Duration(days) * 24 * time.Hour)
		if c.NotBefore.After(c.NotAfter) {
			c.NotBefore = c.NotAfter.Add(-48 * time.Hour)
		}
	}
}

// Department sets the organisational unit, as the control server does.
func Department(d string) Option {
	return func(c *x509.Certificate) { c.Subject.OrganizationalUnit = []string{d} }
}

// Issue signs a device certificate for name with a fresh key.
func (ca *CA) Issue(name string, opts ...Option) (*Device, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	cert, err := ca.sign(name, pub, opts)
	if err != nil {
		return nil, err
	}
	return ca.device(cert, priv), nil
}

// IssueFor signs a device certificate for an existing public key, the way
// the control server signs a CSR: the identity comes from the CA, only the
// key comes from the request.
func (ca *CA) IssueFor(name string, pub crypto.PublicKey, opts ...Option) (*x509.Certificate, error) {
	return ca.sign(name, pub, opts)
}

// SelfSigned creates a device-shaped certificate that no CA vouches for:
// what an attacker would present when pretending to be name.
func SelfSigned(name string) (*Device, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := deviceTemplate(name, nil)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Device{Cert: cert, TLS: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: cert}}, nil
}

func (ca *CA) sign(name string, pub crypto.PublicKey, opts []Option) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, deviceTemplate(name, opts), ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func (ca *CA) device(cert *x509.Certificate, priv ed25519.PrivateKey) *Device {
	raw := [][]byte{cert.Raw}
	if ca.Chain != nil { // issued by an intermediate: send it along
		for _, c := range ca.Chain {
			raw = append(raw, c.Raw)
		}
	}
	return &Device{Cert: cert, TLS: tls.Certificate{Certificate: raw, PrivateKey: priv, Leaf: cert}}
}

func deviceTemplate(name string, opts []Option) *x509.Certificate {
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{identity.HostName(name)},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	for _, o := range opts {
		o(tmpl)
	}
	return tmpl
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n
}
