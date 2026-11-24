package control

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"cipherdrop/internal/identity"
	"cipherdrop/internal/provision"
	"cipherdrop/internal/trust"
)

// InstallIssuing takes the issuing CA certificate signed by the offline root,
// checks it, prepares the OpenSSL CA database, and issues the control
// server's own TLS certificate. After this the server can enrol devices.
func (s *Session) InstallIssuing(issuingPath, rootPath string, ossl *OpenSSL) (*x509.Certificate, error) {
	root, err := trust.LoadCertFile(rootPath)
	if err != nil {
		return nil, err
	}
	if err := trust.CheckRoot(root); err != nil {
		return nil, err
	}
	issuing, err := trust.LoadCertFile(issuingPath)
	if err != nil {
		return nil, err
	}
	if !issuing.IsCA || !issuing.MaxPathLenZero {
		return nil, fmt.Errorf("issuing certificate must be a CA with pathlen 0")
	}
	if _, err := issuing.Verify(x509.VerifyOptions{
		Roots: trust.Pool(root), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("issuing CA does not chain to the root: %w", err)
	}
	ossl.Dir, ossl.Passphrase = s.Paths.IssuingDir(), s.Secrets.CAPassphrase
	if err := ossl.KeyMatches(issuing); err != nil {
		return nil, err
	}
	if err := ossl.InitDatabase(issuing); err != nil {
		return nil, err
	}
	if err := os.WriteFile(s.Paths.Root(), pemCert(root), 0o644); err != nil {
		return nil, err
	}

	// The control server is itself a device, so it gets a certificate from
	// its own issuing CA like everyone else.
	tlsKey, err := (identity.Store{Dir: s.Paths.Dir}).LoadKeyFrom(s.Paths.TLSKey())
	if err != nil {
		return nil, err
	}
	csrPEM, err := identity.CreateCSR(s.Config.Name, tlsKey)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(csrPEM)
	cert, err := ossl.IssueDevice(block.Bytes, s.Config.Name, "infrastructure", DefaultDays)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(s.Paths.TLSCert(), pemCert(cert), 0o644); err != nil {
		return nil, err
	}
	pin := provision.SPKIHash(cert)
	s.Audit.Append("admin", "issuing_ca_installed", map[string]string{
		"issuing_fingerprint": identity.Fingerprint(issuing),
		"root_fingerprint":    identity.Fingerprint(root),
		"server_key_pin":      fmt.Sprintf("%x", pin),
	})
	return issuing, nil
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// DeviceLocal returns the control server's own device identity (its TLS
// certificate under the issuing CA), used to check beacons on the network.
func (s *Session) DeviceLocal() (*trust.Local, error) {
	key, err := identity.Store{}.LoadKeyFrom(s.Paths.TLSKey())
	if err != nil {
		return nil, err
	}
	leaf, err := trust.LoadCertFile(s.Paths.TLSCert())
	if err != nil {
		return nil, err
	}
	issuing, err := trust.LoadCertFile(filepath.Join(s.Paths.IssuingDir(), "ca.crt"))
	if err != nil {
		return nil, err
	}
	root, err := trust.LoadCertFile(s.Paths.Root())
	if err != nil {
		return nil, err
	}
	return &trust.Local{Name: leaf.Subject.CommonName, Department: trust.Department(leaf), Cert: leaf,
		Chain: []*x509.Certificate{issuing}, Root: root, Roots: trust.Pool(root),
		TLS: tls.Certificate{Certificate: [][]byte{leaf.Raw, issuing.Raw}, PrivateKey: key, Leaf: leaf}}, nil
}

// IssuedCert reads a certificate the issuing CA wrote to OpenSSL's
// newcerts directory, by serial number.
func (p Paths) IssuedCert(serial string) (*x509.Certificate, error) {
	return trust.LoadCertFile(filepath.Join(p.IssuingDir(), "newcerts", serial+".pem"))
}
