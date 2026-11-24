// Package evidence produces signed statements that give CipherDrop
// non-repudiation: proof of origin (a signed manifest or message) and proof
// of delivery (a signed receipt or acknowledgement).
//
// TLS already authenticates both ends during a session, but that proof
// cannot be shown to anyone afterwards: the session keys are ephemeral and
// the data is protected with symmetric MACs that either side could have
// produced. An Ed25519 signature made with a device's certified key can be
// checked later by a third party, so the signer cannot deny it.
//
// Each statement is stored as an Envelope: the exact signed bytes, the
// signature, and the signer's certificate chain. Anyone holding the root CA
// certificate can verify it, including with plain OpenSSL (see Export).
package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"cipherdrop/internal/identity"
	"cipherdrop/internal/trust"
)

// Statement kinds. The kind is signed together with the payload (domain
// separation), so a signature on a chat message can never be presented as a
// signature on a receipt.
const (
	KindManifest   = "cipherdrop-manifest-v1"
	KindReceipt    = "cipherdrop-receipt-v1"
	KindMessage    = "cipherdrop-message-v1"
	KindMessageAck = "cipherdrop-message-ack-v1"
)

// Envelope is a signed statement.
type Envelope struct {
	Kind      string   `json:"kind"`
	Payload   []byte   `json:"payload"`   // JSON statement, exactly as signed
	Signature []byte   `json:"signature"` // Ed25519 over SignedBytes(Kind, Payload)
	Chain     [][]byte `json:"chain"`     // DER: signer certificate, then intermediates
}

// SignedBytes is what the signature covers: kind, a zero byte, payload.
func SignedBytes(kind string, payload []byte) []byte {
	b := make([]byte, 0, len(kind)+1+len(payload))
	b = append(b, kind...)
	b = append(b, 0)
	return append(b, payload...)
}

// Sign serialises statement and signs it with the device key. chain is the
// device's TLS certificate chain (leaf first).
func Sign(kind string, statement any, key ed25519.PrivateKey, chain [][]byte) (*Envelope, error) {
	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, err
	}
	return &Envelope{
		Kind:      kind,
		Payload:   payload,
		Signature: ed25519.Sign(key, SignedBytes(kind, payload)),
		Chain:     chain,
	}, nil
}

// Digest is the SHA-256 of the payload, used to reference a statement from
// another one (a receipt names the manifest it confirms).
func (e *Envelope) Digest() string {
	sum := sha256.Sum256(e.Payload)
	return hex.EncodeToString(sum[:])
}

// Signer parses the signer's certificate.
func (e *Envelope) Signer() (*x509.Certificate, error) {
	if len(e.Chain) == 0 {
		return nil, errors.New("statement carries no signer certificate")
	}
	return x509.ParseCertificate(e.Chain[0])
}

// Verify checks that the signer's certificate chains to roots and is valid
// at time at (normally the time the statement claims it was made), and that
// the signature over kind and payload is correct. It returns the signer.
func (e *Envelope) Verify(kind string, roots *x509.CertPool, at time.Time) (*x509.Certificate, error) {
	if e.Kind != kind {
		return nil, fmt.Errorf("expected a %s statement, got %q", kind, e.Kind)
	}
	leaf, err := e.Signer()
	if err != nil {
		return nil, err
	}
	inter := x509.NewCertPool()
	for _, der := range e.Chain[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		inter.AddCert(c)
	}
	if err := trust.VerifyDevice(leaf, roots, inter, at); err != nil {
		return nil, fmt.Errorf("signer certificate not trusted: %w", err)
	}
	pub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("signer key is not Ed25519")
	}
	if !ed25519.Verify(pub, SignedBytes(e.Kind, e.Payload), e.Signature) {
		return nil, errors.New("SIGNATURE INVALID: the statement was altered or not signed by this key")
	}
	return leaf, nil
}

// Decode unmarshals the payload into v.
func (e *Envelope) Decode(v any) error { return json.Unmarshal(e.Payload, v) }

// Save writes the envelope as JSON.
func (e *Envelope) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// Load reads an envelope file.
func Load(path string) (*Envelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var e Envelope
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("%s: not a CipherDrop evidence file: %w", path, err)
	}
	return &e, nil
}

// Export writes the pieces needed to verify the statement with OpenSSL alone:
//
//	signed.bin     the exact bytes that were signed
//	signature.bin  the 64-byte Ed25519 signature
//	signer.pem     the signer's certificate
//	chain.pem      the intermediate CA certificate(s)
func (e *Envelope) Export(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if len(e.Chain) == 0 {
		return errors.New("no signer certificate to export")
	}
	var chain []byte
	for _, der := range e.Chain[1:] {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	files := map[string][]byte{
		"signed.bin":    SignedBytes(e.Kind, e.Payload),
		"signature.bin": e.Signature,
		"signer.pem":    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.Chain[0]}),
		"chain.pem":     chain,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Party identifies a device in a statement.
type Party struct {
	Name        string `json:"name"`
	Department  string `json:"department,omitempty"`
	Fingerprint string `json:"fingerprint"` // SHA-256 of its certificate
}

// PartyOf describes the device that holds cert.
func PartyOf(cert *x509.Certificate) Party {
	return Party{Name: cert.Subject.CommonName, Department: trust.Department(cert), Fingerprint: identity.Fingerprint(cert)}
}
