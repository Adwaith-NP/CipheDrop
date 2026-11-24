package provision

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"errors"
)

// Wire format of POST /v1/enroll (JSON; []byte fields are base64).
type EnrollRequest struct {
	Slot  string `json:"slot"`
	Token []byte `json:"token"`
	CSR   []byte `json:"csr"`   // DER; the CA takes only the public key from it
	Proof []byte `json:"proof"` // see Proof
	// Renewal only: the device's current certificate and a signature with
	// its current key over RenewSignedBytes, proving it is the same machine.
	OldCert []byte `json:"old_cert,omitempty"`
	OldSig  []byte `json:"old_sig,omitempty"`
}

type EnrollResponse struct {
	Name        string   `json:"name"`
	Department  string   `json:"department"`
	Certificate []byte   `json:"certificate"` // DER
	Chain       [][]byte `json:"chain"`       // DER intermediates, issuing CA first
	Root        []byte   `json:"root"`        // DER root CA
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// ExporterLabel names the TLS exporter output used to bind the 2FA code to
// one TLS session (RFC 5705 labels starting with EXPERIMENTAL are for
// private use).
const ExporterLabel = "EXPERIMENTAL-cipherdrop-enroll"

// Exporter derives 32 bytes that only the two ends of this TLS session can
// compute (RFC 8446 §7.5).
func Exporter(cs tls.ConnectionState) ([]byte, error) {
	if cs.Version != tls.VersionTLS13 {
		return nil, errors.New("TLS 1.3 required")
	}
	return cs.ExportKeyingMaterial(ExporterLabel, nil, 32)
}

// RenewSignedBytes is what a renewing device signs with its current key:
// bound, like Proof, to this TLS session, the slot and the new public key,
// so the signature cannot be replayed or attached to another request.
func RenewSignedBytes(exporter []byte, slotID string, newCSR []byte) []byte {
	h := sha256.Sum256(newCSR)
	b := []byte("cipherdrop-renew-v1\x00")
	b = append(b, exporter...)
	b = append(b, slotID...)
	return append(b, h[:]...)
}

// Proof turns the admin's 6-digit code into a value that is useless outside
// this exact enrolment:
//
//	HMAC-SHA256(key = code, "cipherdrop-enroll-v1" ‖ exporter ‖ slot ‖ SHA-256(CSR))
//
// The code itself never crosses the network. The exporter ties the proof to
// this TLS session, so a relaying attacker who runs a second session cannot
// reuse it, and the CSR hash ties it to this public key, so it cannot be
// attached to a different key. Because a 6-digit code has only 10^6 values,
// the proof is sent only inside the server-authenticated TLS channel, and
// the server allows a handful of attempts per slot.
func Proof(code string, exporter []byte, slotID string, csrDER []byte) []byte {
	mac := hmac.New(sha256.New, []byte(code))
	mac.Write([]byte("cipherdrop-enroll-v1\x00"))
	mac.Write(exporter)
	mac.Write([]byte(slotID))
	h := sha256.Sum256(csrDER)
	mac.Write(h[:])
	return mac.Sum(nil)
}
