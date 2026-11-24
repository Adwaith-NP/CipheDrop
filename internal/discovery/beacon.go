// Package discovery lets CipherDrop devices find each other on the LAN.
//
// Every running console broadcasts a small signed beacon on UDP 47474:
// "I am bob, here is my certificate, reach me on QUIC port 47475". A device
// that hears a new beacon answers straight away with its own (a reply), so
// both sides learn about each other within milliseconds.
//
// A beacon is only a claim. It is accepted as "seen" when its certificate
// chains to the organisation's root CA, the name matches the certificate,
// the Ed25519 signature is valid, and it is fresh and not replayed. It
// becomes "verified" only after the two devices complete a mutual TLS 1.3
// handshake, which proves that the far end holds the private key right now.
// A replayed or forged beacon can therefore never produce a verified peer.
package discovery

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"cipherdrop/internal/identity"
	"cipherdrop/internal/trust"
)

const (
	// Port is the UDP port for beacons.
	Port = 47474
	// Interval is how often a device announces itself.
	Interval = 3 * time.Second
	// MaxAge is how old (or how far in the future) a beacon may be.
	MaxAge = 30 * time.Second
	// MaxSize bounds a beacon datagram.
	MaxSize = 2048

	signContext = "cipherdrop-beacon-v1"
)

// Beacon kinds.
const (
	Announce = "announce" // periodic broadcast
	Reply    = "reply"    // unicast answer to a newcomer's announce
)

// Beacon is the signed announcement.
type Beacon struct {
	V     int    `json:"v"`
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Port  int    `json:"port"`  // QUIC port to connect to
	Time  int64  `json:"time"`  // unix milliseconds, for freshness
	Nonce string `json:"nonce"` // 128 random bits, for replay detection
	Cert  []byte `json:"cert"`  // DER device certificate
	Sig   []byte `json:"sig,omitempty"`
}

// signedBytes is what the signature covers: a context label (so a beacon
// signature can never be confused with any other CipherDrop signature) and
// the beacon without its signature.
func signedBytes(b Beacon) []byte {
	b.Sig = nil
	j, _ := json.Marshal(b)
	return append([]byte(signContext+"\x00"), j...)
}

// Make builds and signs a beacon. cert and key are the device's identity.
func Make(kind, name string, quicPort int, cert *x509.Certificate, key ed25519.PrivateKey, now time.Time) ([]byte, error) {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	b := Beacon{V: 1, Kind: kind, Name: name, Port: quicPort, Time: now.UnixMilli(),
		Nonce: hex.EncodeToString(nonce), Cert: cert.Raw}
	b.Sig = ed25519.Sign(key, signedBytes(b))
	return json.Marshal(b)
}

// Verdict is the result of checking one received beacon.
type Verdict struct {
	OK          bool
	Self        bool   // our own beacon, echoed back by the broadcast
	Reason      string // why it was rejected, when !OK
	Kind        string
	Name        string // as claimed; sanitise before printing
	Department  string
	Fingerprint string
	FromIP      string
	QUICAddr    string // FromIP:Port, where to connect
	Cert        *x509.Certificate
}

// Verifier checks beacons against the organisation's PKI and remembers
// nonces to catch replays.
type Verifier struct {
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	SelfFP        string

	mu   sync.Mutex
	seen map[string]time.Time
}

// Check verifies one datagram received from from.
func (v *Verifier) Check(data []byte, from *net.UDPAddr, now time.Time) Verdict {
	out := Verdict{FromIP: from.IP.String()}
	if len(data) > MaxSize {
		out.Reason = "oversized beacon"
		return out
	}
	var b Beacon
	if err := json.Unmarshal(data, &b); err != nil || b.V != 1 {
		out.Reason = "malformed beacon"
		return out
	}
	out.Kind, out.Name = b.Kind, b.Name
	if b.Kind != Announce && b.Kind != Reply {
		out.Reason = "unknown beacon kind"
		return out
	}
	cert, err := x509.ParseCertificate(b.Cert)
	if err != nil {
		out.Reason = "unreadable certificate"
		return out
	}
	out.Cert, out.Fingerprint = cert, identity.Fingerprint(cert)
	out.Department = trust.Department(cert)
	if out.Fingerprint == v.SelfFP {
		out.Self = true
		return out
	}
	if err := trust.VerifyDevice(cert, v.Roots, v.Intermediates, now); err != nil {
		out.Reason = "certificate not trusted: " + err.Error()
		return out
	}
	if cert.Subject.CommonName != b.Name {
		out.Reason = fmt.Sprintf("claims to be %q but the certificate belongs to %q", b.Name, cert.Subject.CommonName)
		return out
	}
	if !ed25519.Verify(cert.PublicKey.(ed25519.PublicKey), signedBytes(b), b.Sig) {
		out.Reason = "signature invalid (beacon altered)"
		return out
	}
	age := now.Sub(time.UnixMilli(b.Time))
	if age > MaxAge || age < -MaxAge {
		out.Reason = fmt.Sprintf("stale beacon (%s old): possible replay", age.Round(time.Second))
		return out
	}
	if b.Port < 1 || b.Port > 65535 {
		out.Reason = "invalid port"
		return out
	}
	if !v.fresh(b.Nonce, now) {
		out.Reason = "replayed beacon (nonce already seen)"
		return out
	}
	out.OK = true
	out.QUICAddr = net.JoinHostPort(out.FromIP, fmt.Sprint(b.Port))
	return out
}

// fresh records a nonce and reports whether it was unseen.
func (v *Verifier) fresh(nonce string, now time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen == nil {
		v.seen = map[string]time.Time{}
	}
	for n, t := range v.seen { // forget nonces older than the freshness window
		if now.Sub(t) > 2*MaxAge {
			delete(v.seen, n)
		}
	}
	if len(nonce) != 32 {
		return false
	}
	if _, dup := v.seen[nonce]; dup {
		return false
	}
	v.seen[nonce] = now
	return true
}

// ErrClosed is returned once the service has been stopped.
var ErrClosed = errors.New("discovery stopped")
