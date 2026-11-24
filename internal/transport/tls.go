// Package transport builds CipherDrop's secure channel: QUIC (RFC 9000)
// protected by TLS 1.3 (RFC 9001) with mutual certificate authentication
// against the private CA and an ephemeral X25519 (ECDHE) key exchange.
package transport

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"

	"cipherdrop/internal/identity"
)

// ALPN identifies the CipherDrop protocol inside the TLS handshake, so a
// CipherDrop endpoint can never be confused with another QUIC service.
const ALPN = "cipherdrop/1"

// KeyExchange is the only key-exchange group CipherDrop allows: ephemeral
// elliptic-curve Diffie-Hellman on X25519 (RFC 7748), the standard TLS 1.3
// group. A fresh key pair per connection gives forward secrecy. Both ends run
// this binary, so allowing exactly one group leaves nothing to negotiate down.
const KeyExchange = tls.X25519

func baseConfig(local tls.Certificate, keyLog io.Writer) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{local},
		CurvePreferences:       []tls.CurveID{KeyExchange},
		NextProtos:             []string{ALPN},
		SessionTicketsDisabled: true, // every connection does a full, mutually authenticated handshake
		KeyLogWriter:           keyLog,
	}
}

// ServerConfig is used by the receiving side. Go's TLS stack verifies the
// sender's certificate chain against roots (RequireAndVerifyClientCert);
// VerifyConnection then applies the CipherDrop policy on top.
func ServerConfig(local tls.Certificate, roots *x509.CertPool, keyLog io.Writer) *tls.Config {
	cfg := baseConfig(local, keyLog)
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = roots
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		return checkPolicy(cs)
	}
	return cfg
}

// ClientConfig is used by the sending side to reach the device called peer.
// The receiver's certificate must chain to roots and carry peer's DNS name.
// If pin is not empty, its SHA-256 fingerprint must also equal pin, which
// binds the connection to the exact device that was discovered.
func ClientConfig(local tls.Certificate, roots *x509.CertPool, peer, pin string, keyLog io.Writer) *tls.Config {
	cfg := baseConfig(local, keyLog)
	cfg.RootCAs = roots
	cfg.ServerName = identity.HostName(peer)
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if err := checkPolicy(cs); err != nil {
			return err
		}
		if pin != "" {
			got := identity.Fingerprint(cs.PeerCertificates[0])
			if !strings.EqualFold(got, pin) {
				return fmt.Errorf("peer certificate fingerprint %s does not match the expected %s", got, pin)
			}
		}
		return nil
	}
	return cfg
}

// checkPolicy runs after the standard chain verification, on both sides.
func checkPolicy(cs tls.ConnectionState) error {
	if cs.Version != tls.VersionTLS13 {
		return errors.New("TLS 1.3 required")
	}
	if cs.NegotiatedProtocol != ALPN {
		return fmt.Errorf("unexpected application protocol %q", cs.NegotiatedProtocol)
	}
	if len(cs.PeerCertificates) == 0 {
		return errors.New("peer sent no certificate")
	}
	leaf := cs.PeerCertificates[0]
	if _, ok := leaf.PublicKey.(ed25519.PublicKey); !ok {
		return fmt.Errorf("peer key is %T, CipherDrop requires Ed25519", leaf.PublicKey)
	}
	name := leaf.Subject.CommonName
	if err := identity.ValidateName(name); err != nil {
		return fmt.Errorf("peer certificate: %w", err)
	}
	if err := leaf.VerifyHostname(identity.HostName(name)); err != nil {
		return fmt.Errorf("peer certificate SAN does not match its name %q", name)
	}
	return nil
}
