package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/quic-go/quic-go"

	"cipherdrop/internal/identity"
)

// QUICConfig returns the transport settings shared by both sides.
func QUICConfig() *quic.Config {
	return &quic.Config{
		// 0-RTT data can be replayed by an attacker (RFC 8446 §8), so it is off.
		Allow0RTT:             false,
		HandshakeIdleTimeout:  10 * time.Second,
		MaxIdleTimeout:        30 * time.Second,
		KeepAlivePeriod:       10 * time.Second,
		MaxIncomingStreams:    16,
		MaxIncomingUniStreams: 16,
		// Flow-control windows sized for a LAN; quic-go grows windows up to these.
		MaxStreamReceiveWindow:     16 << 20,
		MaxConnectionReceiveWindow: 64 << 20,
	}
}

// Listen starts a QUIC listener on addr (for example ":47475").
func Listen(addr string, tlsConf *tls.Config) (*quic.Listener, error) {
	return quic.ListenAddr(addr, tlsConf, QUICConfig())
}

// Dial connects to addr and completes the TLS 1.3 handshake.
func Dial(ctx context.Context, addr string, tlsConf *tls.Config) (*quic.Conn, error) {
	return quic.DialAddr(ctx, addr, tlsConf, QUICConfig())
}

// sasLabel is the TLS exporter label for the verification code. RFC 5705
// reserves labels starting with "EXPERIMENTAL" for private use.
const sasLabel = "EXPERIMENTAL-cipherdrop-sas"

// VerificationCode derives a 6-digit short authentication string from the
// TLS exporter (RFC 8446 §7.5). Both ends get the same code only if they
// share the same session keys, so a man in the middle, who must run two
// separate sessions, shows different codes on the two screens.
func VerificationCode(cs tls.ConnectionState) (string, error) {
	b, err := cs.ExportKeyingMaterial(sasLabel, nil, 8)
	if err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint64(b) % 1_000_000
	return fmt.Sprintf("%03d %03d", n/1000, n%1000), nil
}

// Session describes an established, verified connection.
type Session struct {
	PeerName        string
	PeerDepartment  string
	PeerHost        string
	PeerFingerprint string
	TLSVersion      string
	CipherSuite     string
	KeyExchange     string
	ALPN            string
	QUICVersion     string
	Used0RTT        bool
	Code            string
}

// Describe reads the negotiated parameters of conn.
func Describe(conn *quic.Conn) (Session, error) {
	st := conn.ConnectionState()
	cs := st.TLS
	if len(cs.PeerCertificates) == 0 {
		return Session{}, fmt.Errorf("no peer certificate")
	}
	leaf := cs.PeerCertificates[0]
	code, err := VerificationCode(cs)
	if err != nil {
		return Session{}, err
	}
	return Session{
		PeerName:        leaf.Subject.CommonName,
		PeerDepartment:  department(leaf),
		PeerHost:        identity.HostName(leaf.Subject.CommonName),
		PeerFingerprint: identity.Fingerprint(leaf),
		TLSVersion:      tls.VersionName(cs.Version),
		CipherSuite:     tls.CipherSuiteName(cs.CipherSuite),
		KeyExchange:     cs.CurveID.String(),
		ALPN:            cs.NegotiatedProtocol,
		QUICVersion:     st.Version.String(),
		Used0RTT:        st.Used0RTT,
		Code:            code,
	}, nil
}

func department(c *x509.Certificate) string {
	if len(c.Subject.OrganizationalUnit) > 0 {
		return c.Subject.OrganizationalUnit[0]
	}
	return ""
}

// Print writes a human-readable summary of the session.
func (s Session) Print(w io.Writer) {
	fmt.Fprintf(w, "secure session established\n")
	fmt.Fprintf(w, "  peer           %s (%s)", s.PeerName, s.PeerHost)
	if s.PeerDepartment != "" {
		fmt.Fprintf(w, ", department %s", s.PeerDepartment)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  fingerprint    %s\n", s.PeerFingerprint)
	fmt.Fprintf(w, "  TLS            %s, %s\n", s.TLSVersion, s.CipherSuite)
	fmt.Fprintf(w, "  key exchange   %s\n", s.KeyExchange)
	fmt.Fprintf(w, "  ALPN           %s\n", s.ALPN)
	fmt.Fprintf(w, "  QUIC           %s, 0-RTT used: %t\n", s.QUICVersion, s.Used0RTT)
	fmt.Fprintf(w, "  verify code    %s   (must match the other screen)\n", s.Code)
}
