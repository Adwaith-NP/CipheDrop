// Package provision is the zero-trust enrolment protocol between a new
// machine and the control server.
//
// The admin creates a slot on the control server and gets a one-time link:
//
//	cipherdrop://192.168.56.2:47480/enroll/<slot>?t=<token>&pin=<spki>&ca=<root>
//
//	slot   identifies the pre-registered machine (public)
//	t      128-bit one-time secret; the server keeps only its SHA-256 hash
//	pin    SHA-256 of the control server's public key: the new machine
//	       refuses any server that cannot prove it holds this key
//	ca     SHA-256 fingerprint of the root CA the machine will trust
//
// The link alone is not enough to enrol: the admin must also type a live
// Google Authenticator code on the new machine.
package provision

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// DefaultPort is the control server's HTTPS port.
const DefaultPort = 47480

var (
	b64      = base64.RawURLEncoding
	slotIDRe = regexp.MustCompile(`^[0-9a-f]{16}$`)
)

// Link is a parsed enrolment link.
type Link struct {
	Host   string // host:port of the control server
	SlotID string
	Token  []byte
	Pin    [32]byte // SHA-256 of the control server's SubjectPublicKeyInfo
	CARoot [32]byte // SHA-256 of the root CA certificate
	Renew  bool     // the link renews an enrolled device instead of adding one
}

// NewSlotID returns a random 64-bit slot identifier in hex.
func NewSlotID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// NewToken returns a random 128-bit one-time token.
func NewToken() []byte {
	b := make([]byte, 16)
	rand.Read(b)
	return b
}

// SPKIHash returns the SHA-256 of a certificate's public key, the value
// that curl --pinnedpubkey and the link's pin use.
func SPKIHash(c *x509.Certificate) [32]byte { return sha256.Sum256(c.RawSubjectPublicKeyInfo) }

// String formats the link.
func (l Link) String() string {
	q := url.Values{}
	q.Set("t", b64.EncodeToString(l.Token))
	q.Set("pin", b64.EncodeToString(l.Pin[:]))
	q.Set("ca", b64.EncodeToString(l.CARoot[:]))
	if l.Renew {
		q.Set("r", "1")
	}
	return fmt.Sprintf("cipherdrop://%s/enroll/%s?%s", l.Host, l.SlotID, q.Encode())
}

// ParseLink parses and validates an enrolment link.
func ParseLink(s string) (Link, error) {
	var l Link
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return l, fmt.Errorf("invalid link: %w", err)
	}
	if u.Scheme != "cipherdrop" {
		return l, errors.New("invalid link: must start with cipherdrop://")
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return l, fmt.Errorf("invalid link host %q: %w", u.Host, err)
	}
	l.Host = u.Host
	id, ok := strings.CutPrefix(u.Path, "/enroll/")
	if !ok || !slotIDRe.MatchString(id) {
		return l, errors.New("invalid link: bad slot id")
	}
	l.SlotID = id
	q := u.Query()
	if l.Token, err = b64.DecodeString(q.Get("t")); err != nil || len(l.Token) != 16 {
		return l, errors.New("invalid link: bad token")
	}
	l.Renew = q.Get("r") == "1"
	for name, dst := range map[string]*[32]byte{"pin": &l.Pin, "ca": &l.CARoot} {
		b, err := b64.DecodeString(q.Get(name))
		if err != nil || len(b) != 32 {
			return l, fmt.Errorf("invalid link: bad %s", name)
		}
		copy(dst[:], b)
	}
	return l, nil
}
