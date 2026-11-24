package control

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cipherdrop/internal/audit"
	"cipherdrop/internal/devpki"
	"cipherdrop/internal/identity"
	"cipherdrop/internal/provision"
	"cipherdrop/internal/totp"
)

// goIssuer stands in for OpenSSL in unit tests; the Docker lab exercises
// the real OpenSSL issuer end to end.
type goIssuer struct {
	ca         *devpki.CA
	superseded *[]string
}

func (g goIssuer) IssueDevice(csrDER []byte, name, dept string, days int) (*x509.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	return g.ca.IssueFor(name, csr.PublicKey, devpki.Department(dept), devpki.ValidDays(days))
}

func (g goIssuer) RevokeSuperseded(serial string) error {
	*g.superseded = append(*g.superseded, serial)
	return nil
}

type lab struct {
	t       *testing.T
	session *Session
	server  *Server
	addr    string
	root    *devpki.CA
}

// newLab builds an unlocked control server with an in-memory two-tier PKI
// and serves it on a random local port.
func newLab(t *testing.T) *lab {
	t.Helper()
	p := Paths{Dir: t.TempDir()}
	for _, d := range []string{p.Slots(), p.Release(), p.IssuingDir()} {
		os.MkdirAll(d, 0o700)
	}
	root, _ := devpki.NewCA("Test Root CA")
	issuing, _ := root.NewIssuing("Test Issuing CA 1")
	ctl, _ := issuing.Issue("control", devpki.Department("infrastructure"))

	write := func(path string, data []byte) {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(p.Root(), pemCert(root.Cert))
	write(filepath.Join(p.IssuingDir(), "ca.crt"), pemCert(issuing.Cert))
	write(p.TLSCert(), pemCert(ctl.Cert))
	der, _ := x509.MarshalPKCS8PrivateKey(ctl.TLS.PrivateKey)
	write(p.TLSKey(), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	write(p.AdminState(), []byte(`{"last_step":0}`))

	sec := Secrets{TOTP: totp.NewSecret(), AuditSeed: make([]byte, 32)}
	s := &Session{Paths: p, Secrets: sec, Audit: &audit.Log{Path: p.AuditLog(), Key: sec.AuditKey()}}
	srv, err := NewServer(s, goIssuer{ca: issuing, superseded: new([]string)})
	if err != nil {
		t.Fatal(err)
	}
	srv.Log = log.New(io.Discard, "", 0)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv.TLSConfig())
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler(), ErrorLog: srv.Log}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	s.Config = Config{Name: "control", PublicAddr: ln.Addr().String()}
	return &lab{t: t, session: s, server: srv, addr: ln.Addr().String(), root: root}
}

func (l *lab) slot(name, dept string, ttl time.Duration) (Slot, provision.Link) {
	l.t.Helper()
	sl, link, err := l.session.CreateSlot(name, dept, "unit test", 0, ttl, time.Now())
	if err != nil {
		l.t.Fatal(err)
	}
	return sl, link
}

func (l *lab) code() string {
	return totp.CodeAt(l.session.Secrets.TOTP, totp.Step(time.Now()), totp.Digits)
}

func (l *lab) enroll(link provision.Link, code string) (identity.Store, error) {
	store := identity.Store{Dir: l.t.TempDir()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := provision.Enroll(ctx, link, code, store)
	return store, err
}

func wrong(code string) string {
	if code == "000000" {
		return "000001"
	}
	return "000000"
}

func TestEnrolmentEndToEnd(t *testing.T) {
	l := newLab(t)
	_, link := l.slot("alice", "finance", time.Hour)

	store, err := l.enroll(link, l.code())
	if err != nil {
		t.Fatalf("enrolment failed: %v", err)
	}
	key, err := store.LoadKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := os.ReadFile(store.CertPath())
	block, _ := pem.Decode(cert)
	leaf, _ := x509.ParseCertificate(block.Bytes)
	if leaf.Subject.CommonName != "alice" || leaf.Subject.OrganizationalUnit[0] != "finance" {
		t.Errorf("identity %v comes from the CSR, not from the admin's slot", leaf.Subject)
	}
	if !leaf.PublicKey.(ed25519.PublicKey).Equal(key.Public()) {
		t.Error("certificate is not for the key generated on the device")
	}

	slots, _ := ListSlots(l.session.Paths)
	if slots[0].Status != SlotUsed || slots[0].CertFingerprint != identity.Fingerprint(leaf) {
		t.Errorf("slot after enrolment: %+v", slots[0])
	}
	pub := l.session.Secrets.AuditKey().Public().(ed25519.PublicKey)
	entries, err := audit.Verify(l.session.Paths.AuditLog(), pub)
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	if last := entries[len(entries)-1]; last.Event != "device_enrolled" || last.Details["name"] != "alice" {
		t.Errorf("last audit entry = %+v", last)
	}
}

func TestEnrolmentAttacksAreRefused(t *testing.T) {
	t.Run("wrong 2FA code", func(t *testing.T) {
		l := newLab(t)
		_, link := l.slot("alice", "finance", time.Hour)
		_, err := l.enroll(link, wrong(l.code()))
		mustRefuse(t, err, "invalid enrolment link or 2FA code")
	})

	t.Run("five wrong codes lock the slot", func(t *testing.T) {
		l := newLab(t)
		_, link := l.slot("alice", "finance", time.Hour)
		for range MaxAttempts {
			l.enroll(link, wrong(l.code()))
		}
		_, err := l.enroll(link, l.code())
		mustRefuse(t, err, "locked")
	})

	t.Run("code already used for admin login", func(t *testing.T) {
		l := newLab(t)
		_, link := l.slot("alice", "finance", time.Hour)
		code := l.code()
		l.session.ConsumeTOTP(time.Now(), func(step int64) bool { return totp.CodeAt(l.session.Secrets.TOTP, step, 6) == code })
		_, err := l.enroll(link, code)
		mustRefuse(t, err, "invalid enrolment link or 2FA code")
	})

	t.Run("link used twice", func(t *testing.T) {
		l := newLab(t)
		_, link := l.slot("alice", "finance", time.Hour)
		if _, err := l.enroll(link, l.code()); err != nil {
			t.Fatal(err)
		}
		// Move the server clock forward and use that minute's fresh code, so
		// the refusal is about the reused link, not a reused code.
		later := time.Now().Add(time.Minute)
		l.server.Now = func() time.Time { return later }
		_, err := l.enroll(link, totp.CodeAt(l.session.Secrets.TOTP, totp.Step(later), 6))
		mustRefuse(t, err, "already used")
	})

	t.Run("expired link", func(t *testing.T) {
		l := newLab(t)
		_, link := l.slot("alice", "finance", time.Hour)
		l.server.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
		_, err := l.enroll(link, totp.CodeAt(l.session.Secrets.TOTP, totp.Step(time.Now().Add(2*time.Hour)), 6))
		mustRefuse(t, err, "expired")
	})

	t.Run("guessed token", func(t *testing.T) {
		l := newLab(t)
		_, link := l.slot("alice", "finance", time.Hour)
		link.Token = provision.NewToken()
		_, err := l.enroll(link, l.code())
		mustRefuse(t, err, "invalid enrolment link or 2FA code")
	})

	t.Run("fake control server (pin mismatch)", func(t *testing.T) {
		l := newLab(t)
		_, link := l.slot("alice", "finance", time.Hour)
		fake := newLab(t) // a different server key at a different address
		link.Host = fake.addr
		_, err := l.enroll(link, l.code())
		mustRefuse(t, err, "does not match the pin")
	})

	t.Run("wrong root in the link", func(t *testing.T) {
		l := newLab(t)
		_, link := l.slot("alice", "finance", time.Hour)
		link.CARoot = sha256.Sum256([]byte("someone else's root"))
		store, err := l.enroll(link, l.code())
		mustRefuse(t, err, "does not match the fingerprint")
		if store.Exists() {
			t.Error("key was stored although the root did not match")
		}
	})

	t.Run("proof relayed from another TLS session", func(t *testing.T) {
		l := newLab(t)
		sl, link := l.slot("alice", "finance", time.Hour)
		key, _ := identity.GenerateKey()
		csrPEM, _ := identity.CreateCSR("slot-"+sl.ID, key)
		block, _ := pem.Decode(csrPEM)
		victimSession := []byte(strings.Repeat("A", 32)) // the exporter of the victim's connection
		attackerSession := []byte(strings.Repeat("B", 32))
		proof := provision.Proof(l.code(), victimSession, sl.ID, block.Bytes)
		_, _, err := l.server.Enroll(provision.EnrollRequest{Slot: sl.ID, Token: link.Token, CSR: block.Bytes, Proof: proof},
			attackerSession, "192.0.2.66:1234")
		mustRefuse(t, err, "invalid enrolment link or 2FA code")
	})

	t.Run("proof moved to a different key", func(t *testing.T) {
		l := newLab(t)
		sl, link := l.slot("alice", "finance", time.Hour)
		mk := func() []byte {
			k, _ := identity.GenerateKey()
			p, _ := identity.CreateCSR("slot-"+sl.ID, k)
			b, _ := pem.Decode(p)
			return b.Bytes
		}
		victimCSR, attackerCSR := mk(), mk()
		exp := []byte(strings.Repeat("C", 32))
		proof := provision.Proof(l.code(), exp, sl.ID, victimCSR)
		_, _, err := l.server.Enroll(provision.EnrollRequest{Slot: sl.ID, Token: link.Token, CSR: attackerCSR, Proof: proof},
			exp, "192.0.2.66:1234")
		mustRefuse(t, err, "invalid enrolment link or 2FA code")
	})
}

func mustRefuse(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatal("attack succeeded: enrolment was accepted")
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("refused, but error %q does not mention %q", err, want)
	}
	t.Logf("refused: %v", err)
}

func TestCancelledLinkIsRefused(t *testing.T) {
	l := newLab(t)
	_, link := l.slot("bob", "legal", time.Hour)
	if _, err := l.session.CancelSlot("bob", time.Now()); err != nil {
		t.Fatal(err)
	}
	_, err := l.enroll(link, l.code())
	mustRefuse(t, err, "cancelled")
	// A new link for the same name can now be created and used.
	_, link2 := l.slot("bob", "legal", time.Hour)
	later := time.Now().Add(time.Minute)
	l.server.Now = func() time.Time { return later }
	if _, err := l.enroll(link2, totp.CodeAt(l.session.Secrets.TOTP, totp.Step(later), 6)); err != nil {
		t.Fatalf("replacement link failed: %v", err)
	}
	slots, _ := ListSlots(l.session.Paths)
	if slots[0].CertNotAfter.IsZero() {
		t.Error("certificate expiry not recorded")
	}
}

func TestSlotValidation(t *testing.T) {
	l := newLab(t)
	if _, _, err := l.session.CreateSlot("Alice!", "finance", "", 0, time.Hour, time.Now()); err == nil {
		t.Error("invalid name accepted")
	}
	if _, _, err := l.session.CreateSlot("alice", "fin/ance", "", 0, time.Hour, time.Now()); err == nil {
		t.Error("department with '/' accepted (DN injection)")
	}
	l.slot("alice", "finance", time.Hour)
	if _, _, err := l.session.CreateSlot("alice", "finance", "", 0, time.Hour, time.Now()); err == nil {
		t.Error("second open slot for the same name accepted")
	}
}

func TestLinkRoundTrip(t *testing.T) {
	l := newLab(t)
	_, link := l.slot("bob", "legal", time.Hour)
	parsed, err := provision.ParseLink(link.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.String() != link.String() {
		t.Errorf("round trip changed the link:\n%s\n%s", link, parsed)
	}
	for _, bad := range []string{"https://x/enroll/0123456789abcdef", "cipherdrop://h:1/enroll/xyz?t=a&pin=b&ca=c"} {
		if _, err := provision.ParseLink(bad); err == nil {
			t.Errorf("accepted bad link %q", bad)
		}
	}
}
