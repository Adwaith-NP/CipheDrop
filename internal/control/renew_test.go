package control

import (
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cipherdrop/internal/identity"
	"cipherdrop/internal/provision"
	"cipherdrop/internal/totp"
	"cipherdrop/internal/trust"
)

// laterCode moves the server clock forward by n minutes and returns the
// admin's code for that moment, because each code works only once.
func (l *lab) laterCode(n int) string {
	t := time.Now().Add(time.Duration(n) * time.Minute)
	l.server.Now = func() time.Time { return t }
	return totp.CodeAt(l.session.Secrets.TOTP, totp.Step(t), totp.Digits)
}

func (l *lab) renew(link provision.Link, code string, store identity.Store) (*trust.Local, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	local, _, err := provision.Renew(ctx, link, code, store)
	return local, err
}

func TestValidityChosenAtRegistration(t *testing.T) {
	l := newLab(t)
	_, link, err := l.session.CreateSlot("alice", "finance", "payroll", 30, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	store, err := l.enroll(link, l.code())
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := trust.LoadCertFile(store.CertPath())
	if d := time.Until(leaf.NotAfter); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Errorf("certificate valid for %v, want 30 days", d.Round(time.Hour))
	}
	if _, _, err := l.session.CreateSlot("bob", "legal", "", 5000, time.Hour, time.Now()); err == nil {
		t.Error("validity above the maximum accepted")
	}
}

func TestRenewalKeepsIdentityRotatesKey(t *testing.T) {
	l := newLab(t)
	_, link := l.slot("alice", "finance", time.Hour)
	store, err := l.enroll(link, l.code())
	if err != nil {
		t.Fatal(err)
	}
	oldKey, _ := store.LoadKey()
	oldCert, _ := trust.LoadCertFile(store.CertPath())

	slot, rlink, err := l.session.CreateRenewSlot("alice", 730, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !rlink.Renew || slot.Department != "finance" {
		t.Fatalf("renewal slot = %+v", slot)
	}
	local, err := l.renew(rlink, l.laterCode(1), store)
	if err != nil {
		t.Fatalf("renewal failed: %v", err)
	}
	if local.Name != "alice" || local.Department != "finance" {
		t.Errorf("identity changed: %s/%s", local.Name, local.Department)
	}
	if local.Fingerprint() == identity.Fingerprint(oldCert) {
		t.Error("certificate was not replaced")
	}
	newKey, _ := store.LoadKey()
	if newKey.Equal(oldKey) {
		t.Error("key was not rotated")
	}
	if d := time.Until(local.Cert.NotAfter); d < 729*24*time.Hour {
		t.Errorf("renewed certificate valid for %v, want 730 days", d.Round(time.Hour))
	}
	if _, err := os.Stat(filepath.Join(store.Dir, "retired")); err != nil {
		t.Error("old certificate not archived")
	}
	sup := *l.server.Issuer.(goIssuer).superseded
	if len(sup) != 1 || sup[0] != SerialHex(oldCert.SerialNumber) {
		t.Errorf("superseded = %v, want the old serial", sup)
	}
	slots, _ := ListSlots(l.session.Paths)
	if cur, _ := CurrentCert(slots, "alice"); cur.CertFingerprint != local.Fingerprint() {
		t.Error("control server does not show the renewed certificate as current")
	}
	// The same renewal link cannot be used twice.
	if _, err := l.renew(rlink, l.laterCode(2), store); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Errorf("second use of the renewal link: %v", err)
	}
}

func TestRenewalAfterExpiry(t *testing.T) {
	l := newLab(t)
	_, link, _ := l.session.CreateSlot("alice", "finance", "", 1, time.Hour, time.Now())
	store, err := l.enroll(link, l.code())
	if err != nil {
		t.Fatal(err)
	}
	// Pretend a year passed: the device can no longer start, but can renew.
	expired, _ := l.server.Issuer.IssueDevice(mustCSR(t, store), "alice", "finance", -10)
	os.WriteFile(store.CertPath(), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expired.Raw}), 0o644)
	slots, _ := ListSlots(l.session.Paths)
	cur, _ := CurrentCert(slots, "alice")
	updateSlot(l.session.Paths, cur.ID, func(sl *Slot) error { sl.CertFingerprint = identity.Fingerprint(expired); return nil })

	if _, err := trust.LoadLocal(store); err == nil || !strings.Contains(err.Error(), "renew") {
		t.Fatalf("expired device should be told to renew, got %v", err)
	}
	_, rlink, err := l.session.CreateRenewSlot("alice", 0, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.renew(rlink, l.laterCode(1), store); err != nil {
		t.Fatalf("renewal after expiry failed: %v", err)
	}
	if _, err := trust.LoadLocal(store); err != nil {
		t.Fatalf("renewed device still cannot start: %v", err)
	}
}

func mustCSR(t *testing.T, store identity.Store) []byte {
	key, err := store.LoadKey()
	if err != nil {
		t.Fatal(err)
	}
	p, _ := identity.CreateCSR("alice", key)
	b, _ := pem.Decode(p)
	return b.Bytes
}

func TestRenewalAttacksAreRefused(t *testing.T) {
	l := newLab(t)
	_, la := l.slot("alice", "finance", time.Hour)
	alice, err := l.enroll(la, l.code())
	if err != nil {
		t.Fatal(err)
	}
	_, lb := l.slot("bob", "legal", time.Hour)
	bob, err := l.enroll(lb, l.laterCode(1))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("bob uses alice's renewal link", func(t *testing.T) {
		_, rlink, _ := l.session.CreateRenewSlot("alice", 0, time.Hour, time.Now())
		_, err := l.renew(rlink, l.laterCode(2), bob)
		mustRefuse(t, err, "not the certificate the admin chose to renew")
		l.session.CancelSlot("alice", time.Now())
	})
	t.Run("renewal link used as a new-device enrolment", func(t *testing.T) {
		_, rlink, _ := l.session.CreateRenewSlot("alice", 0, time.Hour, time.Now())
		_, err := l.enroll(rlink, l.laterCode(3))
		mustRefuse(t, err, "renewal link")
		sl, _ := l.session.CancelSlot("alice", time.Now())
		// Even a modified client that skips that check is refused by the server.
		key, _ := identity.GenerateKey()
		csrPEM, _ := identity.CreateCSR("alice", key)
		b, _ := pem.Decode(csrPEM)
		_ = sl
		_, rlink2, _ := l.session.CreateRenewSlot("alice", 0, time.Hour, time.Now())
		code := l.laterCode(4)
		exp := []byte(strings.Repeat("E", 32))
		_, _, err = l.server.Enroll(provision.EnrollRequest{Slot: rlink2.SlotID, Token: rlink2.Token, CSR: b.Bytes,
			Proof: provision.Proof(code, exp, rlink2.SlotID, b.Bytes)}, exp, "192.0.2.66:1")
		mustRefuse(t, err, "run it on that device")
		l.session.CancelSlot("alice", time.Now())
	})
	t.Run("alice's certificate with a signature from another key", func(t *testing.T) {
		_, rlink, _ := l.session.CreateRenewSlot("alice", 0, time.Hour, time.Now())
		oldCert, _ := trust.LoadCertFile(alice.CertPath())
		key, _ := identity.GenerateKey()
		csrPEM, _ := identity.CreateCSR("alice", key)
		b, _ := pem.Decode(csrPEM)
		_, mallory, _ := ed25519.GenerateKey(nil)
		code := l.laterCode(5)
		exp := []byte(strings.Repeat("F", 32))
		_, _, err := l.server.Enroll(provision.EnrollRequest{Slot: rlink.SlotID, Token: rlink.Token, CSR: b.Bytes,
			Proof: provision.Proof(code, exp, rlink.SlotID, b.Bytes), OldCert: oldCert.Raw,
			OldSig: ed25519.Sign(mallory, provision.RenewSignedBytes(exp, rlink.SlotID, b.Bytes))}, exp, "192.0.2.66:1")
		mustRefuse(t, err, "not signed with the device's current key")
	})
	t.Run("renewing a device that was never enrolled", func(t *testing.T) {
		if _, _, err := l.session.CreateRenewSlot("nobody", 0, time.Hour, time.Now()); err == nil {
			t.Fatal("renewal slot created for an unknown device")
		}
	})
}
