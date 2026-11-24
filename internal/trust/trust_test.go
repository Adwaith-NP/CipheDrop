package trust

import (
	"crypto/x509"
	"os"
	"strings"
	"testing"
	"time"

	"cipherdrop/internal/devpki"
	"cipherdrop/internal/identity"
)

type pki struct {
	root, issuing *devpki.CA
}

func newPKI(t *testing.T) pki {
	t.Helper()
	root, err := devpki.NewCA("Test Root CA")
	if err != nil {
		t.Fatal(err)
	}
	issuing, err := root.NewIssuing("Test Issuing CA")
	if err != nil {
		t.Fatal(err)
	}
	return pki{root, issuing}
}

func TestInstallAndLoadThreeLevelChain(t *testing.T) {
	p := newPKI(t)
	key, _ := identity.GenerateKey()
	leaf, err := p.issuing.IssueFor("alice", key.Public(), devpki.Department("finance"))
	if err != nil {
		t.Fatal(err)
	}
	store := identity.Store{Dir: t.TempDir()}
	local, err := Install(store, key, leaf, p.issuing.Chain, p.root.Cert)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if local.Name != "alice" || local.Department != "finance" {
		t.Errorf("identity = %q/%q", local.Name, local.Department)
	}
	if n := len(local.TLS.Certificate); n != 2 {
		t.Errorf("TLS chain has %d certificates, want leaf + issuing = 2", n)
	}
	again, err := LoadLocal(store)
	if err != nil {
		t.Fatalf("LoadLocal: %v", err)
	}
	if again.Fingerprint() != local.Fingerprint() {
		t.Error("fingerprint changed between Install and LoadLocal")
	}
	info, _ := os.Stat(store.KeyPath())
	if info.Mode().Perm() != 0o600 {
		t.Errorf("key mode %04o", info.Mode().Perm())
	}
}

func TestInstallRejects(t *testing.T) {
	p := newPKI(t)
	other := newPKI(t)
	key, _ := identity.GenerateKey()
	good, _ := p.issuing.IssueFor("alice", key.Public())

	cases := []struct {
		name  string
		leaf  func() *x509.Certificate
		chain []*x509.Certificate
		root  *x509.Certificate
		want  string
	}{
		{"certificate for another key", func() *x509.Certificate { d, _ := p.issuing.Issue("alice"); return d.Cert },
			p.issuing.Chain, p.root.Cert, "does not belong"},
		{"issued under a different root", func() *x509.Certificate { c, _ := other.issuing.IssueFor("alice", key.Public()); return c },
			other.issuing.Chain, p.root.Cert, "unknown authority"},
		{"missing intermediate", func() *x509.Certificate { return good },
			nil, p.root.Cert, "unknown authority"},
		{"expired certificate", func() *x509.Certificate {
			c, _ := p.issuing.IssueFor("alice", key.Public(), devpki.Expired())
			return c
		},
			p.issuing.Chain, p.root.Cert, "expired"},
		{"leaf passed off as the root", func() *x509.Certificate { return good },
			p.issuing.Chain, good, "not a CA"},
		{"missing clientAuth usage", func() *x509.Certificate {
			c, _ := p.issuing.IssueFor("alice", key.Public(), func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			})
			return c
		}, p.issuing.Chain, p.root.Cert, "clientAuth"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := identity.Store{Dir: t.TempDir()}
			_, err := Install(store, key, tc.leaf(), tc.chain, tc.root)
			if err == nil {
				t.Fatal("Install accepted a bad identity")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
			if store.Exists() {
				t.Error("a rejected identity was written to disk")
			}
		})
	}
}

func TestVerifyDeviceUsesTime(t *testing.T) {
	p := newPKI(t)
	d, _ := p.issuing.Issue("bob")
	inter := Pool(p.issuing.Chain...)
	if err := VerifyDevice(d.Cert, p.root.Pool, inter, time.Now()); err != nil {
		t.Fatalf("valid cert rejected: %v", err)
	}
	if err := VerifyDevice(d.Cert, p.root.Pool, inter, time.Now().Add(48*time.Hour)); err == nil {
		t.Error("cert accepted after it expired")
	}
}
