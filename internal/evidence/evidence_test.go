package evidence

import (
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cipherdrop/internal/devpki"
)

type statement struct {
	Text string    `json:"text"`
	Time time.Time `json:"time"`
}

func setup(t *testing.T) (*devpki.CA, *devpki.Device, *Envelope) {
	t.Helper()
	root, _ := devpki.NewCA("Test Root CA")
	issuing, _ := root.NewIssuing("Test Issuing CA")
	alice, _ := issuing.Issue("alice", devpki.Department("finance"))
	env, err := Sign(KindMessage, statement{"pay invoice 42", time.Now()}, alice.TLS.PrivateKey.(ed25519.PrivateKey), alice.TLS.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	return root, alice, env
}

func TestSignAndVerify(t *testing.T) {
	root, alice, env := setup(t)
	signer, err := env.Verify(KindMessage, root.Pool, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if PartyOf(signer).Fingerprint != PartyOf(alice.Cert).Fingerprint {
		t.Error("wrong signer returned")
	}
}

func TestVerifyRejects(t *testing.T) {
	cases := map[string]func(*Envelope){
		"payload edited":      func(e *Envelope) { e.Payload = []byte(strings.Replace(string(e.Payload), "42", "43", 1)) },
		"signature bit flip":  func(e *Envelope) { e.Signature[0] ^= 1 },
		"kind swapped":        func(e *Envelope) { e.Kind = KindReceipt },
		"signer cert swapped": func(e *Envelope) { other, _ := devpki.SelfSigned("alice"); e.Chain = [][]byte{other.Cert.Raw} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			root, _, env := setup(t)
			mutate(env)
			kind := KindMessage
			if name == "kind swapped" {
				kind = KindReceipt // a message signature presented as a receipt
			}
			if _, err := env.Verify(kind, root.Pool, time.Now()); err == nil {
				t.Fatal("tampered statement verified")
			} else {
				t.Logf("rejected: %v", err)
			}
		})
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	root, _, env := setup(t)
	p := filepath.Join(t.TempDir(), "msg.json")
	if err := env.Save(p); err != nil {
		t.Fatal(err)
	}
	back, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := back.Verify(KindMessage, root.Pool, time.Now()); err != nil {
		t.Fatal(err)
	}
}

// TestOpenSSLCanVerifyExport proves the evidence does not depend on our own
// code: OpenSSL checks the exported signature directly.
func TestOpenSSLCanVerifyExport(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	_, _, env := setup(t)
	dir := t.TempDir()
	if err := env.Export(dir); err != nil {
		t.Fatal(err)
	}
	pub := filepath.Join(dir, "signer.pub")
	out, err := exec.Command("openssl", "x509", "-in", filepath.Join(dir, "signer.pem"), "-pubkey", "-noout", "-out", pub).CombinedOutput()
	if err != nil {
		t.Skipf("this openssl cannot read Ed25519 certificates: %s", out)
	}
	out, err = exec.Command("openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", pub,
		"-in", filepath.Join(dir, "signed.bin"), "-sigfile", filepath.Join(dir, "signature.bin")).CombinedOutput()
	if err != nil && strings.Contains(string(out), "rawin") {
		t.Skipf("openssl too old for -rawin: %s", out)
	}
	if err != nil {
		t.Fatalf("OpenSSL rejected a valid signature: %s", out)
	}
	// And OpenSSL must reject a tampered copy.
	os.WriteFile(filepath.Join(dir, "signed.bin"), append(SignedBytes(env.Kind, env.Payload), 'x'), 0o644)
	if out, err := exec.Command("openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", pub,
		"-in", filepath.Join(dir, "signed.bin"), "-sigfile", filepath.Join(dir, "signature.bin")).CombinedOutput(); err == nil {
		t.Fatalf("OpenSSL accepted tampered bytes: %s", out)
	}
}
