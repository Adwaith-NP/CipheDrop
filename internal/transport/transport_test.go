package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"cipherdrop/internal/devpki"
	"cipherdrop/internal/identity"
)

type serverResult struct {
	sess Session
	line string
	err  error
}

// startReceiver runs a receiver that answers one ping, like `cipherdrop dev listen --once`.
func startReceiver(t *testing.T, cert tls.Certificate, roots *x509.CertPool, name string) (string, <-chan serverResult) {
	t.Helper()
	ln, err := Listen("127.0.0.1:0", ServerConfig(cert, roots, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	results := make(chan serverResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := ln.Accept(ctx)
		if err != nil {
			results <- serverResult{err: err}
			return
		}
		defer conn.CloseWithError(0, "")
		sess, derr := Describe(conn)
		line, perr := ServePing(ctx, conn, name)
		results <- serverResult{sess: sess, line: line, err: errors.Join(derr, perr)}
		select {
		case <-conn.Context().Done():
		case <-ctx.Done():
		}
	}()
	return ln.Addr().String(), results
}

// sendPing connects like `cipherdrop dev ping` and returns what the sender saw.
func sendPing(addr string, cfg *tls.Config, name string) (Session, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Dial(ctx, addr, cfg)
	if err != nil {
		return Session{}, "", err
	}
	defer conn.CloseWithError(0, "")
	sess, err := Describe(conn)
	if err != nil {
		return Session{}, "", err
	}
	reply, err := Ping(ctx, conn, name)
	return sess, reply, err
}

func newCA(t *testing.T, cn string) *devpki.CA {
	t.Helper()
	ca, err := devpki.NewCA(cn)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func issue(t *testing.T, ca *devpki.CA, name string, opts ...devpki.Option) *devpki.Device {
	t.Helper()
	d, err := ca.Issue(name, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestMutualTLSHandshakeAndPing(t *testing.T) {
	ca := newCA(t, "Test Root CA")
	alice := issue(t, ca, "alice")
	bob := issue(t, ca, "bob")

	addr, results := startReceiver(t, bob.TLS, ca.Pool, "bob")
	pin := identity.Fingerprint(bob.Cert)
	sess, reply, err := sendPing(addr, ClientConfig(alice.TLS, ca.Pool, "bob", pin, nil), "alice")
	if err != nil {
		t.Fatalf("ping failed: %v", err)
	}
	srv := <-results
	if srv.err != nil {
		t.Fatalf("receiver failed: %v", srv.err)
	}

	checks := []struct{ what, got, want string }{
		{"reply", reply, "PONG bob"},
		{"request seen by receiver", srv.line, "PING alice"},
		{"TLS version", sess.TLSVersion, "TLS 1.3"},
		{"key exchange", sess.KeyExchange, "X25519"},
		{"ALPN", sess.ALPN, ALPN},
		{"receiver as seen by sender", sess.PeerName, "bob"},
		{"sender as seen by receiver", srv.sess.PeerName, "alice"},
		{"sender's view of bob's fingerprint", sess.PeerFingerprint, pin},
		{"receiver's view of alice's fingerprint", srv.sess.PeerFingerprint, identity.Fingerprint(alice.Cert)},
		{"verification code on both screens", sess.Code, srv.sess.Code},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.what, c.got, c.want)
		}
	}
	if sess.Used0RTT || srv.sess.Used0RTT {
		t.Error("0-RTT must never be used")
	}
	t.Logf("negotiated %s, %s, %s, code %s", sess.TLSVersion, sess.CipherSuite, sess.KeyExchange, sess.Code)
}

// TestThreeLevelChain mirrors the real deployment: devices are signed by the
// issuing CA and trust only the root, so each side must send its
// intermediate in the handshake.
func TestThreeLevelChain(t *testing.T) {
	root := newCA(t, "Test Root CA")
	issuing, err := root.NewIssuing("Test Issuing CA")
	if err != nil {
		t.Fatal(err)
	}
	alice := issue(t, issuing, "alice", devpki.Department("finance"))
	bob := issue(t, issuing, "bob", devpki.Department("legal"))
	addr, results := startReceiver(t, bob.TLS, root.Pool, "bob")
	sess, _, err := sendPing(addr, ClientConfig(alice.TLS, root.Pool, "bob", "", nil), "alice")
	if err != nil {
		t.Fatalf("ping over a three-level chain failed: %v", err)
	}
	srv := <-results
	if sess.PeerDepartment != "legal" || srv.sess.PeerDepartment != "finance" {
		t.Errorf("departments = %q / %q", sess.PeerDepartment, srv.sess.PeerDepartment)
	}
}

func TestVerificationCodeIsPerSession(t *testing.T) {
	ca := newCA(t, "Test Root CA")
	alice := issue(t, ca, "alice")
	bob := issue(t, ca, "bob")
	var codes []string
	for range 2 {
		addr, results := startReceiver(t, bob.TLS, ca.Pool, "bob")
		sess, _, err := sendPing(addr, ClientConfig(alice.TLS, ca.Pool, "bob", "", nil), "alice")
		if err != nil {
			t.Fatal(err)
		}
		<-results
		codes = append(codes, sess.Code)
	}
	if codes[0] == codes[1] {
		t.Errorf("two sessions produced the same code %s (chance 1 in a million)", codes[0])
	}
}

// TestAttacksAreRejected is the automated version of the threat-model table:
// every case is something Mallory can try, and every one must fail.
func TestAttacksAreRejected(t *testing.T) {
	ca := newCA(t, "CipherDrop Test CA")
	rogueCA := newCA(t, "Mallory CA")
	alice := issue(t, ca, "alice")
	bob := issue(t, ca, "bob")
	carol := issue(t, ca, "carol")
	rogueBob := issue(t, rogueCA, "bob")
	selfSignedBob, err := devpki.SelfSigned("bob")
	if err != nil {
		t.Fatal(err)
	}
	expiredBob := issue(t, ca, "bob", devpki.Expired())
	rogueAlice := issue(t, rogueCA, "alice")

	cases := []struct {
		name     string
		receiver *devpki.Device
		client   func() *tls.Config
	}{
		{"receiver cert from another CA", rogueBob,
			func() *tls.Config { return ClientConfig(alice.TLS, ca.Pool, "bob", "", nil) }},
		{"self-signed receiver claiming to be bob", selfSignedBob,
			func() *tls.Config { return ClientConfig(alice.TLS, ca.Pool, "bob", "", nil) }},
		{"valid device answering under the wrong name", carol,
			func() *tls.Config { return ClientConfig(alice.TLS, ca.Pool, "bob", "", nil) }},
		{"fingerprint differs from the discovered one", bob,
			func() *tls.Config {
				return ClientConfig(alice.TLS, ca.Pool, "bob", identity.Fingerprint(carol.Cert), nil)
			}},
		{"expired receiver certificate", expiredBob,
			func() *tls.Config { return ClientConfig(alice.TLS, ca.Pool, "bob", "", nil) }},
		{"sender without a certificate", bob,
			func() *tls.Config {
				c := ClientConfig(alice.TLS, ca.Pool, "bob", "", nil)
				c.Certificates = nil
				return c
			}},
		{"sender cert from another CA", bob,
			func() *tls.Config { return ClientConfig(rogueAlice.TLS, ca.Pool, "bob", "", nil) }},
		{"client offering only P-256 (no agreed group)", bob,
			func() *tls.Config {
				c := ClientConfig(alice.TLS, ca.Pool, "bob", "", nil)
				c.CurvePreferences = []tls.CurveID{tls.CurveP256}
				return c
			}},
		{"wrong application protocol", bob,
			func() *tls.Config {
				c := ClientConfig(alice.TLS, ca.Pool, "bob", "", nil)
				c.NextProtos = []string{"h3"}
				return c
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, results := startReceiver(t, tc.receiver.TLS, ca.Pool, "bob")
			_, reply, err := sendPing(addr, tc.client(), "alice")
			if err == nil {
				t.Fatalf("attack succeeded: got reply %q", reply)
			}
			t.Logf("rejected: %v", err)
			select {
			case res := <-results:
				if res.err == nil {
					t.Fatalf("receiver accepted the connection and saw %q", res.line)
				}
			case <-time.After(300 * time.Millisecond):
				// Receiver never got a verified connection: also a pass.
			}
		})
	}
}
