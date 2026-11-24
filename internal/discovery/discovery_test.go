package discovery

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"cipherdrop/internal/devpki"
	"cipherdrop/internal/trust"
)

type pki struct {
	root, issuing *devpki.CA
}

func newPKI(t *testing.T) pki {
	root, _ := devpki.NewCA("Test Root CA")
	issuing, _ := root.NewIssuing("Test Issuing CA")
	return pki{root, issuing}
}

func (p pki) local(t *testing.T, name, dept string) *trust.Local {
	d, err := p.issuing.Issue(name, devpki.Department(dept))
	if err != nil {
		t.Fatal(err)
	}
	return &trust.Local{Name: name, Department: dept, Cert: d.Cert, Chain: p.issuing.Chain,
		Root: p.root.Cert, Roots: p.root.Pool, TLS: d.TLS}
}

func (p pki) verifier(selfFP string) *Verifier {
	return &Verifier{Roots: p.root.Pool, Intermediates: trust.Pool(p.issuing.Chain...), SelfFP: selfFP}
}

var from = &net.UDPAddr{IP: net.IPv4(192, 168, 56, 20), Port: Port}

func key(l *trust.Local) ed25519.PrivateKey { return l.TLS.PrivateKey.(ed25519.PrivateKey) }

func TestValidBeacon(t *testing.T) {
	p := newPKI(t)
	bob := p.local(t, "bob", "legal")
	b, err := Make(Announce, "bob", 47475, bob.Cert, key(bob), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	v := p.verifier("me").Check(b, from, time.Now())
	if !v.OK || v.Name != "bob" || v.Department != "legal" || v.QUICAddr != "192.168.56.20:47475" {
		t.Fatalf("valid beacon rejected: %+v", v)
	}
}

func TestRejectedBeacons(t *testing.T) {
	p := newPKI(t)
	bob := p.local(t, "bob", "legal")
	now := time.Now()
	fake, _ := devpki.SelfSigned("bob")

	cases := []struct {
		name string
		make func() []byte
		want string
	}{
		{"self-signed certificate claiming bob", func() []byte {
			b, _ := Make(Announce, "bob", 47475, fake.Cert, fake.TLS.PrivateKey.(ed25519.PrivateKey), now)
			return b
		}, "not trusted"},
		{"bob's certificate under another name", func() []byte {
			b, _ := Make(Announce, "carol", 47475, bob.Cert, key(bob), now)
			return b
		}, "belongs to"},
		{"port changed after signing", func() []byte {
			raw, _ := Make(Announce, "bob", 47475, bob.Cert, key(bob), now)
			var b Beacon
			json.Unmarshal(raw, &b)
			b.Port = 4444
			out, _ := json.Marshal(b)
			return out
		}, "signature invalid"},
		{"stale beacon", func() []byte {
			b, _ := Make(Announce, "bob", 47475, bob.Cert, key(bob), now.Add(-2*time.Minute))
			return b
		}, "stale"},
		{"garbage", func() []byte { return []byte("not json") }, "malformed"},
		{"oversized", func() []byte { return []byte(strings.Repeat("x", MaxSize+1)) }, "oversized"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := p.verifier("me").Check(tc.make(), from, now)
			if v.OK || !strings.Contains(v.Reason, tc.want) {
				t.Fatalf("got OK=%v reason %q, want rejection mentioning %q", v.OK, v.Reason, tc.want)
			}
			t.Logf("rejected: %s", v.Reason)
		})
	}

	t.Run("replayed beacon", func(t *testing.T) {
		b, _ := Make(Announce, "bob", 47475, bob.Cert, key(bob), now)
		v := p.verifier("me")
		if !v.Check(b, from, now).OK {
			t.Fatal("first copy rejected")
		}
		r := v.Check(b, &net.UDPAddr{IP: net.IPv4(192, 168, 56, 66), Port: Port}, now.Add(time.Second))
		if r.OK || !strings.Contains(r.Reason, "replayed") {
			t.Fatalf("replay accepted: %+v", r)
		}
	})
}

func TestOwnBeaconIgnored(t *testing.T) {
	p := newPKI(t)
	bob := p.local(t, "bob", "legal")
	b, _ := Make(Announce, "bob", 47475, bob.Cert, key(bob), time.Now())
	v := p.verifier(trustFP(bob)).Check(b, from, time.Now())
	if !v.Self {
		t.Fatal("own beacon not recognised")
	}
}

func trustFP(l *trust.Local) string { return l.Fingerprint() }

// TestServicesFindEachOther runs two services over loopback: alice
// announces, bob replies at once, and both see a valid peer.
func TestServicesFindEachOther(t *testing.T) {
	p := newPKI(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type seen struct {
		mu    sync.Mutex
		names map[string]bool
	}
	run := func(l *trust.Local) (*Service, *seen, *net.UDPConn) {
		conn, err := Listen(0)
		if err != nil {
			t.Fatal(err)
		}
		s := &seen{names: map[string]bool{}}
		svc := &Service{Local: l, QUICPort: 47475, Announce: true, Port: conn.LocalAddr().(*net.UDPAddr).Port,
			OnVerdict: func(v Verdict) {
				if v.OK {
					s.mu.Lock()
					s.names[v.Name] = true
					s.mu.Unlock()
				}
			}}
		return svc, s, conn
	}
	bobSvc, bobSeen, bobConn := run(p.local(t, "bob", "legal"))
	aliceSvc, aliceSeen, aliceConn := run(p.local(t, "alice", "finance"))
	bobSvc.Targets = func() []*net.UDPAddr { return nil } // bob only answers
	aliceSvc.Targets = func() []*net.UDPAddr {
		return []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: bobConn.LocalAddr().(*net.UDPAddr).Port}}
	}
	if err := bobSvc.StartOn(ctx, bobConn); err != nil {
		t.Fatal(err)
	}
	if err := aliceSvc.StartOn(ctx, aliceConn); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		aliceSeen.mu.Lock()
		bobSeen.mu.Lock()
		done := aliceSeen.names["bob"] && bobSeen.names["alice"]
		bobSeen.mu.Unlock()
		aliceSeen.mu.Unlock()
		if done {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("peers did not find each other: alice saw %v, bob saw %v", aliceSeen.names, bobSeen.names)
}

func TestTableStates(t *testing.T) {
	tb := NewTable()
	now := time.Now()
	v := Verdict{OK: true, Name: "bob", Fingerprint: "FP", QUICAddr: "10.0.0.2:47475", FromIP: "10.0.0.2"}
	if _, isNew := tb.Observe(v, now); !isNew {
		t.Error("first beacon not reported as new")
	}
	if _, isNew := tb.Observe(v, now); isNew {
		t.Error("second beacon reported as new")
	}
	tb.MarkVerified("FP", "bob", "legal", "", "123 456", now)
	if p, ok := tb.Lookup("bob"); !ok || p.State != StateVerified || p.Addr != "10.0.0.2:47475" {
		t.Errorf("lookup = %+v %v", p, ok)
	}
	tb.Observe(Verdict{Name: "bob", FromIP: "10.0.0.66", Reason: "not trusted"}, now)
	if p, _ := tb.Lookup("bob"); p.FromIP != "10.0.0.2" {
		t.Error("an unverified claim was returned by Lookup")
	}
	gone := tb.Sweep(now.Add(OfflineAfter + time.Second))
	if len(gone) != 1 || gone[0].Name != "bob" {
		t.Errorf("sweep = %+v", gone)
	}
}
