package node

import (
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"cipherdrop/internal/devpki"
	"cipherdrop/internal/discovery"
)

// TestDiscoveryAndTwoWayVerification: alice and bob only know each other
// from beacons. Each sees the other as verified after a pinned mutual TLS
// handshake, they can chat by name with no DNS, and a forged beacon shows up
// as UNVERIFIED.
func TestDiscoveryAndTwoWayVerification(t *testing.T) {
	w := newWorld(t)
	noDNS := func(o *Options) { o.Resolve = func(string) string { return "127.0.0.1:1" } }
	bob, _ := w.start(t, "bob", noDNS)
	alice, aliceUI := w.start(t, "alice", noDNS)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bobConn, _ := discovery.Listen(0)
	aliceConn, _ := discovery.Listen(0)
	loop := func(c *net.UDPConn) []*net.UDPAddr {
		return []*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: c.LocalAddr().(*net.UDPAddr).Port}}
	}
	if err := bob.StartDiscovery(ctx, &discovery.Service{Announce: true, Conn: bobConn,
		Targets: func() []*net.UDPAddr { return nil }}); err != nil {
		t.Fatal(err)
	}
	if err := alice.StartDiscovery(ctx, &discovery.Service{Announce: true, Conn: aliceConn,
		Targets: func() []*net.UDPAddr { return loop(bobConn) }}); err != nil {
		t.Fatal(err)
	}

	verified := func(n *Node, name string) bool {
		p, ok := n.Peers.Lookup(name)
		return ok && p.State == discovery.StateVerified
	}
	deadline := time.Now().Add(5 * time.Second)
	for !(verified(alice, "bob") && verified(bob, "alice")) {
		if time.Now().After(deadline) {
			t.Fatalf("not verified both ways: alice sees %+v, bob sees %+v", alice.Peers.Snapshot(), bob.Peers.Snapshot())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := alice.SendMessage(ctx, "bob", "found you without DNS"); err != nil {
		t.Fatalf("chat via the discovered address failed: %v", err)
	}

	// Mallory broadcasts a beacon for "bob" with a self-signed certificate.
	fake, _ := devpki.SelfSigned("bob")
	b, _ := discovery.Make(discovery.Announce, "bob", 47475, fake.Cert, fake.TLS.PrivateKey.(ed25519.PrivateKey), time.Now())
	mallory, _ := net.DialUDP("udp4", nil, loop(aliceConn)[0])
	mallory.Write(b)
	mallory.Close()
	for !aliceUI.contains("UNVERIFIED device claiming \"bob\"") {
		if time.Now().After(deadline.Add(2 * time.Second)) {
			t.Fatal("forged beacon not reported")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if p, _ := alice.Peers.Lookup("bob"); p.State != discovery.StateVerified {
		t.Error("the forged beacon displaced the verified bob")
	}
}
