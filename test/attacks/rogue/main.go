// Command rogue plays Mallory in the attack demos. It holds a self-signed
// certificate that claims someone else's device name, which no real CA signed.
//
//	rogue -mode receiver -name bob   # pretend to be Bob and wait for Alice
//	rogue -mode client -name alice -addr bob:47475   # pretend to be Alice
//	rogue -mode beacon -name bob -for 15s   # broadcast fake "I am bob" beacons
//	rogue -mode replay -name carol           # capture carol's beacon and replay it
//
// Exit status: 0 if CipherDrop rejected the attack, 3 if the attack worked.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"cipherdrop/internal/devpki"
	"cipherdrop/internal/discovery"
	"cipherdrop/internal/transport"
)

func main() {
	mode := flag.String("mode", "receiver", "receiver or client")
	name := flag.String("name", "bob", "device name to impersonate")
	addr := flag.String("addr", ":47475", "listen address (receiver) or target host:port (client)")
	wait := flag.Duration("wait", 20*time.Second, "receiver: how long to wait for a victim")
	dur := flag.Duration("for", 15*time.Second, "beacon: how long to keep broadcasting")
	flag.Parse()
	switch *mode {
	case "beacon":
		os.Exit(runFakeBeacon(*name, *dur))
	case "replay":
		os.Exit(runReplay(*name, *wait))
	}

	fake, err := devpki.SelfSigned(*name)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{fake.TLS},
		CurvePreferences: []tls.CurveID{transport.KeyExchange},
		NextProtos:       []string{transport.ALPN},
	}
	switch *mode {
	case "receiver":
		os.Exit(runReceiver(cfg, *name, *addr, *wait))
	case "client":
		os.Exit(runClient(cfg, *name, *addr))
	default:
		fmt.Fprintln(os.Stderr, "mode must be receiver or client")
		os.Exit(2)
	}
}

func runReceiver(cfg *tls.Config, name, addr string, wait time.Duration) int {
	cfg.ClientAuth = tls.RequestClientCert // Mallory accepts anyone
	ln, err := transport.Listen(addr, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer ln.Close()
	fmt.Printf("[mallory] posing as %q on udp %s with a self-signed certificate\n", name, ln.Addr())
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	conn, err := ln.Accept(ctx)
	if err != nil {
		fmt.Println("[mallory] no victim completed a handshake: attack blocked")
		return 0
	}
	line, err := transport.ServePing(ctx, conn, name)
	if err != nil {
		fmt.Println("[mallory] victim aborted before sending data:", err)
		return 0
	}
	fmt.Printf("[mallory] ATTACK WORKED, victim sent %q\n", line)
	return 3
}

func runClient(cfg *tls.Config, name, addr string) int {
	cfg.InsecureSkipVerify = true // Mallory does not care who answers
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	fmt.Printf("[mallory] connecting to %s, claiming to be %q with a self-signed certificate\n", addr, name)
	conn, err := transport.Dial(ctx, addr, cfg)
	if err != nil {
		fmt.Println("[mallory] handshake rejected: attack blocked:", err)
		return 0
	}
	defer conn.CloseWithError(0, "")
	reply, err := transport.Ping(ctx, conn, name)
	if err != nil {
		fmt.Println("[mallory] connection refused after handshake: attack blocked:", err)
		return 0
	}
	fmt.Printf("[mallory] ATTACK WORKED, receiver replied %q\n", reply)
	return 3
}

// runFakeBeacon broadcasts beacons that claim name, signed with a key whose
// certificate no CA vouches for. Every console must list it in red.
func runFakeBeacon(name string, dur time.Duration) int {
	fake, err := devpki.SelfSigned(name)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	conn, err := discovery.Listen(0)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer conn.Close()
	fmt.Printf("[mallory] broadcasting fake beacons for %q for %s\n", name, dur)
	for end := time.Now().Add(dur); time.Now().Before(end); time.Sleep(2 * time.Second) {
		b, _ := discovery.Make(discovery.Announce, name, 47475, fake.Cert, fake.TLS.PrivateKey.(ed25519.PrivateKey), time.Now())
		for _, t := range discovery.BroadcastTargets(discovery.Port) {
			conn.WriteToUDP(b, t)
		}
	}
	return 0
}

// runReplay waits for a genuine beacon from name and broadcasts an exact
// copy of it: the signature is valid, but the nonce has been seen before.
func runReplay(name string, wait time.Duration) int {
	conn, err := discovery.Listen(discovery.Port)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer conn.Close()
	fmt.Printf("[mallory] waiting for a beacon from %q to replay\n", name)
	conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, discovery.MaxSize)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("[mallory] no beacon captured")
			return 1
		}
		var b discovery.Beacon
		if json.Unmarshal(buf[:n], &b) != nil || b.Name != name {
			continue
		}
		captured := append([]byte(nil), buf[:n]...)
		fmt.Printf("[mallory] captured %s's beacon from %s; replaying it 3 times\n", name, from.IP)
		for range 3 {
			for _, t := range discovery.BroadcastTargets(discovery.Port) {
				conn.WriteToUDP(captured, t)
			}
			time.Sleep(500 * time.Millisecond)
		}
		return 0
	}
}
