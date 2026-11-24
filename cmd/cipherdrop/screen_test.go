package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"cipherdrop/internal/cli"
	"cipherdrop/internal/devpki"
	"cipherdrop/internal/discovery"
	"cipherdrop/internal/evidence"
	"cipherdrop/internal/node"
	"cipherdrop/internal/trust"
)

// TestConsoleScreenPreview draws the real user console with sample data on
// a simulated terminal, checks it, and (with PREVIEW=file) saves it as text.
func TestConsoleScreenPreview(t *testing.T) {
	root, _ := devpki.NewCA("CipherDrop Root CA")
	issuing, _ := root.NewIssuing("CipherDrop Issuing CA 1")
	bob, _ := issuing.Issue("bob", devpki.Department("legal"))
	me := &trust.Local{Name: "bob", Department: "legal", Cert: bob.Cert, Chain: issuing.Chain, Root: root.Cert, Roots: root.Pool, TLS: bob.TLS}

	scr, devices, offers := newConsoleScreen()
	snapshot, stop := scr.Simulate(150, 36)
	defer stop()
	scr.SetPrompt("bob> ")
	scr.SetHeader(consoleHeader(me, "/var/lib/cipherdrop/inbox"))
	now := time.Now()
	scr.SetRows(devices, peerRows([]discovery.Peer{
		{Name: "alice", Department: "finance", FromIP: "192.168.56.10", State: discovery.StateVerified, Code: "891 922", Fingerprint: "04:A7:AC:DE:11", VerifiedAt: now},
		{Name: "carol", Department: "hr", FromIP: "192.168.56.30", State: discovery.StateVerified, Code: "041 985", Fingerprint: "DB:BB:37:4C:3E", VerifiedAt: now},
		{Name: "bob", FromIP: "192.168.56.66", State: discovery.StateUnverified, Problem: "certificate not trusted: x509: certificate signed by unknown authority"},
	}))
	scr.SetRows(offers, offerRows([]*node.Offer{{ID: 1, Manifest: node.Manifest{
		Sender: evidence.Party{Name: "alice", Department: "finance"}, TotalSize: 52428950,
		Files: []node.FileEntry{{Path: "payroll/october.csv"}, {Path: "payroll/scans.bin"}, {Path: "q3-summary.txt"}}}}}))
	ui := &cli.Printer{W: scr}
	ui.Printf("✓ alice (finance) verified (mutual TLS 1.3, both certificates checked, X25519MLKEM768, code 891 922)")
	ui.Printf("✓ carol (hr) verified (mutual TLS 1.3, both certificates checked, X25519MLKEM768, code 041 985)")
	ui.Printf("✗ UNVERIFIED device claiming \"bob\" at 192.168.56.66: certificate not trusted")
	ui.Printf("[alice · finance] the October payroll files are ready   (signature verified)")
	ui.Printf("incoming offer #1 from alice: 3 file(s), 50.0 MiB  type accept 1 or reject 1")

	screen := snapshot()
	for _, want := range []string{"CipherDrop · bob", "Devices on the network", "alice", "891 922", "NOT VERIFIED",
		"Waiting for your answer", "accept 1  or  reject 1", "Messages and events", "bob>"} {
		if !strings.Contains(screen, want) {
			t.Errorf("console screen is missing %q", want)
		}
	}
	t.Logf("\n%s", screen)
	if f := os.Getenv("PREVIEW"); f != "" {
		os.WriteFile(f, []byte(screen), 0o644)
	}
	_ = fmt.Sprint
}
