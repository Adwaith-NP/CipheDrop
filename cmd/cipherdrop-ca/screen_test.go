package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cipherdrop/internal/cli"
	"cipherdrop/internal/control"
	"cipherdrop/internal/discovery"
)

// TestRootScreenPreview draws the real root console with sample data on a
// simulated terminal, checks it, and (with PREVIEW=file) saves it as text.
func TestRootScreenPreview(t *testing.T) {
	r := newRootScreen()
	snapshot, stop := r.Simulate(150, 34)
	defer stop()
	r.SetHeader(rootHeader("control", "192.168.56.2:47480", "3A:9B:9E:E4:E9:99:51:8D:2F:48", "WAfmVlmqECvFCEZLzkGh7F9u2INSrwVXY2+F5AVAjlw="))

	day := time.Date(2026, 11, 16, 5, 50, 0, 0, time.Local)
	slots := []control.Slot{
		{Name: "carol", Department: "hr", Purpose: "staff records", Status: control.SlotUsed, CreatedAt: day.Add(4 * time.Minute),
			UsedAt: day.Add(5 * time.Minute), UsedFrom: "192.168.56.30", CertFingerprint: "C", CertNotAfter: day.AddDate(0, 3, 0)},
		{Name: "bob", Department: "legal", Purpose: "contract archive", Status: control.SlotOpen, CreatedAt: day.Add(3 * time.Minute),
			ExpiresAt: time.Now().Add(20 * time.Hour)},
		{Name: "alice", Department: "finance", Purpose: "payroll exports", Status: control.SlotUsed, CreatedAt: day,
			UsedAt: day.Add(time.Minute), UsedFrom: "192.168.56.10", CertFingerprint: "A", CertNotAfter: day.AddDate(0, 3, 0)},
		{Name: "new-laptop", Department: "it", Purpose: "attack demo", Status: control.SlotLocked, CreatedAt: day.Add(10 * time.Minute)},
		{Name: "dave", Department: "sales", Purpose: "quarterly reports", Status: control.SlotUsed, CreatedAt: day.AddDate(0, -11, 0),
			UsedAt: day.AddDate(0, -11, 0), UsedFrom: "192.168.56.40", CertFingerprint: "D", CertNotAfter: time.Now().Add(12 * 24 * time.Hour)},
		{Name: "erin", Department: "it", Purpose: "backup server", Status: control.SlotUsed, CreatedAt: day.AddDate(-1, 0, -5),
			UsedAt: day.AddDate(-1, 0, -5), UsedFrom: "192.168.56.50", CertFingerprint: "E", CertNotAfter: time.Now().Add(-5 * 24 * time.Hour)},
	}
	seen := []discovery.Peer{
		{Name: "alice", Fingerprint: "A", State: discovery.StateSeen, FromIP: "192.168.56.10", LastSeen: time.Now()},
		{Name: "carol", Fingerprint: "C", State: discovery.StateOffline, FromIP: "192.168.56.30"},
		{Name: "bob", FromIP: "192.168.56.66", State: discovery.StateUnverified, LastSeen: time.Now(),
			Problem: "certificate not trusted: x509: certificate signed by unknown authority"},
	}
	views, intruders := deviceViews(control.Paths{Dir: t.TempDir()}, slots, seen)
	r.SetRows(r.devices, deviceCells(views))
	r.SetRows(r.intruders, intruderCells(intruders))
	ui := &cli.Printer{W: r}
	ui.Printf("ENROLLED alice (finance) from 192.168.56.10: 2FA proof valid, OpenSSL issued certificate serial 7F42E1CE1ACD1CDC")
	ui.Printf("● alice (finance) is online at 192.168.56.10")
	ui.Printf("⚠ UNVERIFIED device claiming \"bob\" at 192.168.56.66: certificate not trusted")
	ui.Printf("REFUSED enrolment for new-laptop (slot 9febbef9d9373e9b) from 192.168.56.66: wrong, expired or reused 2FA code [attempt 5/5]; slot locked")

	screen := snapshot()
	for _, want := range []string{"CipherDrop control server · control", "Registered devices", "enrolled", "waiting", "locked", "renew soon", "cert expired",
		"● online", "○ offline", "Unverified devices on the network", "root>"} {
		if !strings.Contains(screen, want) {
			t.Errorf("root screen is missing %q", want)
		}
	}
	t.Logf("\n%s", screen)
	if f := os.Getenv("PREVIEW"); f != "" {
		os.WriteFile(filepath.Clean(f), []byte(screen), 0o644)
	}
}
