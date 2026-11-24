package audit

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func newLog(t *testing.T) (*Log, ed25519.PublicKey) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	l := &Log{Path: filepath.Join(t.TempDir(), "audit.log"), Key: priv}
	for _, ev := range []string{"admin_login", "slot_created", "device_enrolled"} {
		if err := l.Append("admin", ev, map[string]string{"name": "alice"}); err != nil {
			t.Fatal(err)
		}
	}
	return l, pub
}

func TestIntactLogVerifies(t *testing.T) {
	l, pub := newLog(t)
	entries, err := Verify(l.Path, pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || entries[2].Event != "device_enrolled" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	cases := map[string]func([]byte) []byte{
		"edit a detail": func(b []byte) []byte { return bytes.Replace(b, []byte(`"alice"`), []byte(`"mallo"`), 1) },
		"delete an entry": func(b []byte) []byte {
			lines := bytes.SplitAfter(b, []byte("\n"))
			return bytes.Join(append(lines[:1], lines[2:]...), nil)
		},
		"reorder entries": func(b []byte) []byte {
			l := bytes.SplitAfter(b, []byte("\n"))
			return bytes.Join([][]byte{l[1], l[0], l[2]}, nil)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			l, pub := newLog(t)
			data, _ := os.ReadFile(l.Path)
			os.WriteFile(l.Path, mutate(data), 0o600)
			if _, err := Verify(l.Path, pub); err == nil {
				t.Fatal("tampered log verified")
			} else {
				t.Logf("detected: %v", err)
			}
		})
	}
}

func TestWrongKeyIsDetected(t *testing.T) {
	l, _ := newLog(t)
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := Verify(l.Path, other); err == nil {
		t.Fatal("log verified with the wrong public key")
	}
}
