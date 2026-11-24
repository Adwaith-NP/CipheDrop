package node

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cipherdrop/internal/devpki"
	"cipherdrop/internal/evidence"
	"cipherdrop/internal/trust"
)

type testUI struct {
	t     *testing.T
	mu    sync.Mutex
	lines []string
}

func (u *testUI) Printf(format string, args ...any) {
	s := fmt.Sprintf(format, args...)
	u.mu.Lock()
	u.lines = append(u.lines, s)
	u.mu.Unlock()
	u.t.Log(s)
}

func (u *testUI) contains(sub string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, l := range u.lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

type world struct {
	root, issuing *devpki.CA
	devices       map[string]*devpki.Device
}

func newWorld(t *testing.T) *world {
	root, _ := devpki.NewCA("Test Root CA")
	issuing, _ := root.NewIssuing("Test Issuing CA")
	w := &world{root: root, issuing: issuing, devices: map[string]*devpki.Device{}}
	for name, dept := range map[string]string{"alice": "finance", "bob": "legal", "carol": "hr"} {
		d, err := issuing.Issue(name, devpki.Department(dept))
		if err != nil {
			t.Fatal(err)
		}
		w.devices[name] = d
	}
	return w
}

func (w *world) local(name string) *trust.Local {
	d := w.devices[name]
	return &trust.Local{Name: name, Department: trust.Department(d.Cert), Cert: d.Cert,
		Chain: w.issuing.Chain, Root: w.root.Cert, Roots: w.root.Pool, TLS: d.TLS}
}

// start runs a listening node and returns it with its UI.
func (w *world) start(t *testing.T, name string, tweak func(*Options)) (*Node, *testUI) {
	t.Helper()
	home := t.TempDir()
	opts := DefaultOptions(home)
	if tweak != nil {
		tweak(&opts)
	}
	ui := &testUI{t: t}
	n := New(w.local(name), opts, ui)
	go n.Listen("127.0.0.1:0")
	for n.Addr() == nil {
		time.Sleep(5 * time.Millisecond)
	}
	t.Cleanup(n.Close)
	return n, ui
}

// sender makes a node that dials others at their test addresses.
func (w *world) sender(t *testing.T, name string, peers map[string]*Node) (*Node, *testUI) {
	return w.start(t, name, func(o *Options) {
		o.Resolve = func(peer string) string { return peers[peer].Addr().String() }
	})
}

func writeFile(t *testing.T, p string, data []byte) {
	t.Helper()
	os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestSendFolderWithSignedReceipt(t *testing.T) {
	w := newWorld(t)
	bob, bobUI := w.start(t, "bob", func(o *Options) { o.AcceptFrom = map[string]bool{"alice": true} })
	alice, _ := w.sender(t, "alice", map[string]*Node{"bob": bob})

	src := t.TempDir()
	big := make([]byte, 3<<20)
	rand.Read(big)
	want := map[string][]byte{
		"report.txt":            []byte("quarterly figures"),
		"project/main.go":       []byte("package main"),
		"project/data/blob.bin": big,
		"project/empty.txt":     {},
	}
	for p, d := range want {
		writeFile(t, filepath.Join(src, p), d)
	}
	res, err := alice.SendFiles(ctx(t), "bob", []string{filepath.Join(src, "report.txt"), filepath.Join(src, "project")}, "")
	if err != nil {
		t.Fatalf("transfer failed: %v", err)
	}
	if !res.Receipt.Complete || len(res.Receipt.Files) != 4 {
		t.Fatalf("receipt: %+v", res.Receipt)
	}
	dir := filepath.Join(bob.opts.Inbox, "alice-"+res.Manifest.TransferID[:8])
	for p, d := range want {
		got, err := os.ReadFile(filepath.Join(dir, p))
		if err != nil || !bytes.Equal(got, d) {
			t.Errorf("%s: content differs (%v)", p, err)
		}
	}
	// Both sides hold verifiable evidence.
	for _, f := range []string{res.ManifestFile, res.ReceiptFile,
		filepath.Join(bob.opts.EvidenceDir, res.Manifest.TransferID+".manifest.json")} {
		env, err := evidence.Load(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := env.Verify(env.Kind, w.root.Pool, time.Now()); err != nil {
			t.Errorf("%s does not verify: %v", filepath.Base(f), err)
		}
	}
	if !bobUI.contains("received 4/4 file(s) from alice") {
		t.Error("receiver did not report the transfer")
	}
}

func TestConsentAcceptAndDecline(t *testing.T) {
	w := newWorld(t)
	var bob *Node
	answer := true
	bob, _ = w.start(t, "bob", func(o *Options) {
		o.OnOffer = func(of *Offer) { go bob.Decide(of.ID, answer, "not today") }
	})
	alice, _ := w.sender(t, "alice", map[string]*Node{"bob": bob})
	src := filepath.Join(t.TempDir(), "note.txt")
	writeFile(t, src, []byte("hello"))

	if _, err := alice.SendFiles(ctx(t), "bob", []string{src}, ""); err != nil {
		t.Fatalf("accepted transfer failed: %v", err)
	}
	answer = false
	_, err := alice.SendFiles(ctx(t), "bob", []string{src}, "")
	if err == nil || !strings.Contains(err.Error(), "not today") {
		t.Fatalf("declined transfer: err = %v", err)
	}
}

func TestChatWithSignedAcknowledgement(t *testing.T) {
	w := newWorld(t)
	bob, bobUI := w.start(t, "bob", nil)
	alice, _ := w.sender(t, "alice", map[string]*Node{"bob": bob})
	ack, err := alice.SendMessage(ctx(t), "bob", "meeting at 3pm")
	if err != nil {
		t.Fatal(err)
	}
	if ack.From.Name != "bob" {
		t.Errorf("ack from %q", ack.From.Name)
	}
	if !bobUI.contains("[alice · finance] meeting at 3pm") {
		t.Error("bob did not see the message")
	}
	log, _ := os.ReadFile(alice.opts.ChatLog)
	if !strings.Contains(string(log), `"direction":"ack-in"`) {
		t.Error("signed acknowledgement not logged")
	}
	// bob replies over the connection alice opened.
	if _, err := bob.SendMessage(ctx(t), "alice", "ok"); err != nil {
		t.Fatalf("reply failed: %v", err)
	}
}

func TestChatDuringTransfer(t *testing.T) {
	w := newWorld(t)
	bob, _ := w.start(t, "bob", func(o *Options) { o.AutoAccept = true })
	alice, _ := w.sender(t, "alice", map[string]*Node{"bob": bob})
	src := filepath.Join(t.TempDir(), "large.bin")
	data := make([]byte, 24<<20)
	rand.Read(data)
	writeFile(t, src, data)

	done := make(chan error, 1)
	go func() { _, err := alice.SendFiles(ctx(t), "bob", []string{src}, ""); done <- err }()
	for i := range 5 {
		if _, err := alice.SendMessage(ctx(t), "bob", fmt.Sprintf("message %d while the file is moving", i)); err != nil {
			t.Fatalf("chat blocked by the transfer: %v", err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// offerRaw sends a hand-made manifest, signed with key, as a malicious
// enrolled peer could, and returns bob's answer.
func offerRaw(t *testing.T, from *Node, peer string, m Manifest, key ed25519.PrivateKey, chain [][]byte) Frame {
	t.Helper()
	conn, err := from.connect(ctx(t), peer)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := evidence.Sign(evidence.KindManifest, m, key, chain)
	str, err := conn.OpenStreamSync(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer str.Close()
	writeFrame(str, Frame{Type: "offer", Envelope: env})
	f, err := readFrame(str)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func goodManifest(from, to *Node, path string, content []byte) Manifest {
	sum := sha256.Sum256(content)
	return Manifest{TransferID: newID(), Sender: from.Self, Recipient: to.Self, Created: time.Now().UTC(),
		Files: []FileEntry{{Path: path, Size: int64(len(content)), SHA256: hex.EncodeToString(sum[:])}}, TotalSize: int64(len(content))}
}

func TestMaliciousOffersAreRejected(t *testing.T) {
	w := newWorld(t)
	var bob *Node
	bob, _ = w.start(t, "bob", func(o *Options) {
		o.OnOffer = func(of *Offer) { go bob.Decide(of.ID, false, "declined") }
	})
	alice, _ := w.sender(t, "alice", map[string]*Node{"bob": bob})
	carol := New(w.local("carol"), DefaultOptions(t.TempDir()), &testUI{t: t})
	aliceKey := w.devices["alice"].TLS.PrivateKey.(ed25519.PrivateKey)
	aliceChain := w.devices["alice"].TLS.Certificate
	carolKey := w.devices["carol"].TLS.PrivateKey.(ed25519.PrivateKey)
	carolChain := w.devices["carol"].TLS.Certificate

	cases := []struct {
		name  string
		build func() Manifest
		key   ed25519.PrivateKey
		chain [][]byte
		want  string
	}{
		{"path traversal", func() Manifest { return goodManifest(alice, bob, "../../home/bob/.bashrc", []byte("x")) }, aliceKey, aliceChain, "escapes"},
		{"absolute path", func() Manifest { return goodManifest(alice, bob, "/etc/passwd", []byte("x")) }, aliceKey, aliceChain, "escapes"},
		{"terminal escape in name", func() Manifest { return goodManifest(alice, bob, "a\x1b[2Jb.txt", []byte("x")) }, aliceKey, aliceChain, "control characters"},
		{"addressed to carol", func() Manifest { return goodManifest(alice, carol, "a.txt", []byte("x")) }, aliceKey, aliceChain, "another device"},
		{"signed by carol, sent by alice", func() Manifest { return goodManifest(alice, bob, "a.txt", []byte("x")) }, carolKey, carolChain, "not signed by the connected device"},
		{"size over the limit", func() Manifest {
			m := goodManifest(alice, bob, "huge.iso", []byte("x"))
			m.Files[0].Size, m.TotalSize = 64<<30, 64<<30
			return m
		}, aliceKey, aliceChain, "above this receiver's limit"},
		{"file and folder with one name", func() Manifest {
			m := goodManifest(alice, bob, "a", []byte("x"))
			m.Files = append(m.Files, FileEntry{Path: "a/b", Size: 0, SHA256: strings.Repeat("0", 64)})
			return m
		}, aliceKey, aliceChain, "both a file and a folder"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := offerRaw(t, alice, "bob", tc.build(), tc.key, tc.chain)
			if f.Type != "reject" || !strings.Contains(f.Reason, tc.want) {
				t.Fatalf("got %s %q, want reject mentioning %q", f.Type, f.Reason, tc.want)
			}
			t.Logf("rejected: %s", f.Reason)
		})
	}

	t.Run("replayed manifest", func(t *testing.T) {
		m := goodManifest(alice, bob, "a.txt", []byte("x"))
		offerRaw(t, alice, "bob", m, aliceKey, aliceChain) // declined, but now seen
		f := offerRaw(t, alice, "bob", m, aliceKey, aliceChain)
		if !strings.Contains(f.Reason, "replay") {
			t.Fatalf("replay not detected: %q", f.Reason)
		}
	})
	entries, _ := os.ReadDir(bob.opts.Inbox)
	if len(entries) != 0 {
		t.Errorf("rejected offers created %d inbox entries", len(entries))
	}
}

// TestTamperedDataIsDiscarded: a peer whose bytes do not match its own
// signed manifest gets a receipt that says so, and nothing is kept.
func TestTamperedDataIsDiscarded(t *testing.T) {
	w := newWorld(t)
	bob, _ := w.start(t, "bob", func(o *Options) { o.AutoAccept = true })
	alice, _ := w.sender(t, "alice", map[string]*Node{"bob": bob})
	m := goodManifest(alice, bob, "invoice.txt", []byte("pay 100 EUR"))
	env, _ := evidence.Sign(evidence.KindManifest, m, w.devices["alice"].TLS.PrivateKey.(ed25519.PrivateKey), w.devices["alice"].TLS.Certificate)

	conn, _ := alice.connect(ctx(t), "bob")
	str, _ := conn.OpenStreamSync(ctx(t))
	writeFrame(str, Frame{Type: "offer", Envelope: env})
	if f, _ := readFrame(str); f.Type != "accept" {
		t.Fatalf("expected accept, got %+v", f)
	}
	us, _ := conn.OpenUniStreamSync(ctx(t))
	writeFrame(us, Frame{Type: "data", TransferID: m.TransferID, Index: 0})
	us.Write([]byte("pay 900 EUR")) // same length, different content
	us.Close()

	f, err := readFrame(str)
	if err != nil || f.Type != "receipt" {
		t.Fatalf("no receipt: %v %+v", err, f)
	}
	var rc Receipt
	f.Envelope.Decode(&rc)
	if rc.Complete || rc.Files[0].Status != "hash_mismatch" {
		t.Fatalf("receipt should report the mismatch: %+v", rc)
	}
	if _, err := os.Stat(filepath.Join(bob.opts.Inbox, "alice-"+m.TransferID[:8], "invoice.txt")); err == nil {
		t.Fatal("tampered file was kept")
	}
}

func TestCollectSkipsSymlinks(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "share")
	writeFile(t, filepath.Join(dir, "ok.txt"), []byte("fine"))
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "passwd")); err != nil {
		t.Skip(err)
	}
	files, skipped, err := collectFiles([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].entry.Path != "share/ok.txt" || len(skipped) != 1 {
		t.Fatalf("files=%v skipped=%v", files, skipped)
	}
}

func TestSanitize(t *testing.T) {
	if got := Sanitize("hi\x1b[31mred‮"); strings.ContainsAny(got, "\x1b‮") {
		t.Errorf("escape survived: %q", got)
	}
}
