package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"cipherdrop/internal/evidence"
	"cipherdrop/internal/identity"
)

// parallelFiles is how many files are sent at once, each on its own QUIC stream.
const parallelFiles = 4

// SendResult describes a finished transfer.
type SendResult struct {
	Manifest     Manifest
	Receipt      Receipt
	Bytes        int64
	Elapsed      time.Duration
	Skipped      []string
	ManifestFile string
	ReceiptFile  string
}

// SendFiles offers files and folders to peer. The sender hashes every file,
// signs a manifest (proof of origin), waits for the recipient's consent,
// streams the files in parallel, and finally verifies the recipient's signed
// receipt (proof of delivery). Both statements are saved as evidence.
func (n *Node) SendFiles(ctx context.Context, peer string, paths []string, note string) (*SendResult, error) {
	files, skipped, err := collectFiles(paths)
	if err != nil {
		return nil, err
	}
	conn, err := n.connect(ctx, peer)
	if err != nil {
		return nil, err
	}
	pc := peerCert(conn)
	m := Manifest{TransferID: newID(), Sender: n.Self, Recipient: evidence.PartyOf(pc),
		Created: time.Now().UTC(), Note: note}
	for _, f := range files {
		m.Files = append(m.Files, f.entry)
		m.TotalSize += f.entry.Size
	}
	menv, err := evidence.Sign(evidence.KindManifest, m, n.key, n.Local.TLS.Certificate)
	if err != nil {
		return nil, err
	}

	str, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer str.Close()
	if err := writeFrame(str, Frame{Type: "offer", Envelope: menv}); err != nil {
		return nil, err
	}
	n.ui.Printf("offered %d file(s), %s to %s; waiting for them to accept", len(m.Files), HumanBytes(m.TotalSize), peer)
	str.SetReadDeadline(time.Now().Add(n.opts.DecisionTimeout + 30*time.Second))
	reply, err := readFrame(str)
	if err != nil {
		return nil, fmt.Errorf("no answer from %s: %w", peer, err)
	}
	if reply.Type != "accept" || reply.TransferID != m.TransferID {
		return nil, fmt.Errorf("%s refused the transfer: %s", peer, Sanitize(reply.Reason))
	}

	start := time.Now()
	if err := sendAll(ctx, conn, m.TransferID, files); err != nil {
		return nil, err
	}

	str.SetReadDeadline(time.Now().Add(2*time.Minute + time.Duration(m.TotalSize/(1<<20))*time.Second))
	rf, err := readFrame(str)
	if err != nil {
		return nil, fmt.Errorf("no receipt from %s: %w", peer, err)
	}
	elapsed := time.Since(start)
	if rf.Type != "receipt" || rf.Envelope == nil {
		return nil, fmt.Errorf("%s did not send a receipt: %s", peer, Sanitize(rf.Reason))
	}
	signer, err := rf.Envelope.Verify(evidence.KindReceipt, n.Local.Roots, time.Now())
	if err != nil {
		return nil, fmt.Errorf("receipt rejected: %w", err)
	}
	if identity.Fingerprint(signer) != identity.Fingerprint(pc) {
		return nil, errNotPeer
	}
	var rc Receipt
	if err := rf.Envelope.Decode(&rc); err != nil {
		return nil, err
	}
	if rc.TransferID != m.TransferID || rc.ManifestSHA256 != menv.Digest() || rc.Sender.Fingerprint != n.Self.Fingerprint {
		return nil, errors.New("receipt does not refer to this transfer")
	}

	res := &SendResult{Manifest: m, Receipt: rc, Bytes: m.TotalSize, Elapsed: elapsed, Skipped: skipped,
		ManifestFile: filepath.Join(n.opts.EvidenceDir, m.TransferID+".manifest.json"),
		ReceiptFile:  filepath.Join(n.opts.EvidenceDir, m.TransferID+".receipt.json")}
	if err := menv.Save(res.ManifestFile); err != nil {
		return res, err
	}
	if err := rf.Envelope.Save(res.ReceiptFile); err != nil {
		return res, err
	}
	if !rc.Complete {
		var bad []string
		for _, f := range rc.Files {
			if f.Status != "ok" {
				bad = append(bad, f.Path+" ("+f.Status+")")
			}
		}
		return res, fmt.Errorf("%s reports problems with: %v", peer, bad)
	}
	return res, nil
}

// sendAll streams every file on its own unidirectional QUIC stream,
// parallelFiles at a time.
func sendAll(ctx context.Context, conn *quic.Conn, id string, files []localFile) error {
	sem := make(chan struct{}, parallelFiles)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for i, f := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if err := sendOne(ctx, conn, id, i, f); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("send %s: %w", f.entry.Path, err)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return firstErr
}

func sendOne(ctx context.Context, conn *quic.Conn, id string, idx int, f localFile) error {
	us, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return err
	}
	if err := writeFrame(us, Frame{Type: "data", TransferID: id, Index: idx}); err != nil {
		us.CancelWrite(1)
		return err
	}
	src, err := os.Open(f.abs)
	if err != nil {
		us.CancelWrite(1)
		return err
	}
	defer src.Close()
	// Send exactly the size in the signed manifest. If the file changed
	// since it was hashed, the receiver's hash check will catch it.
	if _, err := io.CopyN(us, src, f.entry.Size); err != nil {
		us.CancelWrite(1)
		return err
	}
	return us.Close()
}

// incomingTransfer is an accepted offer whose files are arriving.
type incomingTransfer struct {
	m         Manifest
	conn      *quic.Conn
	dir       string
	root      *os.Root
	mu        sync.Mutex
	started   []bool
	results   []FileResult
	remaining int
	done      chan struct{}
}

var transferIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (n *Node) handleOffer(conn *quic.Conn, str *quic.Stream, f Frame) {
	defer str.Close()
	reject := func(reason string) {
		writeFrame(str, Frame{Type: "reject", Reason: reason})
	}
	if f.Envelope == nil {
		reject("missing manifest")
		return
	}
	pc := peerCert(conn)
	// Proof of origin: the manifest must be signed by the device on the
	// other end of this mutually authenticated connection.
	signer, err := f.Envelope.Verify(evidence.KindManifest, n.Local.Roots, time.Now())
	if err != nil {
		n.ui.Printf("rejected an offer from %s: %v", pc.Subject.CommonName, err)
		reject(err.Error())
		return
	}
	if identity.Fingerprint(signer) != identity.Fingerprint(pc) {
		reject(errNotPeer.Error())
		return
	}
	var m Manifest
	if err := f.Envelope.Decode(&m); err != nil {
		reject("malformed manifest")
		return
	}
	switch {
	case !transferIDRe.MatchString(m.TransferID):
		reject("bad transfer id")
		return
	case m.Sender.Fingerprint != identity.Fingerprint(pc):
		reject("manifest names a different sender")
		return
	case m.Recipient.Fingerprint != n.Self.Fingerprint:
		reject("manifest is addressed to another device")
		return
	case time.Since(m.Created).Abs() > time.Hour:
		reject("manifest is too old or from the future (check clocks)")
		return
	case !n.markSeen("transfer:" + m.TransferID):
		reject("transfer id already used (replay)")
		return
	}
	if err := ValidateManifest(&m, n.opts.MaxTotal); err != nil {
		n.ui.Printf("rejected an unsafe offer from %s: %v", Sanitize(m.Sender.Name), err)
		reject(err.Error())
		return
	}

	d := n.awaitDecision(m)
	if !d.accept {
		reason := d.reason
		if reason == "" {
			reason = "declined by the recipient"
		}
		reject(reason)
		return
	}

	tr, err := n.prepareIncoming(conn, m)
	if err != nil {
		n.ui.Printf("cannot receive from %s: %v", m.Sender.Name, err)
		reject("receiver error")
		return
	}
	defer tr.root.Close()
	if err := writeFrame(str, Frame{Type: "accept", TransferID: m.TransferID}); err != nil {
		n.dropIncoming(m.TransferID)
		return
	}
	n.ui.Printf("receiving %d file(s), %s from %s into %s", len(m.Files), HumanBytes(m.TotalSize), m.Sender.Name, tr.dir)

	timeout := 2*time.Minute + time.Duration(m.TotalSize/(1<<20))*time.Second
	select {
	case <-tr.done:
	case <-conn.Context().Done():
	case <-time.After(timeout):
	}
	n.dropIncoming(m.TransferID)

	tr.mu.Lock()
	results := append([]FileResult(nil), tr.results...)
	tr.mu.Unlock()
	complete := true
	for i := range results {
		if results[i].Status == "" {
			results[i].Status = "failed"
		}
		if results[i].Status != "ok" {
			complete = false
		}
	}
	rc := Receipt{TransferID: m.TransferID, ManifestSHA256: f.Envelope.Digest(), Sender: m.Sender,
		Recipient: n.Self, Received: time.Now().UTC(), Files: results, Complete: complete}
	renv, err := evidence.Sign(evidence.KindReceipt, rc, n.key, n.Local.TLS.Certificate)
	if err != nil {
		return
	}
	f.Envelope.Save(filepath.Join(n.opts.EvidenceDir, m.TransferID+".manifest.json"))
	renv.Save(filepath.Join(n.opts.EvidenceDir, m.TransferID+".receipt.json"))
	str.SetWriteDeadline(time.Now().Add(30 * time.Second))
	writeFrame(str, Frame{Type: "receipt", Envelope: renv})

	ok := 0
	for _, r := range results {
		if r.Status == "ok" {
			ok++
		}
	}
	n.ui.Printf("received %d/%d file(s) from %s, every SHA-256 checked against the signed manifest; signed receipt sent",
		ok, len(results), m.Sender.Name)
}

func (n *Node) prepareIncoming(conn *quic.Conn, m Manifest) (*incomingTransfer, error) {
	// The sender's name passed the certificate policy, so it is a safe
	// single path element.
	dir := filepath.Join(n.opts.Inbox, m.Sender.Name+"-"+m.TransferID[:8])
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// os.Root confines every file operation to dir: no "..", absolute path
	// or symbolic link can make a write land outside it.
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	tr := &incomingTransfer{m: m, conn: conn, dir: dir, root: root,
		started: make([]bool, len(m.Files)), results: make([]FileResult, len(m.Files)),
		remaining: len(m.Files), done: make(chan struct{})}
	for i, f := range m.Files {
		tr.results[i].Path = f.Path
	}
	n.mu.Lock()
	n.incoming[m.TransferID] = tr
	n.mu.Unlock()
	return tr, nil
}

func (n *Node) dropIncoming(id string) {
	n.mu.Lock()
	delete(n.incoming, id)
	n.mu.Unlock()
}

// handleData receives one file on a unidirectional stream.
func (n *Node) handleData(conn *quic.Conn, us *quic.ReceiveStream) {
	us.SetReadDeadline(time.Now().Add(15 * time.Second))
	f, err := readFrame(us)
	if err != nil || f.Type != "data" {
		us.CancelRead(1)
		return
	}
	n.mu.Lock()
	tr, ok := n.incoming[f.TransferID]
	n.mu.Unlock()
	// Data is accepted only for an accepted offer, only from the connection
	// that made it, and only once per file.
	if !ok || tr.conn != conn || f.Index < 0 || f.Index >= len(tr.m.Files) {
		us.CancelRead(1)
		return
	}
	tr.mu.Lock()
	if tr.started[f.Index] {
		tr.mu.Unlock()
		us.CancelRead(1)
		return
	}
	tr.started[f.Index] = true
	tr.mu.Unlock()

	entry := tr.m.Files[f.Index]
	us.SetReadDeadline(time.Now().Add(30 * time.Minute))
	status, got := receiveFile(tr.root, entry, us)

	tr.mu.Lock()
	tr.results[f.Index] = FileResult{Path: entry.Path, SHA256: got, Status: status}
	tr.remaining--
	if tr.remaining == 0 {
		close(tr.done)
	}
	tr.mu.Unlock()
	if status != "ok" {
		n.ui.Printf("file %s from %s: %s, discarded", Sanitize(entry.Path), tr.m.Sender.Name, status)
	}
}

// receiveFile writes one file to a temporary name inside root, checks its
// SHA-256 against the signed manifest, and only then gives it its real
// name. A file that does not match is deleted.
func receiveFile(root *os.Root, e FileEntry, r io.Reader) (status, sum string) {
	if dir := path.Dir(e.Path); dir != "." {
		if err := root.MkdirAll(dir, 0o700); err != nil {
			return "failed", ""
		}
	}
	tmp := e.Path + ".part"
	out, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "failed", ""
	}
	h := sha256.New()
	_, err = io.CopyN(io.MultiWriter(out, h), r, e.Size)
	var extra [1]byte
	if err == nil {
		if k, _ := r.Read(extra[:]); k > 0 {
			err = errors.New("more data than the manifest declared")
		}
	}
	closeErr := out.Close()
	sum = hex.EncodeToString(h.Sum(nil))
	switch {
	case err != nil || closeErr != nil:
		root.Remove(tmp)
		return "failed", ""
	case sum != e.SHA256:
		root.Remove(tmp)
		return "hash_mismatch", sum
	}
	// Received files are never executable, whatever mode the sender had.
	root.Chmod(tmp, 0o644)
	if err := root.Rename(tmp, e.Path); err != nil {
		root.Remove(tmp)
		return "failed", sum
	}
	return "ok", sum
}
