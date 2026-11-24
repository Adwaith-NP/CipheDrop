// Package node is the CipherDrop peer: it accepts and opens mutually
// authenticated QUIC connections and runs file transfers and chat over them.
//
// One QUIC connection per pair of devices carries everything at once:
//
//	bidirectional stream per chat message   msg  -> ack       (both signed)
//	bidirectional stream per transfer        offer -> accept/reject ... receipt
//	one unidirectional stream per file       data header + raw bytes
//
// Because QUIC multiplexes streams, a large transfer never blocks chat.
package node

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"cipherdrop/internal/evidence"
)

// Frame is one length-prefixed JSON message on a stream.
type Frame struct {
	Type       string             `json:"type"` // msg, ack, offer, accept, reject, receipt, data
	Envelope   *evidence.Envelope `json:"envelope,omitempty"`
	TransferID string             `json:"transfer_id,omitempty"`
	Index      int                `json:"index,omitempty"`
	Reason     string             `json:"reason,omitempty"`
}

// maxFrame bounds a frame so a peer cannot make us allocate without limit.
const maxFrame = 4 << 20

func writeFrame(w io.Writer, f Frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(b) > maxFrame {
		return errors.New("frame too large")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readFrame(r io.Reader) (Frame, error) {
	var f Frame
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return f, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxFrame {
		return f, fmt.Errorf("invalid frame length %d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return f, err
	}
	return f, json.Unmarshal(b, &f)
}

// Manifest is the sender's signed statement of exactly what it is sending
// and to whom: proof of origin.
type Manifest struct {
	TransferID string         `json:"transfer_id"`
	Sender     evidence.Party `json:"sender"`
	Recipient  evidence.Party `json:"recipient"`
	Created    time.Time      `json:"created"`
	Files      []FileEntry    `json:"files"`
	TotalSize  int64          `json:"total_size"`
	Note       string         `json:"note,omitempty"`
}

// FileEntry describes one file in a manifest.
type FileEntry struct {
	Path   string `json:"path"` // relative, forward slashes
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

// Receipt is the recipient's signed statement of what it received: proof
// of delivery. ManifestSHA256 binds it to one exact signed manifest.
type Receipt struct {
	TransferID     string         `json:"transfer_id"`
	ManifestSHA256 string         `json:"manifest_sha256"`
	Sender         evidence.Party `json:"sender"`
	Recipient      evidence.Party `json:"recipient"`
	Received       time.Time      `json:"received"`
	Files          []FileResult   `json:"files"`
	Complete       bool           `json:"complete"`
}

// FileResult is the outcome for one file.
type FileResult struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"` // hash of the bytes actually received
	Status string `json:"status"`           // ok, hash_mismatch, failed
}

// Message is a signed chat message.
type Message struct {
	ID   string         `json:"id"`
	From evidence.Party `json:"from"`
	To   evidence.Party `json:"to"`
	Sent time.Time      `json:"sent"`
	Text string         `json:"text"`
}

// MessageAck is the recipient's signed confirmation of one message.
type MessageAck struct {
	ID            string         `json:"id"`
	MessageSHA256 string         `json:"message_sha256"`
	From          evidence.Party `json:"from"` // who received the message
	To            evidence.Party `json:"to"`
	Received      time.Time      `json:"received"`
}

// Limits a receiver enforces on an offer.
const (
	MaxFiles       = 10000
	MaxMessageText = 4096
)

func newID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ValidatePath rejects any path that could escape the transfer folder or
// confuse the receiver: absolute paths, "..", backslashes, control
// characters, unclean forms, and our own temporary suffix.
func ValidatePath(p string) error {
	switch {
	case p == "" || len(p) > 1024:
		return fmt.Errorf("invalid path length")
	case strings.ContainsRune(p, '\\'):
		return fmt.Errorf("path %q contains a backslash", Sanitize(p))
	case !filepath.IsLocal(p) || path.IsAbs(p):
		return fmt.Errorf("path %q escapes the transfer folder", Sanitize(p))
	case path.Clean(p) != p:
		return fmt.Errorf("path %q is not in canonical form", Sanitize(p))
	case strings.HasSuffix(p, ".part"):
		return fmt.Errorf("path %q uses a reserved suffix", Sanitize(p))
	}
	for _, r := range p {
		if unicode.IsControl(r) {
			return fmt.Errorf("path %q contains control characters", Sanitize(p))
		}
	}
	return nil
}

// ValidateManifest checks the file list before anything is written.
func ValidateManifest(m *Manifest, maxTotal int64) error {
	if len(m.Files) == 0 || len(m.Files) > MaxFiles {
		return fmt.Errorf("offer has %d files (allowed 1-%d)", len(m.Files), MaxFiles)
	}
	files := map[string]bool{}
	dirs := map[string]bool{}
	var total int64
	for _, f := range m.Files {
		if err := ValidatePath(f.Path); err != nil {
			return err
		}
		if f.Size < 0 || len(f.SHA256) != 64 {
			return fmt.Errorf("bad size or hash for %q", Sanitize(f.Path))
		}
		if files[f.Path] {
			return fmt.Errorf("duplicate path %q", Sanitize(f.Path))
		}
		files[f.Path] = true
		for d := path.Dir(f.Path); d != "."; d = path.Dir(d) {
			dirs[d] = true
		}
		total += f.Size
	}
	for f := range files {
		if dirs[f] {
			return fmt.Errorf("%q is both a file and a folder", Sanitize(f))
		}
	}
	if total != m.TotalSize {
		return errors.New("total size does not match the file list")
	}
	if maxTotal > 0 && total > maxTotal {
		return fmt.Errorf("offer is %s, above this receiver's limit of %s", HumanBytes(total), HumanBytes(maxTotal))
	}
	return nil
}

// Sanitize makes peer-supplied text safe to print: control characters
// (including ANSI escape sequences that could rewrite the terminal) are
// replaced, so a malicious peer cannot spoof what the user sees.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) || r == ' ' || r == ' ' || r == '‮' {
			return '�'
		}
		return r
	}, s)
}

// HumanBytes formats a byte count.
func HumanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
