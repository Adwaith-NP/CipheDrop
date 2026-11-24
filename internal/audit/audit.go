// Package audit keeps a tamper-evident log of administrative actions.
//
// Each entry stores the SHA-256 hash of the previous entry (a hash chain), so
// deleting, reordering or editing any entry breaks every hash after it. Each
// entry's hash is also signed with the control server's Ed25519 audit key,
// so an entry cannot be forged without that key. Together they give
// non-repudiation for admin actions: who created which enrolment slot, which
// device was enrolled, which attempts failed.
package audit

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"cipherdrop/internal/filelock"
)

// Entry is one line of the log.
type Entry struct {
	Seq     int64             `json:"seq"`
	Time    string            `json:"time"`
	Actor   string            `json:"actor"`
	Event   string            `json:"event"`
	Details map[string]string `json:"details,omitempty"`
	Prev    string            `json:"prev"`
	Hash    string            `json:"hash"`
	Sig     []byte            `json:"sig"`
}

const genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// digest hashes the entry with Hash and Sig cleared. encoding/json writes
// struct fields in declaration order and map keys sorted, so the bytes are
// canonical.
func digest(e Entry) (string, error) {
	e.Hash, e.Sig = "", nil
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Log appends signed entries to a file.
type Log struct {
	Path string
	Key  ed25519.PrivateKey
}

// Append adds one entry, chained to the last one and signed.
func (l *Log) Append(actor, event string, details map[string]string) error {
	return filelock.With(l.Path+".lock", func() error {
		last, err := readAll(l.Path)
		if err != nil {
			return err
		}
		e := Entry{Seq: 1, Prev: genesis, Time: time.Now().UTC().Format(time.RFC3339Nano),
			Actor: actor, Event: event, Details: details}
		if n := len(last); n > 0 {
			e.Seq = last[n-1].Seq + 1
			e.Prev = last[n-1].Hash
		}
		if e.Hash, err = digest(e); err != nil {
			return err
		}
		raw, _ := hex.DecodeString(e.Hash)
		e.Sig = ed25519.Sign(l.Key, raw)
		line, err := json.Marshal(e)
		if err != nil {
			return err
		}
		f, err := os.OpenFile(l.Path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(line, '\n')); err != nil {
			f.Close()
			return err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	})
}

// Verify checks the whole chain and every signature. It returns the entries
// if the log is intact.
func Verify(path string, pub ed25519.PublicKey) ([]Entry, error) {
	entries, err := readAll(path)
	if err != nil {
		return nil, err
	}
	prev := genesis
	for i, e := range entries {
		if e.Seq != int64(i+1) {
			return nil, fmt.Errorf("entry %d: sequence number %d, expected %d (entry removed or reordered)", i+1, e.Seq, i+1)
		}
		if e.Prev != prev {
			return nil, fmt.Errorf("entry %d: chain broken, previous hash does not match", e.Seq)
		}
		h, err := digest(e)
		if err != nil {
			return nil, err
		}
		if h != e.Hash {
			return nil, fmt.Errorf("entry %d: content was modified (hash mismatch)", e.Seq)
		}
		raw, _ := hex.DecodeString(e.Hash)
		if !ed25519.Verify(pub, raw, e.Sig) {
			return nil, fmt.Errorf("entry %d: signature invalid", e.Seq)
		}
		prev = e.Hash
	}
	return entries, nil
}

func readAll(path string) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Entry
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, n, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}
