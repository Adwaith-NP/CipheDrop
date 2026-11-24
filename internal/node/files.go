package node

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
)

// localFile is a file the sender is about to offer.
type localFile struct {
	abs   string
	entry FileEntry
}

// collectFiles expands the paths given on the command line into regular
// files with relative names, and hashes each one with SHA-256. A folder
// keeps its own name as the top-level directory. Symbolic links and special
// files are skipped, so the sender never follows a link out of the folder.
func collectFiles(args []string) ([]localFile, []string, error) {
	var out []localFile
	var skipped []string
	seen := map[string]bool{}
	add := func(abs, rel string, info fs.FileInfo) error {
		rel = filepath.ToSlash(rel)
		if err := ValidatePath(rel); err != nil {
			return err
		}
		if seen[rel] {
			return fmt.Errorf("%s is given twice", rel)
		}
		seen[rel] = true
		sum, err := hashFile(abs)
		if err != nil {
			return err
		}
		out = append(out, localFile{abs: abs, entry: FileEntry{Path: rel, Size: info.Size(), Mode: uint32(info.Mode().Perm()), SHA256: sum}})
		return nil
	}
	for _, arg := range args {
		abs, err := filepath.Abs(arg)
		if err != nil {
			return nil, nil, err
		}
		info, err := os.Lstat(abs)
		if err != nil {
			return nil, nil, err
		}
		switch {
		case info.Mode().IsRegular():
			if err := add(abs, filepath.Base(abs), info); err != nil {
				return nil, nil, err
			}
		case info.IsDir():
			base := filepath.Dir(abs)
			err := filepath.WalkDir(abs, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				fi, err := d.Info()
				if err != nil {
					return err
				}
				if !fi.Mode().IsRegular() {
					skipped = append(skipped, p)
					return nil
				}
				rel, err := filepath.Rel(base, p)
				if err != nil {
					return err
				}
				return add(p, rel, fi)
			})
			if err != nil {
				return nil, nil, err
			}
		default:
			skipped = append(skipped, abs)
		}
	}
	if len(out) == 0 {
		return nil, skipped, fmt.Errorf("nothing to send")
	}
	if len(out) > MaxFiles {
		return nil, skipped, fmt.Errorf("too many files (%d, limit %d)", len(out), MaxFiles)
	}
	return out, skipped, nil
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// topLevel summarises a manifest for display, e.g. "report.pdf, src/ (12 files)".
func topLevel(m *Manifest) string {
	counts := map[string]int{}
	var order []string
	for _, f := range m.Files {
		top := f.Path
		for d := path.Dir(f.Path); d != "."; d = path.Dir(d) {
			top = d + "/"
		}
		if counts[top] == 0 {
			order = append(order, top)
		}
		counts[top]++
	}
	s := ""
	for i, t := range order {
		if i > 0 {
			s += ", "
		}
		if i == 4 {
			s += fmt.Sprintf("and %d more", len(order)-4)
			break
		}
		s += Sanitize(t)
		if counts[t] > 1 {
			s += fmt.Sprintf(" (%d files)", counts[t])
		}
	}
	return s
}
