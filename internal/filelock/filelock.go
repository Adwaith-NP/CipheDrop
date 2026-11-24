// Package filelock serialises access to a state file between processes
// (the control server and the admin CLI run separately).
package filelock

import (
	"os"
	"syscall"
)

// With opens path (creating it if needed), holds an exclusive flock while fn
// runs, then releases it.
func With(path string, fn func() error) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}
