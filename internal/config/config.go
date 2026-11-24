// Package config holds CipherDrop's fixed settings and where state lives on disk.
package config

import (
	"errors"
	"os"
	"path/filepath"
)

const (
	// DefaultQUICPort is the UDP port the receiver listens on.
	DefaultQUICPort = 47475
	// DefaultDiscoveryPort is the UDP port for signed beacons (phase P2).
	DefaultDiscoveryPort = 47474
)

// Home returns the directory that holds this device's key and certificates:
// $CIPHERDROP_HOME if set, otherwise $XDG_CONFIG_HOME/cipherdrop,
// otherwise ~/.config/cipherdrop.
func Home() (string, error) {
	if dir := os.Getenv("CIPHERDROP_HOME"); dir != "" {
		return dir, nil
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "cipherdrop"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", errors.New("cannot find a home directory; set CIPHERDROP_HOME")
	}
	return filepath.Join(home, ".config", "cipherdrop"), nil
}
