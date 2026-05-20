// Package config resolves Doppel's runtime paths and default settings.
package config

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	// DefaultAddr is the default proxy listen address. Binding to
	// localhost keeps the proxy off the network unless deliberately
	// reconfigured.
	DefaultAddr = "127.0.0.1:8080"

	// DefaultProfile is the identity profile used when none is selected.
	DefaultProfile = "safari-ios-iphone15"
)

// Config holds resolved runtime settings.
type Config struct {
	// DataDir holds machine-local state: the CA key pair and user
	// profiles.
	DataDir string
	// Addr is the proxy listen address.
	Addr string
	// Profile is the name of the identity profile to emulate.
	Profile string
}

// Default returns the configuration used when no flags are supplied.
func Default() (Config, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return Config{}, fmt.Errorf("locate user config directory: %w", err)
	}
	return Config{
		DataDir: filepath.Join(base, "doppel"),
		Addr:    DefaultAddr,
		Profile: DefaultProfile,
	}, nil
}

// CACertPath returns the path of the CA certificate.
func (c Config) CACertPath() string { return filepath.Join(c.DataDir, "ca.pem") }

// CAKeyPath returns the path of the CA private key.
func (c Config) CAKeyPath() string { return filepath.Join(c.DataDir, "ca.key") }

// ProfilesDir returns the directory scanned for user-supplied profiles.
func (c Config) ProfilesDir() string { return filepath.Join(c.DataDir, "profiles") }

// CAExists reports whether a CA has already been generated for this machine.
func (c Config) CAExists() bool {
	for _, path := range []string{c.CACertPath(), c.CAKeyPath()} {
		if _, err := os.Stat(path); err != nil {
			return false
		}
	}
	return true
}
