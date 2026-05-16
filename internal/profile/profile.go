// Package profile describes a network identity: the TLS ClientHello, ALPN,
// HTTP headers and HTTP/2 traits that together make traffic indistinguishable
// from a specific real device and browser.
//
// A profile is pure data. Mapping a profile to a concrete TLS ClientHello is
// the responsibility of the upstream package, which keeps this package free
// of any TLS dependency.
package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Profile is a complete network-identity fingerprint.
type Profile struct {
	// Name uniquely identifies the profile.
	Name string `json:"name"`
	// Description is a human-readable summary of the emulated device.
	Description string `json:"description"`
	// ClientHello names the TLS ClientHello template to emulate. The
	// upstream package resolves this to a concrete handshake.
	ClientHello string `json:"client_hello"`
	// UserAgent is the User-Agent header value for the emulated browser.
	UserAgent string `json:"user_agent"`
	// ALPN lists the application protocols to advertise, most preferred
	// first (for example "h2" then "http/1.1").
	ALPN []string `json:"alpn"`
	// Headers controls how request headers are rewritten.
	Headers HeaderProfile `json:"headers"`
	// HTTP2 describes HTTP/2 traits. It is applied best-effort; see the
	// project roadmap for exact HTTP/2 frame fingerprinting.
	HTTP2 *HTTP2Profile `json:"http2,omitempty"`
}

// HeaderProfile controls request-header rewriting.
type HeaderProfile struct {
	// Order lists header names (lower-case) in the order the emulated
	// browser sends them. Headers absent from this list are appended
	// afterwards in alphabetical order.
	Order []string `json:"order"`
	// Set holds headers to inject or override so the request matches the
	// emulated browser exactly.
	Set map[string]string `json:"set"`
}

// HTTP2Profile describes HTTP/2 connection traits.
type HTTP2Profile struct {
	// Settings holds HTTP/2 SETTINGS values keyed by setting name.
	Settings map[string]uint32 `json:"settings,omitempty"`
	// PseudoHeaderOrder lists the order of HTTP/2 pseudo-headers, which is
	// distinctive per browser engine.
	PseudoHeaderOrder []string `json:"pseudo_header_order,omitempty"`
}

// Validate reports whether the profile is internally consistent.
func (p *Profile) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("profile: name is required")
	}
	if strings.TrimSpace(p.ClientHello) == "" {
		return fmt.Errorf("profile %q: client_hello is required", p.Name)
	}
	if strings.TrimSpace(p.UserAgent) == "" {
		return fmt.Errorf("profile %q: user_agent is required", p.Name)
	}
	if len(p.ALPN) == 0 {
		return fmt.Errorf("profile %q: at least one ALPN protocol is required", p.Name)
	}
	return nil
}

// Apply rewrites req so its headers match the profile. The User-Agent and any
// configured headers are set, overriding whatever value the client supplied.
func (p *Profile) Apply(req *http.Request) {
	if p.UserAgent != "" {
		req.Header.Set("User-Agent", p.UserAgent)
	}
	for name, value := range p.Headers.Set {
		req.Header.Set(name, value)
	}
}

// OrderHeaders returns the header keys of h ordered to match the profile.
// Keys named in Headers.Order come first in that order; any remaining keys
// follow in stable alphabetical order. Comparison is case-insensitive.
func (p *Profile) OrderHeaders(h http.Header) []string {
	rank := make(map[string]int, len(p.Headers.Order))
	for i, name := range p.Headers.Order {
		rank[strings.ToLower(name)] = i
	}

	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}

	sort.SliceStable(keys, func(i, j int) bool {
		ri, oki := rank[strings.ToLower(keys[i])]
		rj, okj := rank[strings.ToLower(keys[j])]
		switch {
		case oki && okj:
			return ri < rj
		case oki:
			return true
		case okj:
			return false
		default:
			return keys[i] < keys[j]
		}
	})
	return keys
}

// Load reads and validates a profile from a JSON file.
func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read profile: %w", err)
	}
	return parse(data)
}

// LoadDir loads every *.json profile in dir, keyed by profile name.
func LoadDir(dir string) (map[string]*Profile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read profile directory: %w", err)
	}

	out := make(map[string]*Profile)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p, err := Load(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if _, dup := out[p.Name]; dup {
			return nil, fmt.Errorf("duplicate profile name %q", p.Name)
		}
		out[p.Name] = p
	}
	return out, nil
}

func parse(data []byte) (*Profile, error) {
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("decode profile: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}
