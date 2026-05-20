// Package launch prepares child processes to route their HTTPS traffic through
// a running Doppel proxy.
package launch

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const defaultBypassList = "<local>"

// Options controls how a launched process is wired to Doppel.
type Options struct {
	ProxyAddr       string
	CACertPath      string
	IncludeEnv      bool
	IncludeChromium bool
	ProxyAllSchemes bool
	BypassList      string
}

// Command builds an exec.Cmd that inherits the current terminal and is
// configured to send HTTPS traffic through Doppel.
func Command(ctx context.Context, opts Options, argv []string) (*exec.Cmd, error) {
	if len(argv) == 0 {
		return nil, fmt.Errorf("no command provided")
	}
	if strings.TrimSpace(opts.ProxyAddr) == "" {
		return nil, fmt.Errorf("proxy address is required")
	}

	args := append([]string(nil), argv[1:]...)
	if opts.IncludeChromium {
		args = AppendChromiumArgs(args, opts)
	}

	cmd := exec.CommandContext(ctx, argv[0], args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if opts.IncludeEnv {
		cmd.Env = ProxyEnv(os.Environ(), opts)
	}
	return cmd, nil
}

// ProxyEnv returns an environment with HTTPS-oriented proxy and CA settings.
// Plain HTTP and generic proxy variables are removed to avoid accidental
// chaining through an unrelated proxy.
func ProxyEnv(base []string, opts Options) []string {
	proxyURL := "http://" + opts.ProxyAddr
	updates := map[string]string{
		"HTTPS_PROXY":         proxyURL,
		"https_proxy":         proxyURL,
		"NO_PROXY":            "localhost,127.0.0.1,::1",
		"no_proxy":            "localhost,127.0.0.1,::1",
		"REQUESTS_CA_BUNDLE":  opts.CACertPath,
		"NODE_EXTRA_CA_CERTS": opts.CACertPath,
		"SSL_CERT_FILE":       opts.CACertPath,
	}
	drop := map[string]struct{}{
		"HTTP_PROXY": {},
		"http_proxy": {},
		"ALL_PROXY":  {},
		"all_proxy":  {},
	}

	out := make([]string, 0, len(base)+len(updates))
	seen := make(map[string]struct{}, len(updates))
	for _, entry := range base {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			out = append(out, entry)
			continue
		}
		if _, remove := drop[name]; remove {
			continue
		}
		if value, exists := updates[name]; exists {
			out = append(out, name+"="+value)
			seen[name] = struct{}{}
			continue
		}
		out = append(out, entry)
	}
	for name, value := range updates {
		if _, exists := seen[name]; !exists {
			out = append(out, name+"="+value)
		}
	}
	return out
}

// AppendChromiumArgs appends Chromium/Electron proxy switches. By default only
// HTTPS URLs are proxied because Doppel expects a TLS stream after CONNECT.
func AppendChromiumArgs(args []string, opts Options) []string {
	proxyRule := "https=http://" + opts.ProxyAddr
	if opts.ProxyAllSchemes {
		proxyRule = "http://" + opts.ProxyAddr
	}

	bypass := opts.BypassList
	if strings.TrimSpace(bypass) == "" {
		bypass = defaultBypassList
	}

	out := append([]string(nil), args...)
	out = append(out, "--proxy-server="+proxyRule)
	out = append(out, "--proxy-bypass-list="+bypass)
	return out
}
