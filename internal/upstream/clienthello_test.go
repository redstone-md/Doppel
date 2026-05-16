package upstream

import "testing"

func TestResolveClientHelloKnown(t *testing.T) {
	for _, name := range ClientHelloNames() {
		if _, err := resolveClientHello(name); err != nil {
			t.Errorf("resolveClientHello(%q): %v", name, err)
		}
	}
}

func TestResolveClientHelloCaseInsensitive(t *testing.T) {
	if _, err := resolveClientHello("  Safari-IOS "); err != nil {
		t.Errorf("expected case/space-insensitive match: %v", err)
	}
}

func TestResolveClientHelloUnknown(t *testing.T) {
	if _, err := resolveClientHello("netscape-navigator"); err == nil {
		t.Error("expected error for unknown client_hello")
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in       string
		host     string
		port     string
	}{
		{"example.com", "example.com", "443"},
		{"example.com:8443", "example.com", "8443"},
		{"203.0.113.1:443", "203.0.113.1", "443"},
	}
	for _, c := range cases {
		host, port := splitHostPort(c.in)
		if host != c.host || port != c.port {
			t.Errorf("splitHostPort(%q) = %q,%q; want %q,%q", c.in, host, port, c.host, c.port)
		}
	}
}
