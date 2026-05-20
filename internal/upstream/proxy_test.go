package upstream

import (
	"net"
	"testing"
)

func TestParseProxyStandardURL(t *testing.T) {
	cfg, err := ParseProxy("socks5://user:pass@example.com:1080")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Scheme != "socks5" || cfg.Address != "example.com:1080" {
		t.Fatalf("unexpected proxy config: %#v", cfg)
	}
	if cfg.Auth == nil || cfg.Auth.Username != "user" || cfg.Auth.Password != "pass" {
		t.Fatalf("unexpected auth: %#v", cfg.Auth)
	}
}

func TestParseProxyProviderURL(t *testing.T) {
	cfg, err := ParseProxy("socks5://proxy.example:2002:user:p:a:ss")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != "proxy.example:2002" {
		t.Fatalf("unexpected address: %s", cfg.Address)
	}
	if cfg.Auth == nil || cfg.Auth.Username != "user" || cfg.Auth.Password != "p:a:ss" {
		t.Fatalf("unexpected auth: %#v", cfg.Auth)
	}
}

func TestParseProxyRejectsUnsupportedScheme(t *testing.T) {
	if _, err := ParseProxy("http://proxy.example:8080"); err == nil {
		t.Fatal("expected unsupported scheme error")
	}
}

func TestSOCKS5ConnectRequestUsesDomainNames(t *testing.T) {
	req, err := socks5ConnectRequest(net.JoinHostPort("example.com", "443"))
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := []byte{0x05, 0x01, 0x00, 0x03, byte(len("example.com"))}
	if string(req[:len(wantPrefix)]) != string(wantPrefix) {
		t.Fatalf("bad request prefix: %#v", req[:len(wantPrefix)])
	}
}
