package proxy_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/Rxflex/doppel/internal/ca"
	"github.com/Rxflex/doppel/internal/mitm"
	"github.com/Rxflex/doppel/internal/profile"
	"github.com/Rxflex/doppel/internal/proxy"
	"github.com/Rxflex/doppel/internal/upstream"
)

// fixture starts a TLS backend and a Doppel proxy in front of it, returning
// the proxy address and a CA pool the client can trust.
type fixture struct {
	proxyAddr  string
	backendURL *url.URL
	caPool     *x509.CertPool
}

func newFixture(t *testing.T, body string) fixture {
	t.Helper()

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(backend.Close)

	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}

	authority, err := ca.Generate()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(authority.CertificatePEM()) {
		t.Fatal("add CA certificate to pool")
	}

	profiles, err := profile.Builtin()
	if err != nil {
		t.Fatalf("load builtin profiles: %v", err)
	}

	// The httptest backend uses a self-signed certificate, so upstream
	// verification is disabled for this test only.
	transport := &upstream.RoundTripper{
		Dialer:  &upstream.Dialer{SkipVerify: true},
		Profile: profiles["chrome-windows"],
	}
	t.Cleanup(func() { _ = transport.Close() })

	server := &proxy.Server{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Interceptor: &mitm.Interceptor{
			CA:        authority,
			Profile:   profiles["chrome-windows"],
			Transport: transport,
			Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.Serve(ctx, ln) }()

	return fixture{
		proxyAddr:  ln.Addr().String(),
		backendURL: backendURL,
		caPool:     pool,
	}
}

// request performs an HTTPS GET to the backend through tunnelConn and returns
// the response body.
func (f fixture) request(t *testing.T, tunnelConn net.Conn) string {
	t.Helper()
	_ = tunnelConn.SetDeadline(time.Now().Add(10 * time.Second))

	host, _, _ := net.SplitHostPort(f.backendURL.Host)
	tlsConn := tls.Client(tunnelConn, &tls.Config{RootCAs: f.caPool, ServerName: host})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client TLS handshake through proxy: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, f.backendURL.String()+"/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

func TestSOCKS5Interception(t *testing.T) {
	f := newFixture(t, "hello via socks5")

	conn, err := net.Dial("tcp", f.proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// SOCKS5 greeting, expecting the no-authentication method.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	selection := make([]byte, 2)
	if _, err := io.ReadFull(conn, selection); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if selection[0] != 0x05 || selection[1] != 0x00 {
		t.Fatalf("method selection = % x, want 05 00", selection)
	}

	// SOCKS5 CONNECT request for the backend host.
	host, portStr, _ := net.SplitHostPort(f.backendURL.Host)
	port, _ := strconv.Atoi(portStr)
	connectReq := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	connectReq = append(connectReq, host...)
	connectReq = append(connectReq, byte(port>>8), byte(port))
	if _, err := conn.Write(connectReq); err != nil {
		t.Fatalf("write connect request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("connect reply status = 0x%02x, want 0x00", reply[1])
	}

	if got := f.request(t, conn); got != "hello via socks5" {
		t.Errorf("body = %q, want %q", got, "hello via socks5")
	}
}

func TestHTTPConnectInterception(t *testing.T) {
	f := newFixture(t, "hello via connect")

	conn, err := net.Dial("tcp", f.proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n",
		f.backendURL.Host, f.backendURL.Host)

	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}
	if status != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatalf("CONNECT status = %q", status)
	}
	// Consume headers up to the blank line.
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	if got := f.request(t, conn); got != "hello via connect" {
		t.Errorf("body = %q, want %q", got, "hello via connect")
	}
}
