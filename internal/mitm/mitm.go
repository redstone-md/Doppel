// Package mitm terminates TLS from a client, then re-originates the request
// upstream through a fingerprint-emulating connection.
//
// The client-facing leg uses a certificate minted by the local CA, so the
// client must trust that CA. That leg always runs over HTTP/1.1: its
// fingerprint is irrelevant because it never leaves the machine. Only the
// upstream leg, produced by the upstream package, is observed by the server.
package mitm

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/redstone-md/Doppel/internal/ca"
	"github.com/redstone-md/Doppel/internal/profile"
	"github.com/redstone-md/Doppel/internal/upstream"
)

// hopByHopHeaders are connection-scoped headers that must not be forwarded
// from the client request to the upstream server.
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
	"Proxy-Authenticate",
	"Proxy-Authorization",
}

// Interceptor terminates client TLS and forwards requests upstream with the
// TLS fingerprint and headers of the configured profile.
type Interceptor struct {
	CA        *ca.Authority
	Profile   *profile.Profile
	Transport *upstream.RoundTripper
	Logger    *slog.Logger

	// RewriteHeaders controls whether the client's original HTTP headers are
	// overwritten with the profile's values (User-Agent, Accept, Sec-Fetch-*,
	// etc.). When false, only hop-by-hop headers are stripped and the rest
	// pass through unchanged. The TLS fingerprint is always applied regardless
	// of this setting.
	RewriteHeaders bool

	// PassthroughList lists host patterns that should be tunneled directly
	// without MITM interception. The pattern syntax matches Dialer.BypassList:
	//   "<local>"          matches localhost / loopback
	//   "host.com"         exact match only
	//   ".host.com"        matches host.com and any subdomain
	//   ".tiktokv.com"     matches tnc16.tiktokv.com, gecko-sg.tiktokv.com, etc.
	PassthroughList []string
}

// Intercept terminates TLS on clientConn (which the client opened believing
// it was reaching host), then serves requests until the client disconnects.
// It takes ownership of clientConn and closes it on return.
func (ic *Interceptor) Intercept(clientConn net.Conn, host string) {
	defer clientConn.Close()

	tlsConn := tls.Server(clientConn, ic.CA.ServerTLSConfig(host, []string{"http/1.1"}))
	if err := tlsConn.Handshake(); err != nil {
		ic.logger().Debug("client TLS handshake failed", "host", host, "error", err)
		return
	}
	defer tlsConn.Close()

	reader := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				ic.logger().Debug("read client request", "host", host, "error", err)
			}
			return
		}
		if err := ic.forward(tlsConn, req, host); err != nil {
			if isConnectionTakenOver(err) {
				return
			}
			if isClientAbort(err) {
				ic.logger().Debug("client closed response stream", "host", host, "error", err)
				return
			}
			ic.logger().Warn("request failed", "host", host, "error", err)
			return
		}
	}
}

// forward re-issues req upstream and writes the response back to the client.
func (ic *Interceptor) forward(client net.Conn, req *http.Request, host string) error {
	if isWebSocketUpgrade(req) {
		return ic.forwardWebSocket(client, req, host)
	}

	authority := req.Host
	if authority == "" {
		authority = host
	}
	targetURL := fmt.Sprintf("https://%s%s", authority, req.URL.RequestURI())

	outReq, err := http.NewRequest(req.Method, targetURL, req.Body)
	if err != nil {
		writeStatus(client, http.StatusBadRequest)
		return fmt.Errorf("build upstream request: %w", err)
	}
	outReq.Header = req.Header.Clone()
	outReq.ContentLength = req.ContentLength
	for _, name := range hopByHopHeaders {
		outReq.Header.Del(name)
	}

	// Rewrite identity-revealing headers so they match the profile.
	// Skipped when RewriteHeaders is false to preserve the client's own headers.
	if ic.RewriteHeaders {
		ic.Profile.Apply(outReq)
	}

	resp, err := ic.Transport.RoundTrip(outReq)
	if err != nil {
		writeStatus(client, http.StatusBadGateway)
		return fmt.Errorf("upstream round trip: %w", err)
	}
	defer resp.Body.Close()

	ic.logger().Info("proxied",
		"profile", ic.Profile.Name,
		"method", req.Method,
		"url", targetURL,
		"status", resp.StatusCode,
	)

	if err := resp.Write(client); err != nil {
		return fmt.Errorf("write response to client: %w", err)
	}
	return nil
}

func (ic *Interceptor) forwardWebSocket(client net.Conn, req *http.Request, host string) error {
	authority := req.Host
	if authority == "" {
		authority = host
	}
	targetURL := fmt.Sprintf("https://%s%s", authority, req.URL.RequestURI())

	outReq, err := http.NewRequest(req.Method, targetURL, req.Body)
	if err != nil {
		writeStatus(client, http.StatusBadRequest)
		return fmt.Errorf("build upstream websocket request: %w", err)
	}
	outReq.Header = req.Header.Clone()
	outReq.ContentLength = req.ContentLength
	outReq.Host = authority
	for _, name := range []string{"Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization"} {
		outReq.Header.Del(name)
	}
	if ic.RewriteHeaders && ic.Profile.UserAgent != "" {
		outReq.Header.Set("User-Agent", ic.Profile.UserAgent)
	}

	conn, err := ic.Transport.Dialer.DialWithALPN(req.Context(), ic.Profile, authority, []string{"http/1.1"})
	if err != nil {
		writeStatus(client, http.StatusBadGateway)
		return fmt.Errorf("websocket upstream dial: %w", err)
	}
	if conn.ALPN == "h2" {
		_ = conn.Close()
		writeStatus(client, http.StatusBadGateway)
		return fmt.Errorf("websocket upstream negotiated h2 despite http/1.1-only ALPN")
	}
	if err := upstream.WriteRequestHTTP1(conn, outReq, ic.Profile); err != nil {
		_ = conn.Close()
		return fmt.Errorf("write websocket upgrade upstream: %w", err)
	}

	upstreamReader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(upstreamReader, outReq)
	if err != nil {
		_ = conn.Close()
		writeStatus(client, http.StatusBadGateway)
		return fmt.Errorf("read websocket upgrade response: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer conn.Close()
		if err := resp.Write(client); err != nil {
			return fmt.Errorf("write websocket rejection to client: %w", err)
		}
		return nil
	}
	if err := resp.Write(client); err != nil {
		_ = conn.Close()
		return fmt.Errorf("write websocket upgrade response to client: %w", err)
	}

	ic.logger().Info("websocket proxied", "profile", ic.Profile.Name, "url", targetURL)
	tunnel(client, conn, upstreamReader)
	return errConnectionTakenOver
}

// matchesPassthrough reports whether host matches one of the passthrough
// patterns. See PassthroughList for the pattern syntax.
func (ic *Interceptor) MatchesPassthrough(host string) bool {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
	}
	for _, pattern := range ic.PassthroughList {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}
		if pattern == "<local>" {
			if hostname == "127.0.0.1" || hostname == "::1" || hostname == "localhost" {
				return true
			}
			continue
		}
		if strings.HasPrefix(pattern, ".") {
			// .domain.com matches domain.com and any subdomain
			suffix := strings.ToLower(pattern)
			h := strings.ToLower(hostname)
			if h == suffix[1:] || strings.HasSuffix(h, suffix) {
				return true
			}
		} else {
			if strings.EqualFold(hostname, pattern) {
				return true
			}
		}
	}
	return false
}

// Passthrough creates a raw TCP tunnel between clientConn and the target host,
// bypassing MITM entirely. The client's native TLS stream reaches the upstream
// server unmodified. clientConn is closed on return.
func (ic *Interceptor) Passthrough(clientConn net.Conn, host string) {
	defer clientConn.Close()

	hostname, port := splitHost(host)
	target := net.JoinHostPort(hostname, port)

	timeout := 30 * time.Second
	upstreamConn, err := ic.Transport.Dialer.DialTCP(context.Background(), target, timeout)
	if err != nil {
		ic.logger().Warn("passthrough dial failed", "host", host, "error", err)
		return
	}
	defer upstreamConn.Close()

	ic.logger().Info("passthrough tunnel open", "profile", ic.Profile.Name, "host", host)

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstreamConn, clientConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, upstreamConn)
		done <- struct{}{}
	}()
	<-done

	ic.logger().Info("passthrough tunnel closed", "host", host)
}

// splitHost splits "host:port" into hostname and port (defaults to "443").
func splitHost(host string) (hostname, port string) {
	if h, p, err := net.SplitHostPort(host); err == nil {
		return h, p
	}
	return host, "443"
}

func isWebSocketUpgrade(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Upgrade"), "websocket") && headerTokenContains(req.Header.Get("Connection"), "upgrade")
}

func headerTokenContains(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func tunnel(client net.Conn, upstreamConn net.Conn, upstreamReader *bufio.Reader) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstreamConn, client)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, upstreamReader)
		done <- struct{}{}
	}()
	<-done
	_ = upstreamConn.Close()
	_ = client.Close()
}

func (ic *Interceptor) logger() *slog.Logger {
	if ic.Logger != nil {
		return ic.Logger
	}
	return slog.Default()
}

// writeStatus writes a minimal HTTP/1.1 response carrying only a status code,
// used to report proxy-side failures to the client.
func writeStatus(w io.Writer, status int) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		status, http.StatusText(status))
}
