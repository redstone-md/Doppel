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
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"

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
	ic.Profile.Apply(outReq)

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
