package proxy

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// handleHTTP serves an HTTP proxy client. Only the CONNECT method is
// supported: Doppel intercepts TLS, so it needs an encrypted tunnel to
// terminate. Plain-HTTP forward proxying is intentionally out of scope.
func (s *Server) handleHTTP(pc *peekConn) {
	req, err := http.ReadRequest(pc.r)
	if err != nil {
		s.logger().Debug("read HTTP proxy request", "error", err)
		_ = pc.Close()
		return
	}

	if req.Method != http.MethodConnect {
		s.logger().Debug("rejecting non-CONNECT request", "method", req.Method)
		writeHTTPStatus(pc, http.StatusNotImplemented)
		_ = pc.Close()
		return
	}

	if _, err := io.WriteString(pc, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		s.logger().Debug("write CONNECT response", "error", err)
		_ = pc.Close()
		return
	}

	// Negotiation is complete; the long-lived TLS session must not inherit
	// the handshake deadline.
	_ = pc.SetReadDeadline(time.Time{})

	// pc now carries the raw client TLS stream. Intercept takes ownership
	// of the connection and closes it when done.
	s.Interceptor.Intercept(pc, req.Host)
}

func writeHTTPStatus(w io.Writer, status int) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		status, http.StatusText(status))
}
