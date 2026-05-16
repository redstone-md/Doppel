package upstream

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"golang.org/x/net/http2"

	"github.com/Rxflex/doppel/internal/profile"
)

// RoundTripper performs HTTP requests over upstream connections whose TLS
// fingerprint matches a profile. The protocol (HTTP/1.1 or HTTP/2) is chosen
// from the ALPN result of the handshake.
//
// A fresh connection is used per request. Connection pooling and HTTP/2
// stream multiplexing are tracked on the project roadmap.
type RoundTripper struct {
	Dialer  *Dialer
	Profile *profile.Profile
}

var _ http.RoundTripper = (*RoundTripper)(nil)

// RoundTrip implements http.RoundTripper.
func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	conn, err := rt.Dialer.Dial(req.Context(), rt.Profile, req.URL.Host)
	if err != nil {
		return nil, err
	}

	switch conn.ALPN {
	case "h2":
		return rt.roundTripHTTP2(conn, req)
	default:
		return rt.roundTripHTTP1(conn, req)
	}
}

func (rt *RoundTripper) roundTripHTTP2(conn *Conn, req *http.Request) (*http.Response, error) {
	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("establish http/2 connection: %w", err)
	}

	resp, err := cc.RoundTrip(req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("http/2 round trip: %w", err)
	}
	resp.Body = &connClosingBody{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

func (rt *RoundTripper) roundTripHTTP1(conn *Conn, req *http.Request) (*http.Response, error) {
	if err := writeRequestHTTP1(conn, req, rt.Profile); err != nil {
		_ = conn.Close()
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read http/1.1 response: %w", err)
	}
	resp.Body = &connClosingBody{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

// writeRequestHTTP1 serialises req over an HTTP/1.1 connection with header
// names emitted in the order dictated by the profile. Writing the request by
// hand (rather than via http.Request.Write) is what gives Doppel control over
// HTTP/1.1 header order.
func writeRequestHTTP1(w io.Writer, req *http.Request, p *profile.Profile) error {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}

	headers := make(http.Header, len(req.Header)+2)
	for name, values := range req.Header {
		headers[name] = values
	}
	headers.Set("Host", host)

	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return fmt.Errorf("read request body: %w", err)
		}
	}
	if req.Body != nil || req.Method == http.MethodPost || req.Method == http.MethodPut {
		headers.Set("Content-Length", strconv.Itoa(len(body)))
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\n", req.Method, req.URL.RequestURI())
	for _, name := range p.OrderHeaders(headers) {
		for _, value := range headers[name] {
			fmt.Fprintf(&buf, "%s: %s\r\n", name, value)
		}
	}
	buf.WriteString("\r\n")

	if _, err := w.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("write request head: %w", err)
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return fmt.Errorf("write request body: %w", err)
		}
	}
	return nil
}

// connClosingBody closes the underlying upstream connection once the response
// body is closed, since each request uses its own connection.
type connClosingBody struct {
	io.ReadCloser
	conn io.Closer
}

func (b *connClosingBody) Close() error {
	bodyErr := b.ReadCloser.Close()
	connErr := b.conn.Close()
	if bodyErr != nil {
		return bodyErr
	}
	return connErr
}
