package upstream

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/http2"

	"github.com/redstone-md/Doppel/internal/profile"
)

const (
	// h2ReadIdleTimeout makes the HTTP/2 layer send a PING after this much
	// idle time and drop the connection if the peer does not answer. It
	// keeps dead upstream connections from leaking goroutines.
	h2ReadIdleTimeout = 30 * time.Second
	// h2PingTimeout bounds how long to wait for that PING ack.
	h2PingTimeout = 15 * time.Second
)

// RoundTripper performs HTTP requests over upstream connections whose TLS
// fingerprint matches a profile. HTTP/2 connections are pooled per host and
// reused across requests; HTTP/1.1 connections are used once and closed.
//
// RoundTripper is safe for concurrent use.
type RoundTripper struct {
	Dialer  *Dialer
	Profile *profile.Profile

	once sync.Once
	h2t  *http2.Transport

	mu   sync.Mutex
	pool map[string]*pooledH2
}

// pooledH2 is a reusable HTTP/2 connection and the raw connection beneath it.
type pooledH2 struct {
	cc  *http2.ClientConn
	raw *Conn
}

var _ http.RoundTripper = (*RoundTripper)(nil)

func (rt *RoundTripper) init() {
	rt.once.Do(func() {
		rt.h2t = &http2.Transport{
			ReadIdleTimeout: h2ReadIdleTimeout,
			PingTimeout:     h2PingTimeout,
		}
		rt.pool = make(map[string]*pooledH2)
	})
}

// RoundTrip implements http.RoundTripper. The response body is transparently
// decompressed so the client always receives a decodable stream.
func (rt *RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := rt.roundTrip(req)
	if err != nil {
		return nil, err
	}
	if err := decodeResponse(resp); err != nil {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("decode response body: %w", err)
	}
	return resp, nil
}

func (rt *RoundTripper) roundTrip(req *http.Request) (*http.Response, error) {
	rt.init()
	host := req.URL.Host

	// Fast path: reuse a pooled HTTP/2 connection. A body-less request may
	// be retried on a fresh connection if the pooled one has gone stale.
	if cc := rt.cachedH2(host); cc != nil {
		resp, err := cc.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		rt.evict(host)
		if req.Body != nil {
			return nil, fmt.Errorf("http/2 round trip: %w", err)
		}
	}

	conn, err := rt.Dialer.Dial(req.Context(), rt.Profile, host)
	if err != nil {
		return nil, err
	}

	if conn.ALPN != "h2" {
		return roundTripHTTP1(conn, req, rt.Profile)
	}

	cc, err := rt.adoptH2(host, conn)
	if err != nil {
		return nil, err
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		rt.evict(host)
		return nil, fmt.Errorf("http/2 round trip: %w", err)
	}
	return resp, nil
}

// Close closes every pooled connection. The RoundTripper must not be reused
// afterwards.
func (rt *RoundTripper) Close() error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for host, pc := range rt.pool {
		_ = pc.raw.Close()
		delete(rt.pool, host)
	}
	return nil
}

// cachedH2 returns a usable pooled connection for host, evicting it if it can
// no longer accept requests.
func (rt *RoundTripper) cachedH2(host string) *http2.ClientConn {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	pc, ok := rt.pool[host]
	if !ok {
		return nil
	}
	if !pc.cc.CanTakeNewRequest() {
		delete(rt.pool, host)
		_ = pc.raw.Close()
		return nil
	}
	return pc.cc
}

// adoptH2 wraps conn in an HTTP/2 client connection and stores it in the pool.
func (rt *RoundTripper) adoptH2(host string, conn *Conn) (*http2.ClientConn, error) {
	cc, err := rt.h2t.NewClientConn(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("establish http/2 connection: %w", err)
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if existing, ok := rt.pool[host]; ok && existing.cc.CanTakeNewRequest() {
		// Another goroutine pooled a connection first; keep theirs.
		_ = conn.Close()
		return existing.cc, nil
	}
	if old, ok := rt.pool[host]; ok {
		_ = old.raw.Close()
	}
	rt.pool[host] = &pooledH2{cc: cc, raw: conn}
	return cc, nil
}

// evict removes and closes the pooled connection for host.
func (rt *RoundTripper) evict(host string) {
	rt.mu.Lock()
	pc, ok := rt.pool[host]
	if ok {
		delete(rt.pool, host)
	}
	rt.mu.Unlock()
	if ok {
		_ = pc.raw.Close()
	}
}

// roundTripHTTP1 performs a single request over an HTTP/1.1 connection, which
// is closed once the response body is closed.
func roundTripHTTP1(conn *Conn, req *http.Request, p *profile.Profile) (*http.Response, error) {
	if err := writeRequestHTTP1(conn, req, p); err != nil {
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

// connClosingBody closes the underlying HTTP/1.1 connection once the response
// body is closed, since each HTTP/1.1 request uses its own connection.
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
