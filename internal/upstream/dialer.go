package upstream

import (
	"context"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/redstone-md/Doppel/internal/profile"
)

const defaultTimeout = 30 * time.Second

// Conn is an established upstream TLS connection together with the application
// protocol negotiated through ALPN ("h2" or "http/1.1").
type Conn struct {
	net.Conn
	ALPN string
}

// Dialer establishes TLS connections whose ClientHello emulates the device
// described by a profile.
type Dialer struct {
	// Timeout bounds both the TCP connection and the TLS handshake.
	// A zero value uses defaultTimeout.
	Timeout time.Duration
	// SkipVerify disables verification of the upstream server certificate.
	// It must remain false outside of debugging: skipping verification
	// would let an attacker between Doppel and the server go unnoticed.
	SkipVerify bool
	// UpstreamProxy routes Doppel's outbound TCP connection through a proxy.
	// Nil means direct egress.
	UpstreamProxy *ProxyConfig
}

// Dial connects to host (host:port, defaulting to port 443) and performs a
// TLS handshake using the profile's ClientHello template.
func (d *Dialer) Dial(ctx context.Context, p *profile.Profile, host string) (*Conn, error) {
	return d.DialWithALPN(ctx, p, host, p.ALPN)
}

// DialWithALPN is Dial with an explicit ALPN list. It is used for protocol
// paths such as WebSocket upgrade where HTTP/1.1 must be negotiated upstream.
func (d *Dialer) DialWithALPN(ctx context.Context, p *profile.Profile, host string, alpn []string) (*Conn, error) {
	helloID, err := resolveClientHello(p.ClientHello)
	if err != nil {
		return nil, err
	}

	hostname, port := splitHostPort(host)

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	target := net.JoinHostPort(hostname, port)
	raw, err := d.dialTCP(ctx, target, timeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", host, err)
	}

	cfg := &utls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: d.SkipVerify,
		NextProtos:         alpn,
	}
	uconn := utls.UClient(raw, cfg, helloID)

	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := uconn.SetDeadline(deadline); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("set handshake deadline: %w", err)
	}

	if err := uconn.Handshake(); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("tls handshake with %s: %w", hostname, err)
	}
	if err := uconn.SetDeadline(time.Time{}); err != nil {
		_ = uconn.Close()
		return nil, fmt.Errorf("clear handshake deadline: %w", err)
	}

	return &Conn{Conn: uconn, ALPN: uconn.ConnectionState().NegotiatedProtocol}, nil
}

func (d *Dialer) dialTCP(ctx context.Context, target string, timeout time.Duration) (net.Conn, error) {
	if d.UpstreamProxy != nil {
		return d.UpstreamProxy.Dial(ctx, "tcp", target, timeout)
	}
	tcpDialer := &net.Dialer{Timeout: timeout}
	return tcpDialer.DialContext(ctx, "tcp", target)
}

func splitHostPort(host string) (hostname, port string) {
	if h, p, err := net.SplitHostPort(host); err == nil {
		return h, p
	}
	return host, "443"
}
