package upstream

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ProxyConfig describes an upstream proxy used between Doppel and the target
// server.
type ProxyConfig struct {
	Scheme  string
	Address string
	Auth    *ProxyAuth
}

// ProxyAuth holds upstream proxy credentials.
type ProxyAuth struct {
	Username string
	Password string
}

// ParseProxy parses an upstream proxy URL. The canonical form is
// socks5://user:pass@host:port. For compatibility with common proxy-provider
// dashboards, socks5://host:port:user:pass is also accepted.
func ParseProxy(raw string) (*ProxyConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	scheme, _, ok := strings.Cut(raw, "://")
	if !ok {
		return nil, fmt.Errorf("upstream proxy must include a scheme")
	}
	if scheme != "socks5" && scheme != "socks5h" {
		return nil, fmt.Errorf("unsupported upstream proxy scheme %q", scheme)
	}

	u, err := url.Parse(raw)
	if err == nil {
		if host, port, err := net.SplitHostPort(u.Host); err == nil {
			return &ProxyConfig{
				Scheme:  "socks5",
				Address: net.JoinHostPort(host, port),
				Auth:    proxyAuthFromURL(u),
			}, nil
		}
	}

	return parseProviderProxyURL(raw, scheme)
}

func proxyAuthFromURL(u *url.URL) *ProxyAuth {
	if u.User == nil {
		return nil
	}
	password, _ := u.User.Password()
	return &ProxyAuth{Username: u.User.Username(), Password: password}
}

func parseProviderProxyURL(raw, scheme string) (*ProxyConfig, error) {
	body := strings.TrimPrefix(raw, scheme+"://")
	parts := strings.SplitN(body, ":", 4)
	if len(parts) != 4 {
		return nil, fmt.Errorf("upstream proxy must be socks5://user:pass@host:port")
	}
	if parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("upstream proxy host and port are required")
	}
	if _, err := strconv.ParseUint(parts[1], 10, 16); err != nil {
		return nil, fmt.Errorf("upstream proxy port: %w", err)
	}
	return &ProxyConfig{
		Scheme:  "socks5",
		Address: net.JoinHostPort(parts[0], parts[1]),
		Auth:    &ProxyAuth{Username: parts[2], Password: parts[3]},
	}, nil
}

func (p *ProxyConfig) Dial(ctx context.Context, network, target string, timeout time.Duration) (net.Conn, error) {
	if p == nil {
		return nil, fmt.Errorf("upstream proxy is nil")
	}
	if network != "tcp" {
		return nil, fmt.Errorf("unsupported upstream proxy network %q", network)
	}
	if p.Scheme != "socks5" {
		return nil, fmt.Errorf("unsupported upstream proxy scheme %q", p.Scheme)
	}
	return p.dialSOCKS5(ctx, target, timeout)
}

func (p *ProxyConfig) dialSOCKS5(ctx context.Context, target string, timeout time.Duration) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", p.Address)
	if err != nil {
		return nil, fmt.Errorf("dial upstream proxy: %w", err)
	}

	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set proxy deadline: %w", err)
	}

	if err := p.socks5Handshake(conn, target); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (p *ProxyConfig) socks5Handshake(conn net.Conn, target string) error {
	methods := []byte{0x00}
	if p.Auth != nil {
		methods = append(methods, 0x02)
	}
	greeting := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(greeting); err != nil {
		return fmt.Errorf("write socks5 greeting: %w", err)
	}

	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("read socks5 greeting: %w", err)
	}
	if response[0] != 0x05 {
		return fmt.Errorf("bad socks5 version 0x%02x", response[0])
	}
	if response[1] == 0xff {
		return fmt.Errorf("upstream proxy rejected authentication methods")
	}
	if response[1] == 0x02 {
		if err := p.socks5UsernamePassword(conn); err != nil {
			return err
		}
	} else if response[1] != 0x00 {
		return fmt.Errorf("unsupported socks5 authentication method 0x%02x", response[1])
	}

	request, err := socks5ConnectRequest(target)
	if err != nil {
		return err
	}
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("write socks5 connect request: %w", err)
	}
	return readSOCKS5ConnectReply(conn)
}

func (p *ProxyConfig) socks5UsernamePassword(conn net.Conn) error {
	if p.Auth == nil {
		return fmt.Errorf("upstream proxy requires credentials")
	}
	username := []byte(p.Auth.Username)
	password := []byte(p.Auth.Password)
	if len(username) > 255 || len(password) > 255 {
		return fmt.Errorf("upstream proxy credentials are too long")
	}

	request := []byte{0x01, byte(len(username))}
	request = append(request, username...)
	request = append(request, byte(len(password)))
	request = append(request, password...)
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("write socks5 auth: %w", err)
	}

	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("read socks5 auth: %w", err)
	}
	if response[1] != 0x00 {
		return fmt.Errorf("upstream proxy authentication failed")
	}
	return nil
}

func socks5ConnectRequest(target string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("split target host: %w", err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("parse target port: %w", err)
	}

	request := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			request = append(request, 0x01)
			request = append(request, v4...)
		} else {
			request = append(request, 0x04)
			request = append(request, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("target hostname is too long")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, host...)
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(port))
	request = append(request, portBuf...)
	return request, nil
}

func readSOCKS5ConnectReply(conn net.Conn) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read socks5 connect reply: %w", err)
	}
	if header[0] != 0x05 {
		return fmt.Errorf("bad socks5 reply version 0x%02x", header[0])
	}
	if err := discardSOCKS5BoundAddress(conn, header[3]); err != nil {
		return err
	}
	if header[1] != 0x00 {
		return fmt.Errorf("upstream proxy connect failed: %s", socks5ReplyText(header[1]))
	}
	return nil
}

func discardSOCKS5BoundAddress(conn net.Conn, atyp byte) error {
	var n int
	switch atyp {
	case 0x01:
		n = net.IPv4len
	case 0x04:
		n = net.IPv6len
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return fmt.Errorf("read socks5 bound host length: %w", err)
		}
		n = int(length[0])
	default:
		return fmt.Errorf("unsupported socks5 reply address type 0x%02x", atyp)
	}
	buf := make([]byte, n+2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read socks5 bound address: %w", err)
	}
	return nil
}

func socks5ReplyText(code byte) string {
	switch code {
	case 0x01:
		return "general failure"
	case 0x02:
		return "connection not allowed"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("status 0x%02x", code)
	}
}
