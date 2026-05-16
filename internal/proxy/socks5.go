package proxy

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SOCKS5 protocol constants (RFC 1928).
const (
	socks5Version   = 0x05
	socks5NoAuth    = 0x00
	socks5CmdConn   = 0x01
	socks5ATYPv4    = 0x01
	socks5ATYPHost  = 0x03
	socks5ATYPv6    = 0x04
	socks5ReplyOK   = 0x00
	socks5ReplyCmd  = 0x07 // command not supported
	socks5ReplyATYP = 0x08 // address type not supported
)

// handleSOCKS5 serves a SOCKS5 client. After the CONNECT command the target
// host is known, so the connection is handed to the interceptor exactly as in
// the HTTP CONNECT path.
func (s *Server) handleSOCKS5(pc *peekConn) {
	target, err := socks5Negotiate(pc.r, pc)
	if err != nil {
		s.logger().Debug("SOCKS5 negotiation failed", "error", err)
		_ = pc.Close()
		return
	}

	// pc now carries the raw client TLS stream. Intercept takes ownership
	// of the connection and closes it when done.
	s.Interceptor.Intercept(pc, target)
}

// socks5Negotiate performs the SOCKS5 greeting and CONNECT exchange, returning
// the requested "host:port".
func socks5Negotiate(r *bufio.Reader, w io.Writer) (string, error) {
	// Greeting: VER, NMETHODS, METHODS...
	ver, err := r.ReadByte()
	if err != nil {
		return "", fmt.Errorf("read version: %w", err)
	}
	if ver != socks5Version {
		return "", fmt.Errorf("unexpected version 0x%02x", ver)
	}
	nMethods, err := r.ReadByte()
	if err != nil {
		return "", fmt.Errorf("read method count: %w", err)
	}
	if _, err := r.Discard(int(nMethods)); err != nil {
		return "", fmt.Errorf("discard methods: %w", err)
	}

	// Select the no-authentication method.
	if _, err := w.Write([]byte{socks5Version, socks5NoAuth}); err != nil {
		return "", fmt.Errorf("write method selection: %w", err)
	}

	// Request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return "", fmt.Errorf("read request header: %w", err)
	}
	if head[0] != socks5Version {
		return "", fmt.Errorf("bad request version 0x%02x", head[0])
	}
	if head[1] != socks5CmdConn {
		_ = writeSOCKS5Reply(w, socks5ReplyCmd)
		return "", fmt.Errorf("unsupported command 0x%02x", head[1])
	}

	host, err := readSOCKS5Address(r, head[3])
	if err != nil {
		_ = writeSOCKS5Reply(w, socks5ReplyATYP)
		return "", err
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	if err := writeSOCKS5Reply(w, socks5ReplyOK); err != nil {
		return "", fmt.Errorf("write reply: %w", err)
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func readSOCKS5Address(r *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case socks5ATYPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", fmt.Errorf("read IPv4 address: %w", err)
		}
		return net.IP(buf).String(), nil
	case socks5ATYPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", fmt.Errorf("read IPv6 address: %w", err)
		}
		return net.IP(buf).String(), nil
	case socks5ATYPHost:
		length, err := r.ReadByte()
		if err != nil {
			return "", fmt.Errorf("read host length: %w", err)
		}
		buf := make([]byte, int(length))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", fmt.Errorf("read host: %w", err)
		}
		return string(buf), nil
	default:
		return "", fmt.Errorf("unsupported address type 0x%02x", atyp)
	}
}

// writeSOCKS5Reply writes a reply with the given status. The bound address is
// reported as 0.0.0.0:0, which clients ignore for CONNECT.
func writeSOCKS5Reply(w io.Writer, status byte) error {
	_, err := w.Write([]byte{
		socks5Version, status, 0x00, socks5ATYPv4,
		0, 0, 0, 0, // bound address 0.0.0.0
		0, 0, // bound port 0
	})
	return err
}
