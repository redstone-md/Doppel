// Package proxy accepts client connections and hands the encrypted stream to
// the MITM interceptor.
//
// A single listener serves both SOCKS5 and HTTP CONNECT clients: the protocol
// is detected from the first byte of the connection (0x05 marks SOCKS5,
// anything else is treated as HTTP). This lets any client point at one port.
package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/Rxflex/doppel/internal/mitm"
)

// handshakeTimeout bounds how long a client has to complete proxy negotiation
// (the SOCKS5 handshake or HTTP CONNECT request). It stops a client that
// connects and then goes silent from pinning a goroutine indefinitely.
const handshakeTimeout = 30 * time.Second

// Server listens for proxy clients and routes each connection to the
// interceptor.
type Server struct {
	// Addr is the listen address, for example "127.0.0.1:8080".
	Addr string
	// Interceptor handles TLS termination and upstream re-origination.
	Interceptor *mitm.Interceptor
	// Logger receives structured logs; slog.Default() is used when nil.
	Logger *slog.Logger
}

// peekConn lets a connection be inspected without consuming bytes: all reads
// go through a bufio.Reader, so a byte peeked for protocol detection is still
// delivered to the eventual consumer (the TLS server).
type peekConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// ListenAndServe binds to s.Addr and serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.Addr, err)
	}
	return s.Serve(ctx, ln)
}

// Serve accepts connections on ln until ctx is cancelled, then waits for
// in-flight connections to finish. ln is closed on return.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.logger().Info("doppel listening",
		"addr", ln.Addr().String(),
		"profile", s.Interceptor.Profile.Name,
	)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			s.logger().Warn("accept failed", "error", err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(conn)
		}()
	}
}

// handle detects the proxy protocol and dispatches the connection. The
// negotiation phase runs under a deadline; handlers clear it before handing
// the connection to the interceptor for the long-lived TLS session.
func (s *Server) handle(conn net.Conn) {
	pc := &peekConn{Conn: conn, r: bufio.NewReader(conn)}

	if err := conn.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		_ = conn.Close()
		return
	}

	first, err := pc.r.Peek(1)
	if err != nil {
		if !errors.Is(err, net.ErrClosed) {
			s.logger().Debug("peek failed", "error", err)
		}
		_ = conn.Close()
		return
	}

	switch first[0] {
	case 0x05:
		s.handleSOCKS5(pc)
	case 0x04:
		s.logger().Debug("rejecting SOCKS4 client; SOCKS4 is not supported")
		_ = conn.Close()
	default:
		s.handleHTTP(pc)
	}
}

func (s *Server) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}
