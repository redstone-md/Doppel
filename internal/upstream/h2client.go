package upstream

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"sync"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/redstone-md/Doppel/internal/profile"
)

type h2ClientConn struct {
	conn *Conn
	p    *profile.Profile
	fr   *http2.Framer
	enc  *hpack.Encoder

	mu      sync.Mutex
	nextID  uint32
	streams map[uint32]*h2Stream
	closed  bool
}

type h2Stream struct {
	req      *http.Request
	headers  chan *http.Response
	errs     chan error
	bodyR    *io.PipeReader
	bodyW    *io.PipeWriter
	trailers http.Header
}

func newH2ClientConn(conn *Conn, p *profile.Profile) (*h2ClientConn, error) {
	cc := &h2ClientConn{conn: conn, p: p, nextID: 1, streams: make(map[uint32]*h2Stream)}
	cc.fr = http2.NewFramer(conn, conn)
	cc.fr.ReadMetaHeaders = hpack.NewDecoder(1<<20, nil)
	var hbuf bytes.Buffer
	cc.enc = hpack.NewEncoder(&hbuf)

	settings, err := h2Settings(p)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write http/2 preface: %w", err)
	}
	if err := cc.fr.WriteSettings(settings...); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write http/2 settings: %w", err)
	}
	if incr := h2ConnectionWindowUpdate(p); incr > 0 {
		if err := cc.fr.WriteWindowUpdate(0, incr); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("write http/2 window update: %w", err)
		}
	}
	go cc.readLoop()
	return cc, nil
}

func (cc *h2ClientConn) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := readRequestBody(req)
	if err != nil {
		return nil, err
	}
	stream := &h2Stream{req: req, headers: make(chan *http.Response, 1), errs: make(chan error, 1)}
	stream.bodyR, stream.bodyW = io.Pipe()

	id, err := cc.writeRequest(req, body, stream)
	if err != nil {
		return nil, err
	}

	select {
	case resp := <-stream.headers:
		resp.Body = &h2Body{ReadCloser: stream.bodyR, cc: cc, streamID: id}
		return resp, nil
	case err := <-stream.errs:
		cc.removeStream(id)
		return nil, err
	case <-req.Context().Done():
		cc.removeStream(id)
		return nil, req.Context().Err()
	}
}

func (cc *h2ClientConn) CanTakeNewRequest() bool {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return !cc.closed
}

func (cc *h2ClientConn) Close() error {
	cc.mu.Lock()
	if cc.closed {
		cc.mu.Unlock()
		return nil
	}
	cc.closed = true
	streams := cc.streams
	cc.streams = make(map[uint32]*h2Stream)
	cc.mu.Unlock()
	for id, st := range streams {
		st.fail(fmt.Errorf("http/2 connection closed"))
		delete(streams, id)
	}
	return cc.conn.Close()
}

func (cc *h2ClientConn) writeRequest(req *http.Request, body []byte, stream *h2Stream) (uint32, error) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if cc.closed {
		return 0, fmt.Errorf("http/2 connection closed")
	}
	id := cc.nextID
	cc.nextID += 2
	cc.streams[id] = stream

	block, err := cc.headerBlock(req, len(body))
	if err != nil {
		delete(cc.streams, id)
		return 0, err
	}
	if err := cc.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block, EndStream: len(body) == 0, EndHeaders: true}); err != nil {
		delete(cc.streams, id)
		return 0, fmt.Errorf("write http/2 headers: %w", err)
	}
	for len(body) > 0 {
		n := len(body)
		if n > 16384 {
			n = 16384
		}
		chunk := body[:n]
		body = body[n:]
		if err := cc.fr.WriteData(id, len(body) == 0, chunk); err != nil {
			delete(cc.streams, id)
			return 0, fmt.Errorf("write http/2 data: %w", err)
		}
	}
	return id, nil
}

func (cc *h2ClientConn) headerBlock(req *http.Request, bodyLen int) ([]byte, error) {
	var buf bytes.Buffer
	cc.enc = hpack.NewEncoder(&buf)
	for _, hf := range pseudoHeaders(req, cc.p) {
		if err := cc.enc.WriteField(hf); err != nil {
			return nil, err
		}
	}
	for _, hf := range regularHeaders(req, cc.p, bodyLen) {
		if err := cc.enc.WriteField(hf); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func (cc *h2ClientConn) readLoop() {
	for {
		frame, err := cc.fr.ReadFrame()
		if err != nil {
			cc.failAll(fmt.Errorf("read http/2 frame: %w", err))
			return
		}
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				cc.writeControl(func() error { return cc.fr.WriteSettingsAck() })
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				cc.writeControl(func() error { return cc.fr.WritePing(true, f.Data) })
			}
		case *http2.MetaHeadersFrame:
			cc.handleHeaders(f)
		case *http2.DataFrame:
			cc.handleData(f)
		case *http2.RSTStreamFrame:
			cc.failStream(f.StreamID, fmt.Errorf("http/2 stream reset: %s", f.ErrCode))
		case *http2.GoAwayFrame:
			cc.failAll(fmt.Errorf("http/2 goaway: %s", f.ErrCode))
		}
	}
}

func (cc *h2ClientConn) writeControl(fn func() error) {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	if !cc.closed {
		_ = fn()
	}
}
