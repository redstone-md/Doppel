package upstream

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/redstone-md/Doppel/internal/profile"
)

func (cc *h2ClientConn) handleHeaders(f *http2.MetaHeadersFrame) {
	st := cc.stream(f.StreamID)
	if st == nil {
		return
	}
	status := 0
	headers := make(http.Header)
	for _, hf := range f.Fields {
		if hf.Name == ":status" {
			status, _ = strconv.Atoi(hf.Value)
			continue
		}
		if !strings.HasPrefix(hf.Name, ":") {
			headers.Add(http.CanonicalHeaderKey(hf.Name), hf.Value)
		}
	}
	if status == 0 {
		st.fail(fmt.Errorf("http/2 response missing :status"))
		return
	}
	resp := &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        headers,
		Request:       st.req,
		ContentLength: -1,
	}
	if cl := headers.Get("Content-Length"); cl != "" {
		resp.ContentLength, _ = strconv.ParseInt(cl, 10, 64)
	}
	select {
	case st.headers <- resp:
	default:
		st.trailers = headers
	}
	if f.StreamEnded() {
		cc.endStream(f.StreamID)
	}
}

func (cc *h2ClientConn) handleData(f *http2.DataFrame) {
	st := cc.stream(f.StreamID)
	if st == nil {
		return
	}
	if len(f.Data()) > 0 {
		if _, err := st.bodyW.Write(f.Data()); err != nil {
			cc.removeStream(f.StreamID)
			return
		}
		incr := uint32(len(f.Data()))
		cc.writeControl(func() error {
			if err := cc.fr.WriteWindowUpdate(0, incr); err != nil {
				return err
			}
			return cc.fr.WriteWindowUpdate(f.StreamID, incr)
		})
	}
	if f.StreamEnded() {
		cc.endStream(f.StreamID)
	}
}

func (cc *h2ClientConn) stream(id uint32) *h2Stream {
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.streams[id]
}

func (cc *h2ClientConn) endStream(id uint32) {
	cc.removeStream(id)
}

func (cc *h2ClientConn) removeStream(id uint32) {
	cc.mu.Lock()
	st := cc.streams[id]
	delete(cc.streams, id)
	cc.mu.Unlock()
	if st != nil {
		_ = st.bodyW.Close()
	}
}

func (cc *h2ClientConn) failStream(id uint32, err error) {
	cc.mu.Lock()
	st := cc.streams[id]
	delete(cc.streams, id)
	cc.mu.Unlock()
	if st != nil {
		st.fail(err)
	}
}

func (cc *h2ClientConn) failAll(err error) {
	cc.mu.Lock()
	cc.closed = true
	streams := cc.streams
	cc.streams = make(map[uint32]*h2Stream)
	cc.mu.Unlock()
	for _, st := range streams {
		st.fail(err)
	}
	_ = cc.conn.Close()
}

func (st *h2Stream) fail(err error) {
	select {
	case st.errs <- err:
	default:
	}
	_ = st.bodyW.CloseWithError(err)
}

func pseudoHeaders(req *http.Request, p *profile.Profile) []hpack.HeaderField {
	values := map[string]string{
		":method":    req.Method,
		":scheme":    req.URL.Scheme,
		":path":      req.URL.RequestURI(),
		":authority": requestAuthority(req),
	}
	out := make([]hpack.HeaderField, 0, 4)
	for _, name := range h2PseudoHeaderOrder(p) {
		if value := values[name]; value != "" {
			out = append(out, hpack.HeaderField{Name: name, Value: value})
			delete(values, name)
		}
	}
	for _, name := range []string{":method", ":authority", ":scheme", ":path"} {
		if value := values[name]; value != "" {
			out = append(out, hpack.HeaderField{Name: name, Value: value})
		}
	}
	return out
}

func regularHeaders(req *http.Request, p *profile.Profile, bodyLen int) []hpack.HeaderField {
	headers := make(http.Header, len(req.Header)+1)
	for name, values := range req.Header {
		if strings.EqualFold(name, "Host") || strings.EqualFold(name, "Connection") {
			continue
		}
		headers[name] = values
	}
	if bodyLen > 0 {
		headers.Set("Content-Length", strconv.Itoa(bodyLen))
	}

	keys := p.OrderHeaders(headers)
	ordered := make([]hpack.HeaderField, 0, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		lower := strings.ToLower(key)
		for _, value := range headers[key] {
			ordered = append(ordered, hpack.HeaderField{Name: lower, Value: value})
		}
		seen[lower] = struct{}{}
	}
	var rest []string
	for key := range headers {
		lower := strings.ToLower(key)
		if _, ok := seen[lower]; !ok {
			rest = append(rest, key)
		}
	}
	sort.Strings(rest)
	for _, key := range rest {
		for _, value := range headers[key] {
			ordered = append(ordered, hpack.HeaderField{Name: strings.ToLower(key), Value: value})
		}
	}
	return ordered
}

func requestAuthority(req *http.Request) string {
	if req.Host != "" {
		return req.Host
	}
	return req.URL.Host
}

func readRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}
	return body, nil
}

type h2Body struct {
	io.ReadCloser
	cc       *h2ClientConn
	streamID uint32
}

func (b *h2Body) Close() error {
	err := b.ReadCloser.Close()
	b.cc.removeStream(b.streamID)
	return err
}
