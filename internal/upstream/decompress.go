package upstream

import (
	"bufio"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

// decodeResponse transparently decompresses resp so the client always
// receives a usable body, regardless of the Accept-Encoding the profile
// advertised. The profile may ask the server for an encoding (br, zstd) the
// client cannot decode itself, so Doppel decodes it here.
//
// Content-Encoding and Content-Length are removed because they no longer
// describe the body handed to the client.
func decodeResponse(resp *http.Response) error {
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if encoding == "" || encoding == "identity" {
		return nil
	}

	decoded, err := decompressor(encoding, resp.Body)
	if err != nil {
		return err
	}
	if decoded == nil {
		return nil // unknown encoding: leave the body untouched
	}

	resp.Body = decoded
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Content-Length")
	resp.ContentLength = -1
	resp.Uncompressed = true
	return nil
}

// decompressor wraps body in a reader for the given Content-Encoding. It
// returns (nil, nil) for encodings Doppel does not handle, leaving the caller
// to pass the body through unchanged.
func decompressor(encoding string, body io.ReadCloser) (io.ReadCloser, error) {
	switch encoding {
	case "gzip", "x-gzip":
		zr, err := gzip.NewReader(body)
		if err != nil {
			return nil, fmt.Errorf("gzip reader: %w", err)
		}
		return &decompressBody{reader: zr, closers: []io.Closer{zr, body}}, nil

	case "br":
		return &decompressBody{
			reader:  brotli.NewReader(body),
			closers: []io.Closer{body},
		}, nil

	case "zstd":
		zr, err := zstd.NewReader(body)
		if err != nil {
			return nil, fmt.Errorf("zstd reader: %w", err)
		}
		rc := zr.IOReadCloser()
		return &decompressBody{reader: rc, closers: []io.Closer{rc, body}}, nil

	case "deflate":
		// "deflate" is usually zlib-wrapped, but some servers send raw
		// DEFLATE. Peek at the header to tell the two apart.
		buffered := bufio.NewReader(body)
		if looksLikeZlib(buffered) {
			zr, err := zlib.NewReader(buffered)
			if err != nil {
				return nil, fmt.Errorf("zlib reader: %w", err)
			}
			return &decompressBody{reader: zr, closers: []io.Closer{zr, body}}, nil
		}
		fr := flate.NewReader(buffered)
		return &decompressBody{reader: fr, closers: []io.Closer{fr, body}}, nil

	default:
		return nil, nil
	}
}

// looksLikeZlib reports whether the next two bytes are a valid zlib header.
func looksLikeZlib(r *bufio.Reader) bool {
	header, err := r.Peek(2)
	if err != nil || len(header) < 2 {
		return false
	}
	const deflateCompression = 0x08
	if header[0]&0x0f != deflateCompression {
		return false
	}
	return (uint16(header[0])<<8|uint16(header[1]))%31 == 0
}

// decompressBody adapts a decompressing reader into an io.ReadCloser that also
// closes the underlying response body.
type decompressBody struct {
	reader  io.Reader
	closers []io.Closer
}

func (b *decompressBody) Read(p []byte) (int, error) { return b.reader.Read(p) }

func (b *decompressBody) Close() error {
	var firstErr error
	for _, c := range b.closers {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
