package upstream

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

var decompressPayload = "Doppel transparently decodes compressed responses " +
	"so a lightweight client never has to. Repeated text compresses well. " +
	strings.Repeat("the quick brown fox jumps over the lazy dog. ", 16)

func TestDecodeResponse(t *testing.T) {
	cases := []struct {
		name     string
		encoding string
		compress func([]byte) []byte
	}{
		{"gzip", "gzip", gzipBytes},
		{"brotli", "br", brotliBytes},
		{"zstd", "zstd", zstdBytes},
		{"zlib-wrapped deflate", "deflate", zlibBytes},
		{"raw deflate", "deflate", rawDeflateBytes},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := &http.Response{Header: http.Header{}}
			resp.Header.Set("Content-Encoding", c.encoding)
			resp.Body = io.NopCloser(bytes.NewReader(c.compress([]byte(decompressPayload))))

			if err := decodeResponse(resp); err != nil {
				t.Fatalf("decodeResponse: %v", err)
			}
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read decoded body: %v", err)
			}
			if string(got) != decompressPayload {
				t.Errorf("decoded body does not match original (%d vs %d bytes)",
					len(got), len(decompressPayload))
			}
			if resp.Header.Get("Content-Encoding") != "" {
				t.Error("Content-Encoding header was not cleared")
			}
			if !resp.Uncompressed {
				t.Error("Uncompressed flag was not set")
			}
		})
	}
}

func TestDecodeResponsePassthrough(t *testing.T) {
	for _, encoding := range []string{"", "identity", "exotic-codec"} {
		resp := &http.Response{Header: http.Header{}}
		if encoding != "" {
			resp.Header.Set("Content-Encoding", encoding)
		}
		resp.Body = io.NopCloser(strings.NewReader("plain body"))

		if err := decodeResponse(resp); err != nil {
			t.Fatalf("encoding %q: %v", encoding, err)
		}
		got, _ := io.ReadAll(resp.Body)
		if string(got) != "plain body" {
			t.Errorf("encoding %q: body = %q, want unchanged", encoding, got)
		}
	}
}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func brotliBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := brotli.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func zstdBytes(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := zstd.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func zlibBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func rawDeflateBytes(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}
