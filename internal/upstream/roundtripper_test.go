package upstream

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/redstone-md/Doppel/internal/profile"
)

func testProfile(t *testing.T) *profile.Profile {
	t.Helper()
	profiles, err := profile.Builtin()
	if err != nil {
		t.Fatalf("load builtin profiles: %v", err)
	}
	return profiles["chrome-windows"]
}

func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "proto=%s path=%s", r.Proto, r.URL.Path)
	})
}

func drain(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	_ = resp.Body.Close()
	return string(body)
}

func TestRoundTripperHTTP2(t *testing.T) {
	backend := httptest.NewUnstartedServer(echoHandler())
	backend.EnableHTTP2 = true
	backend.StartTLS()
	defer backend.Close()

	rt := &RoundTripper{Dialer: &Dialer{SkipVerify: true}, Profile: testProfile(t)}
	defer rt.Close()

	req, _ := http.NewRequest(http.MethodGet, backend.URL+"/h2", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp.ProtoMajor != 2 {
		t.Errorf("ProtoMajor = %d, want 2", resp.ProtoMajor)
	}
	if got := drain(t, resp); got != "proto=HTTP/2.0 path=/h2" {
		t.Errorf("body = %q", got)
	}
}

func TestRoundTripperHTTP1(t *testing.T) {
	backend := httptest.NewTLSServer(echoHandler()) // HTTP/1.1 only
	defer backend.Close()

	rt := &RoundTripper{Dialer: &Dialer{SkipVerify: true}, Profile: testProfile(t)}
	defer rt.Close()

	req, _ := http.NewRequest(http.MethodGet, backend.URL+"/h1", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if resp.ProtoMajor != 1 {
		t.Errorf("ProtoMajor = %d, want 1", resp.ProtoMajor)
	}
	if got := drain(t, resp); got != "proto=HTTP/1.1 path=/h1" {
		t.Errorf("body = %q", got)
	}
}

func TestRoundTripperPoolsHTTP2(t *testing.T) {
	backend := httptest.NewUnstartedServer(echoHandler())
	backend.EnableHTTP2 = true
	backend.StartTLS()
	defer backend.Close()

	rt := &RoundTripper{Dialer: &Dialer{SkipVerify: true}, Profile: testProfile(t)}
	defer rt.Close()

	for i := 0; i < 3; i++ {
		req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/req%d", backend.URL, i), nil)
		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatalf("RoundTrip %d: %v", i, err)
		}
		drain(t, resp)
	}

	rt.mu.Lock()
	poolSize := len(rt.pool)
	rt.mu.Unlock()
	if poolSize != 1 {
		t.Errorf("pool size = %d, want 1 (connection should be reused)", poolSize)
	}
}

func TestRoundTripperConcurrentHTTP2(t *testing.T) {
	backend := httptest.NewUnstartedServer(echoHandler())
	backend.EnableHTTP2 = true
	backend.StartTLS()
	defer backend.Close()

	rt := &RoundTripper{Dialer: &Dialer{SkipVerify: true}, Profile: testProfile(t)}
	defer rt.Close()

	const requests = 12
	errs := make(chan error, requests)
	for i := 0; i < requests; i++ {
		go func(i int) {
			req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/concurrent%d", backend.URL, i), nil)
			resp, err := rt.RoundTrip(req)
			if err != nil {
				errs <- err
				return
			}
			if resp.ProtoMajor != 2 {
				errs <- fmt.Errorf("ProtoMajor = %d, want 2", resp.ProtoMajor)
				return
			}
			drain(t, resp)
			errs <- nil
		}(i)
	}
	for i := 0; i < requests; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}
func TestRoundTripperCloseEmptiesPool(t *testing.T) {
	backend := httptest.NewUnstartedServer(echoHandler())
	backend.EnableHTTP2 = true
	backend.StartTLS()
	defer backend.Close()

	rt := &RoundTripper{Dialer: &Dialer{SkipVerify: true}, Profile: testProfile(t)}

	req, _ := http.NewRequest(http.MethodGet, backend.URL+"/", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	drain(t, resp)

	if err := rt.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	rt.mu.Lock()
	poolSize := len(rt.pool)
	rt.mu.Unlock()
	if poolSize != 0 {
		t.Errorf("pool size after Close = %d, want 0", poolSize)
	}
}
